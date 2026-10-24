#!/usr/bin/env node
// Cybertis SSDLC upload — pushes scan reports to POST /api/ingest/ssdlc/v1/scans.
// Node >= 20, zero dependencies, ESM, single file — easy to audit before you pin it.
// Wire contract: schema cybertis.ssdlc.ingest/1 (see README.md, "What it does").
import { createHash, createHmac } from "node:crypto";
import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

export const SCHEMA_ID = "cybertis.ssdlc.ingest/1";
export const FORMATS = ["json", "jsonl", "sarif", "cyclonedx"];
// What a report covers (README, "coverage" input): only `full` / `tree` runs may
// auto-resolve findings on the server; `range` / `diff` never do.
export const COVERAGES = ["full", "range", "tree", "diff"];
export const DEFAULT_COVERAGE = "full";
// How the scanner process ended, per report (`execution.status`). `ok` is the
// server's only proof that an EMPTY report (e.g. nuclei JSONL) is a clean
// scan; `error` makes the run PARTIAL. Absent = no claim.
export const EXECUTION_STATUSES = ["ok", "error", "unknown"];
export const PROFILE_MAX = 80;
export const GZIP_THRESHOLD = 256 * 1024;
export const SNIPPET_MAX = 300;
export const USER_AGENT = "cybertis-ssdlc-upload/1";
export const POLL_BUDGET_MS = 20_000;
const MAX_ATTEMPTS = 3;
const TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

// ── pure helpers ────────────────────────────────────────────────────────────
export const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const truthy = (v) => /^(true|1|yes)$/i.test(String(v ?? "").trim());

/** `tool=path[:format][@coverage]` per line; `#` comments and blank lines ignored. */
export function parseReportSpecs(text) {
  const specs = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) throw new Error(`bad report spec "${line}" (expected tool=path[:format][@coverage])`);
    const tool = line.slice(0, eq).trim().toLowerCase();
    let pattern = line.slice(eq + 1).trim();
    let format;
    let coverage;
    const at = pattern.lastIndexOf("@");
    if (at > 0 && COVERAGES.includes(pattern.slice(at + 1))) {
      coverage = pattern.slice(at + 1);
      pattern = pattern.slice(0, at);
    }
    const colon = pattern.lastIndexOf(":");
    if (colon > 0 && FORMATS.includes(pattern.slice(colon + 1))) {
      format = pattern.slice(colon + 1);
      pattern = pattern.slice(0, colon);
    }
    if (!pattern) throw new Error(`bad report spec "${line}" (empty path)`);
    specs.push(coverage ? { tool, pattern, format, coverage } : { tool, pattern, format });
  }
  return specs;
}

/**
 * The `coverage` / `profile` inputs: either ONE bare value for every report,
 * or `tool=value` lines (per tool; a bare line is the default for the rest).
 * Returns `(tool) => value | undefined`. `allowed` (optional) validates values.
 */
export function parseToolValues(text, { name, allowed, max } = {}) {
  let fallback;
  const byTool = new Map();
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    const tool = eq > 0 ? line.slice(0, eq).trim().toLowerCase() : null;
    const value = (eq > 0 ? line.slice(eq + 1) : line).trim();
    if (!value) throw new Error(`bad ${name ?? "value"} "${line}" (empty value)`);
    if (allowed && !allowed.includes(value)) throw new Error(`bad ${name ?? "value"} "${value}" (expected one of ${allowed.join(", ")})`);
    if (max && value.length > max) throw new Error(`bad ${name ?? "value"} "${value.slice(0, 20)}…" (longer than ${max} characters)`);
    if ([...value].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) throw new Error(`bad ${name ?? "value"} (control characters)`);
    if (tool) byTool.set(tool, value);
    else fallback = value;
  }
  return (tool) => byTool.get(tool) ?? fallback;
}

export function globToRegExp(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") { i++; re += "(?:.*/)?"; } else re += ".*";
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

const SKIP_DIRS = new Set(["node_modules", ".git"]);
function walk(dir, out, depth) {
  if (depth > 12) return;
  let entries = [];
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(p, out, depth + 1); }
    else if (e.isFile()) out.push(p);
  }
}

/** Tiny matcher: `*`, `?`, `**`. Returns matching FILE paths (sorted); a plain path returns itself when it exists. */
export function expandGlob(pattern, cwd = process.cwd()) {
  const abs = path.isAbsolute(pattern) ? pattern : path.join(cwd, pattern);
  if (!/[*?]/.test(pattern)) return existsSync(abs) && statSync(abs).isFile() ? [abs] : [];
  const segs = abs.split(path.sep);
  let i = 0;
  while (i < segs.length && !/[*?]/.test(segs[i])) i++;
  const base = segs.slice(0, i).join(path.sep) || path.sep;
  const re = globToRegExp(segs.slice(i).join("/"));
  const files = [];
  walk(base, files, 0);
  return files.filter((f) => re.test(path.relative(base, f).split(path.sep).join("/"))).sort();
}

export const SCOPES = ["DEFAULT_BRANCH", "SCHEDULED", "PULL_REQUEST"];
// The `scope` input (README "Pull requests"): auto | push | schedule |
// pull_request, or the wire value itself (v1.1 workflows pass `SCHEDULED`).
const SCOPE_INPUTS = {
  auto: null, push: "DEFAULT_BRANCH", default_branch: "DEFAULT_BRANCH",
  schedule: "SCHEDULED", scheduled: "SCHEDULED", pull_request: "PULL_REQUEST",
};
export const PR_EVENTS = ["pull_request", "pull_request_target"];

/** True for "" and every value `resolveScope` understands; anything else is ignored with a warning. */
export const isKnownScopeInput = (explicit) => !explicit || Object.hasOwn(SCOPE_INPUTS, String(explicit).trim().toLowerCase());

/** The run's scope: the `scope` input, else (auto / unknown) from the event — schedule → SCHEDULED, a PR event → PULL_REQUEST, anything else → DEFAULT_BRANCH. */
export function resolveScope(explicit, eventName) {
  const key = String(explicit ?? "").trim().toLowerCase();
  const mapped = Object.hasOwn(SCOPE_INPUTS, key) ? SCOPE_INPUTS[key] : null;
  if (mapped) return mapped;
  if (eventName === "schedule") return "SCHEDULED";
  return PR_EVENTS.includes(eventName) ? "PULL_REQUEST" : "DEFAULT_BRANCH";
}

/**
 * `run.pullRequest` from the event payload (`GITHUB_EVENT_PATH`): number,
 * head / base commit and the base branch. Null when the payload has no
 * well-formed pull_request (a push event, a hand-set `scope: pull_request`).
 */
export function pullRequestFromEvent(event) {
  const pr = event?.pull_request;
  const sha = (v) => (typeof v === "string" && /^[0-9a-f]{40}$/.test(v) ? v : null);
  const number = pr?.number;
  const headSha = sha(pr?.head?.sha);
  const baseSha = sha(pr?.base?.sha);
  const baseRef = pr?.base?.ref;
  if (!Number.isSafeInteger(number) || number <= 0 || !headSha || !baseSha) return null;
  if (typeof baseRef !== "string" || !baseRef || baseRef.length > 255 || /[\x00-\x1f\x7f]/.test(baseRef)) return null;
  return { number, headSha, baseSha, baseRef };
}

export function targetKindFor(key, explicit) {
  if (explicit) return explicit.toUpperCase();
  if (key.startsWith("url:")) return "WEB_APP";
  if (key.startsWith("host:")) return "HOST";
  return "REPOSITORY";
}

export const AUTH_MODES = ["token", "oidc", "auto"];

/**
 * Which credential the upload uses (README "Authentication"):
 *   token  the `api-token` bearer, as in v1.1;
 *   oidc   a GitHub Actions OIDC id token (the job needs `permissions: id-token: write`);
 *   auto   (default) OIDC when the runner can mint one (ACTIONS_ID_TOKEN_REQUEST_URL is set)
 *          AND `api-token` is empty or `prefer-oidc` is true; else the token.
 * Fails SAFE: OIDC requested but unavailable → the token when there is one.
 * Returns { mode: "oidc" | "token" | null, note } — null = nothing to authenticate with.
 */
export function resolveAuthMode({ auth, token, preferOidc, oidcAvailable }) {
  const raw = String(auth ?? "").trim().toLowerCase() || "auto";
  const wanted = AUTH_MODES.includes(raw) ? raw : "auto";
  const note = wanted === raw ? null : `unknown auth "${auth}" — using auto`;
  if (wanted === "token") return { mode: token ? "token" : null, note };
  if (wanted === "oidc" || (wanted === "auto" && (!token || preferOidc))) {
    if (oidcAvailable) return { mode: "oidc", note };
    if (wanted === "oidc" && token) return { mode: "token", note: "auth: oidc but the job cannot mint an id token (add `permissions: id-token: write`) — using api-token" };
    if (wanted === "oidc") return { mode: null, note: "auth: oidc but the job cannot mint an id token (add `permissions: id-token: write`)" };
  }
  return { mode: token ? "token" : null, note };
}

/** The `aud` the id token is minted for: `oidc-audience`, else the endpoint's origin (what the server expects by default). */
export function oidcAudienceFor(endpoint, explicit) {
  if (explicit) return explicit;
  try { return new URL(endpoint).origin; } catch { return endpoint; }
}

/**
 * One GitHub Actions OIDC id token. The server consumes each token's `jti`
 * once, so every request (each POST attempt, each status poll) asks for a
 * fresh one. Throws on any failure — the caller falls back or gives up.
 */
export async function fetchIdToken({ requestUrl, requestToken, audience, fetchImpl = fetch, timeoutMs = 10_000 }) {
  const url = new URL(requestUrl);
  url.searchParams.set("audience", audience);
  const res = await fetchImpl(url.toString(), { headers: { authorization: `bearer ${requestToken}`, accept: "application/json", "user-agent": USER_AGENT }, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`id token request: HTTP ${res.status}`);
  const value = (await res.json())?.value;
  if (typeof value !== "string" || value.split(".").length !== 3) throw new Error("id token request: no token in the response");
  return value;
}

/**
 * Returns a `::notice::` reason when the run should be skipped, else null.
 * `oidc` = an id token will authenticate instead of `token`. A PR event
 * uploads only on opt-in — `scope: pull_request` or `allow-pr: true` — so a
 * v1.1 workflow that also runs on PRs keeps skipping them.
 */
export function skipReason({ token, eventName, allowPr, oidc = false, scopeInput = "" }) {
  if (!token && !oidc) return "api-token is empty — skipping upload (create CYBERTIS_SSDLC_TOKEN to enable the SSDLC feed)";
  const prOptIn = allowPr || String(scopeInput).trim().toLowerCase() === "pull_request";
  if (PR_EVENTS.includes(eventName) && !prOptIn) return `${eventName} event without scope: pull_request (or allow-pr: true) — skipping upload`;
  return null;
}

/** Local masking; the server strips again regardless. Returns { text, changed }. */
export function maskReport(tool, format, text) {
  let doc;
  try { doc = JSON.parse(text); } catch { return { text, changed: 0 }; }
  let changed = 0;
  const isSarif = format === "sarif" || tool === "sarif" || (doc && Array.isArray(doc.runs) && typeof doc.$schema === "string" && /sarif/i.test(doc.$schema));
  if (tool === "gitleaks" && Array.isArray(doc)) {
    for (const f of doc) {
      if (!f || typeof f !== "object") continue;
      if (typeof f.Secret === "string" && !/^[0-9a-f]{64}$/.test(f.Secret)) { f.Secret = sha256(f.Secret); changed++; }
      for (const k of ["Match", "Line"]) if (k in f) { delete f[k]; changed++; }
    }
  } else if (tool === "semgrep" && doc && Array.isArray(doc.results)) {
    for (const r of doc.results) if (r?.extra && "lines" in r.extra) { delete r.extra.lines; changed++; }
  } else if (isSarif && doc && Array.isArray(doc.runs)) {
    for (const run of doc.runs) for (const r of run?.results ?? []) {
      if (!r || typeof r !== "object") continue;
      for (const k of ["codeFlows", "relatedLocations"]) if (k in r) { delete r[k]; changed++; }
      for (const loc of r.locations ?? []) {
        const region = loc?.physicalLocation?.region;
        for (const s of [region?.snippet, loc?.physicalLocation?.contextRegion?.snippet]) {
          if (s && typeof s.text === "string" && s.text.length > SNIPPET_MAX) { s.text = s.text.slice(0, SNIPPET_MAX); changed++; }
        }
      }
    }
  } else return { text, changed: 0 };
  return { text: changed ? JSON.stringify(doc) : text, changed };
}

/** Envelope for one CI run. `reports` = [{ tool, format, text }]. */
export function buildEnvelope(ctx, reports) {
  const target = { kind: targetKindFor(ctx.targetKey, ctx.targetKind), key: ctx.targetKey };
  if (ctx.displayName) target.displayName = ctx.displayName;
  if (ctx.defaultBranch) target.defaultBranch = ctx.defaultBranch;
  if (ctx.internetFacing === "true" || ctx.internetFacing === "false") target.internetFacing = ctx.internetFacing === "true";
  const attempt = Number(ctx.runAttempt || 1);
  const run = {
    externalId: `gha:${ctx.repository}:${ctx.runId}${attempt > 1 ? `:a${attempt}` : ""}`,
    target,
    scope: resolveScope(ctx.scope, ctx.eventName),
    ciProvider: "github-actions",
    completedAt: (ctx.now ?? new Date()).toISOString(),
  };
  if (run.scope === "PULL_REQUEST" && ctx.pullRequest) run.pullRequest = { ...ctx.pullRequest };
  if (ctx.ref) run.branchRef = ctx.ref;
  if (/^[0-9a-f]{7,40}$/.test(ctx.sha ?? "")) run.commitSha = ctx.sha;
  // The link names the REAL run (`ciRunId` = GITHUB_RUN_ID): a `run-id` input such as `<run_id>-community` only keys the externalId.
  const urlRunId = ctx.ciRunId || ctx.runId;
  if (ctx.serverUrl && ctx.repository && urlRunId) run.ciRunUrl = `${ctx.serverUrl}/${ctx.repository}/actions/runs/${urlRunId}`;
  return {
    schema: SCHEMA_ID,
    run,
    reports: reports.map((r) => {
      const entry = { tool: r.tool, content: Buffer.from(r.text, "utf8").toString("base64"), encoding: "base64", sha256: sha256(Buffer.from(r.text, "utf8")) };
      if (r.format) entry.format = r.format;
      entry.coverage = r.coverage ?? DEFAULT_COVERAGE;
      if (r.profile) entry.profile = r.profile;
      if (r.execution) entry.execution = { status: r.execution };
      return entry;
    }),
  };
}

/** Wire bytes (+ gzip above the threshold) and the optional signature headers. */
export function encodeBody(envelope, { sign, token, now = Date.now() }) {
  const json = Buffer.from(JSON.stringify(envelope), "utf8");
  const gzip = json.length > GZIP_THRESHOLD;
  const body = gzip ? gzipSync(json) : json;
  const headers = { "content-type": "application/json", "user-agent": USER_AGENT, authorization: `Bearer ${token}` };
  if (gzip) headers["content-encoding"] = "gzip";
  if (sign) Object.assign(headers, signHeaders(token, body, Math.floor(now / 1000)));
  return { body, headers, gzip, jsonBytes: json.length };
}

export function signHeaders(token, bodyBytes, tsSeconds) {
  const mac = createHmac("sha256", token).update(`${tsSeconds}.${sha256(bodyBytes)}`).digest("hex");
  return { "x-cybertis-timestamp": String(tsSeconds), "x-cybertis-signature": `v1=${mac}` };
}

/**
 * The server refused the OIDC credential itself (not the report): the token
 * may still be accepted — a repository the App has not inventoried yet, an
 * audience mismatch, the replay cache down. Anything else (400, 409, 413,
 * feature_disabled…) would fail the same way with the token.
 */
export function shouldFallBackToToken(status, code) {
  if (status === 401) return true;
  return typeof code === "string" && (code.startsWith("oidc_") || code === "replay_cache_unavailable");
}

export const isRetryable = (status) => status === 429 || (status >= 500 && status <= 599);
export function retryDelayMs(attempt, retryAfter) {
  const ra = Number(retryAfter);
  if (Number.isFinite(ra) && ra > 0) return Math.min(ra, 30) * 1000;
  return 1000 * 2 ** (attempt - 1);
}

const TERMINAL = new Set(["COMPLETED", "PARTIAL", "FAILED", "DUPLICATE"]);
export const isTerminal = (status) => TERMINAL.has(status);

/** Markdown for $GITHUB_STEP_SUMMARY. `runs` = the response's runs[] (possibly refreshed by polling). */
export function renderSummary({ runs = [], gate, dashboard, skipped, error }) {
  const lines = ["### Cybertis SSDLC upload", ""];
  if (skipped) return [...lines, `_Skipped: ${skipped}_`, ""].join("\n");
  if (error) lines.push(`> :warning: ${error}`, "");
  if (runs.length) {
    lines.push("| tool | status | total | new | reopened | resolved | C / H / M / L / I | link |", "|---|---|---|---|---|---|---|---|");
    for (const r of runs) {
      const s = r.summary ?? {};
      const tiers = s.byTier ? TIERS.map((t) => s.byTier[t] ?? 0).join(" / ") : "—";
      const n = (v) => (v ?? "—");
      const link = r.links?.dashboard ?? dashboard ?? r.links?.run;
      lines.push(`| ${r.tool} | ${r.status}${r.duplicate ? " (dup)" : ""} | ${n(s.total)} | ${n(s.new)} | ${n(s.reopened)} | ${n(s.resolved)} | ${tiers} | ${link ? `[open](${link})` : "—"} |`);
      for (const w of r.warnings ?? []) lines.push(`| | ⚠ ${String(w).replace(/\|/g, "\\|")} | | | | | | |`);
    }
    lines.push("");
  }
  if (gate) lines.push(`Gate: **${gate.mode ?? "REPORT_ONLY"}** — ${gate.pass === false ? ":x: fail" : ":white_check_mark: pass"}${gate.reasons?.length ? ` (${gate.reasons.join("; ")})` : ""}`, "");
  return lines.join("\n");
}

// ── runtime (GitHub Actions) ────────────────────────────────────────────────
const input = (name, dflt = "") => { const v = process.env[`INPUT_${name.replace(/-/g, "_").toUpperCase()}`]; return v === undefined || v === "" ? dflt : v; };
const log = { notice: (m) => console.log(`::notice::${m}`), warn: (m) => console.log(`::warning::${m}`), error: (m) => console.log(`::error::${m}`) };
function writeOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  if (!f) return;
  const eol = `ghadelimiter_${Date.now()}`;
  appendFileSync(f, `${name}<<${eol}\n${value}\n${eol}\n`);
}
function writeSummary(md) { const f = process.env.GITHUB_STEP_SUMMARY; if (f) appendFileSync(f, `${md}\n`); }
function readEvent() {
  try { return JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, "utf8")); } catch { return null; }
}
async function errorCode(res) {
  try { const j = await res.json(); return { code: j?.error ?? "error", text: `${j?.error ?? "error"}${j?.message ? ` — ${String(j.message).slice(0, 200)}` : ""}` }; } catch { return { code: null, text: "unreadable error body" }; }
}

/** `authHeader()` is awaited per attempt: an OIDC id token is single-use. */
async function postWithRetries(url, body, headers, authHeader, timeoutMs) {
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(url, { method: "POST", body, headers: { ...headers, authorization: await authHeader() }, signal: AbortSignal.timeout(timeoutMs) });
      if (res.ok) return { ok: true, status: res.status, json: await res.json() };
      const { code, text: detail } = await errorCode(res);
      if (isRetryable(res.status) && attempt < MAX_ATTEMPTS) {
        const wait = retryDelayMs(attempt, res.headers.get("retry-after"));
        log.warn(`ssdlc-upload: HTTP ${res.status} ${detail} — retry ${attempt}/${MAX_ATTEMPTS - 1} in ${wait / 1000}s`);
        await new Promise((r) => setTimeout(r, wait));
        continue;
      }
      return { ok: false, status: res.status, code, error: `HTTP ${res.status} ${detail}` };
    } catch (e) {
      if (attempt < MAX_ATTEMPTS) {
        const wait = retryDelayMs(attempt);
        log.warn(`ssdlc-upload: network error (${e?.name ?? "Error"}) — retry ${attempt}/${MAX_ATTEMPTS - 1} in ${wait / 1000}s`);
        await new Promise((r) => setTimeout(r, wait));
        continue;
      }
      return { ok: false, error: `network error: ${e?.message ?? e}` };
    }
  }
}

async function pollRuns(endpoint, runs, authHeader, timeoutMs) {
  const deadline = Date.now() + POLL_BUDGET_MS;
  const out = runs.map((r) => ({ ...r }));
  while (Date.now() < deadline && out.some((r) => !isTerminal(r.status))) {
    await new Promise((r) => setTimeout(r, 2000));
    for (const [i, r] of out.entries()) {
      if (isTerminal(r.status) || !r.scanRunId) continue;
      try {
        const res = await fetch(`${endpoint}/${encodeURIComponent(r.scanRunId)}`, { headers: { authorization: await authHeader(), "user-agent": USER_AGENT }, signal: AbortSignal.timeout(timeoutMs) });
        if (!res.ok) continue;
        const j = await res.json();
        const fresh = j?.runs?.[0] ?? j;
        if (fresh?.status) out[i] = { ...r, ...fresh, tool: r.tool };
      } catch { /* keep polling until the budget runs out */ }
    }
  }
  return out;
}

export async function main() {
  const token = input("api-token").trim();
  if (token) console.log(`::add-mask::${token}`);
  const eventName = process.env.GITHUB_EVENT_NAME ?? "";
  const failOn = input("fail-on", "none");
  const oidcEnv = { requestUrl: process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? "", requestToken: process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? "" };
  const auth = resolveAuthMode({ auth: input("auth", "auto"), token, preferOidc: truthy(input("prefer-oidc", "false")), oidcAvailable: Boolean(oidcEnv.requestUrl && oidcEnv.requestToken) });
  if (auth.note) log.warn(`ssdlc-upload: ${auth.note}`);
  const scopeInput = input("scope");
  if (!isKnownScopeInput(scopeInput)) log.warn(`ssdlc-upload: unknown scope "${scopeInput.slice(0, 40)}" — using auto`);
  const scope = resolveScope(scopeInput, eventName);
  const event = readEvent();
  const pullRequest = scope === "PULL_REQUEST" ? pullRequestFromEvent(event) : null;
  const skipped = auth.mode === null && auth.note
    ? `${auth.note} — skipping upload`
    : skipReason({ token, eventName, allowPr: truthy(input("allow-pr", "false")), oidc: auth.mode === "oidc", scopeInput })
      ?? (scope === "PULL_REQUEST" && !pullRequest ? `scope PULL_REQUEST but the ${eventName || "unknown"} event payload has no pull_request — skipping upload` : null);
  const emptyOutputs = () => { writeOutput("scan-run-ids", ""); writeOutput("gate-pass", ""); writeOutput("summary-json", "[]"); };
  if (skipped) { log.notice(`ssdlc-upload: ${skipped}`); if (truthy(input("summary", "true"))) writeSummary(renderSummary({ skipped })); emptyOutputs(); return 0; }

  const endpoint = input("endpoint", "https://platform.cybertis.co.il/api/ingest/ssdlc/v1/scans").replace(/\/+$/, "");
  const timeoutMs = Math.max(5, Number(input("timeout-seconds", "60")) || 60) * 1000;
  const mask = truthy(input("mask-secrets", "true"));
  // A bad coverage / profile input must not cost the upload: warn and fall
  // back (coverage → full per report, no profile).
  const safeToolValues = (name, opts) => {
    try { return parseToolValues(input(name), { name, ...opts }); } catch (e) { log.warn(`ssdlc-upload: ${e?.message ?? e} — input "${name}" ignored`); return () => undefined; }
  };
  const coverageOf = safeToolValues("coverage", { allowed: COVERAGES });
  const profileOf = safeToolValues("profile", { max: PROFILE_MAX });
  const executionOf = safeToolValues("execution", { allowed: EXECUTION_STATUSES });
  const reports = [];
  for (const spec of parseReportSpecs(input("reports"))) {
    const files = expandGlob(spec.pattern);
    if (!files.length) { log.warn(`ssdlc-upload: no file for ${spec.tool} (${spec.pattern})`); continue; }
    if (files.length > 1) log.warn(`ssdlc-upload: ${spec.tool}: ${files.length} files match ${spec.pattern} — using ${path.relative(process.cwd(), files[0])}`);
    if (reports.some((r) => r.tool === spec.tool)) { log.warn(`ssdlc-upload: ${spec.tool} listed twice — keeping the first`); continue; }
    const raw = readFileSync(files[0], "utf8");
    const { text, changed } = mask ? maskReport(spec.tool, spec.format, raw) : { text: raw, changed: 0 };
    const coverage = spec.coverage ?? coverageOf(spec.tool) ?? DEFAULT_COVERAGE;
    const profile = profileOf(spec.tool);
    const execution = executionOf(spec.tool);
    console.log(`ssdlc-upload: ${spec.tool} ← ${path.relative(process.cwd(), files[0])} (${raw.length} chars${changed ? `, ${changed} field(s) masked` : ""}, coverage ${coverage}${profile ? `, profile ${profile}` : ""}${execution ? `, execution ${execution}` : ""})`);
    reports.push({ tool: spec.tool, format: spec.format, coverage, profile, execution, text });
  }
  if (!reports.length) { log.warn("ssdlc-upload: no reports found — nothing uploaded"); writeSummary(renderSummary({ skipped: "no report files found" })); emptyOutputs(); return 0; }

  const repository = process.env.GITHUB_REPOSITORY ?? "";
  const targetKey = input("target-key", `github:${repository}`);
  const envelope = buildEnvelope({
    repository, runId: input("run-id", process.env.GITHUB_RUN_ID ?? ""), ciRunId: process.env.GITHUB_RUN_ID, runAttempt: process.env.GITHUB_RUN_ATTEMPT,
    targetKey, targetKind: input("target-kind"), displayName: input("target-display-name", targetKey.startsWith("github:") ? repository.split("/").pop() : ""),
    defaultBranch: event?.repository?.default_branch, internetFacing: input("internet-facing").toLowerCase(), scope, eventName, pullRequest,
    ref: process.env.GITHUB_REF, sha: process.env.GITHUB_SHA, serverUrl: process.env.GITHUB_SERVER_URL,
  }, reports);
  let mode = auth.mode;
  const audience = oidcAudienceFor(endpoint, input("oidc-audience"));
  const idToken = async () => {
    const value = await fetchIdToken({ ...oidcEnv, audience, timeoutMs });
    console.log(`::add-mask::${value}`);
    return value;
  };
  // The first id token doubles as the probe: a runner that cannot mint one falls back to api-token (fails SAFE).
  let firstIdToken = null;
  if (mode === "oidc") {
    try { firstIdToken = await idToken(); } catch (e) {
      if (!token) { log.warn(`ssdlc-upload: ${e?.message ?? e} — no id token and no api-token, nothing uploaded`); writeSummary(renderSummary({ error: "no OIDC id token and no api-token" })); emptyOutputs(); return 0; }
      log.warn(`ssdlc-upload: ${e?.message ?? e} — falling back to api-token`);
      mode = "token";
    }
  }
  // An id token is the credential AND binds the run (the server derives target / commit / run from it): no HMAC.
  const { body, headers, gzip, jsonBytes } = encodeBody(envelope, { sign: mode === "token" && truthy(input("sign", "true")), token });
  let authHeader = mode === "oidc"
    ? async () => { const t = firstIdToken ?? (await idToken()); firstIdToken = null; return `Bearer ${t}`; }
    : async () => `Bearer ${token}`;
  console.log(`ssdlc-upload: POST ${endpoint} — ${reports.length} report(s), ${jsonBytes} bytes json${gzip ? `, ${body.length} bytes gzip` : ""}, externalId ${envelope.run.externalId}, scope ${envelope.run.scope}${pullRequest ? ` #${pullRequest.number}` : ""}, auth ${mode}`);

  let res = await postWithRetries(endpoint, body, headers, authHeader, timeoutMs);
  if (!res.ok && mode === "oidc" && token && shouldFallBackToToken(res.status, res.code)) {
    log.warn(`ssdlc-upload: OIDC upload refused (${res.error}) — retrying with api-token`);
    mode = "token";
    authHeader = async () => `Bearer ${token}`;
    const signed = encodeBody(envelope, { sign: truthy(input("sign", "true")), token });
    res = await postWithRetries(endpoint, signed.body, signed.headers, authHeader, timeoutMs);
  }
  if (!res.ok) { log.warn(`ssdlc-upload: upload failed — ${res.error}`); writeSummary(renderSummary({ error: res.error })); emptyOutputs(); return 0; }
  let runs = Array.isArray(res.json?.runs) ? res.json.runs : [res.json];
  if (runs.some((r) => !isTerminal(r.status))) runs = await pollRuns(endpoint, runs, authHeader, timeoutMs);
  const gate = res.json?.gate ?? null;
  console.log(`ssdlc-upload: HTTP ${res.status} — ${runs.map((r) => `${r.tool}:${r.status}`).join(", ")}${gate ? ` — gate ${gate.mode} pass=${gate.pass}` : ""}`);
  if (truthy(input("summary", "true"))) writeSummary(renderSummary({ runs, gate, dashboard: res.json?.links?.dashboard }));
  writeOutput("scan-run-ids", runs.map((r) => r.scanRunId).filter(Boolean).join(","));
  writeOutput("gate-pass", gate ? String(gate.pass !== false) : "");
  writeOutput("summary-json", JSON.stringify(runs.map((r) => ({ tool: r.tool, scanRunId: r.scanRunId, status: r.status, duplicate: r.duplicate, summary: r.summary ?? null, warnings: r.warnings ?? [] }))));
  if (failOn === "gate" && gate && gate.pass === false) { log.error(`ssdlc-upload: gate failed (${(gate.reasons ?? []).join("; ") || "no reason given"})`); return 1; }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => process.exit(code), (e) => { log.warn(`ssdlc-upload: unexpected error — ${e?.message ?? e}`); process.exit(0); });
}
