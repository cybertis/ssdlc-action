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
export const GZIP_THRESHOLD = 256 * 1024;
export const SNIPPET_MAX = 300;
export const USER_AGENT = "cybertis-ssdlc-upload/1";
export const POLL_BUDGET_MS = 20_000;
const MAX_ATTEMPTS = 3;
const TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

// ── pure helpers ────────────────────────────────────────────────────────────
export const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const truthy = (v) => /^(true|1|yes)$/i.test(String(v ?? "").trim());

/** `tool=path[:format]` per line; `#` comments and blank lines ignored. */
export function parseReportSpecs(text) {
  const specs = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) throw new Error(`bad report spec "${line}" (expected tool=path[:format])`);
    const tool = line.slice(0, eq).trim().toLowerCase();
    let pattern = line.slice(eq + 1).trim();
    let format;
    const colon = pattern.lastIndexOf(":");
    if (colon > 0 && FORMATS.includes(pattern.slice(colon + 1))) {
      format = pattern.slice(colon + 1);
      pattern = pattern.slice(0, colon);
    }
    if (!pattern) throw new Error(`bad report spec "${line}" (empty path)`);
    specs.push({ tool, pattern, format });
  }
  return specs;
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

export function resolveScope(explicit, eventName) {
  if (explicit) return explicit.toUpperCase();
  return eventName === "schedule" ? "SCHEDULED" : "DEFAULT_BRANCH";
}

export function targetKindFor(key, explicit) {
  if (explicit) return explicit.toUpperCase();
  if (key.startsWith("url:")) return "WEB_APP";
  if (key.startsWith("host:")) return "HOST";
  return "REPOSITORY";
}

/** Returns a `::notice::` reason when the run should be skipped, else null. */
export function skipReason({ token, eventName, allowPr }) {
  if (!token) return "api-token is empty — skipping upload (create CYBERTIS_SSDLC_TOKEN to enable the SSDLC feed)";
  if (eventName === "pull_request" && !allowPr) return "pull_request event and allow-pr=false — skipping upload (v1 ingest accepts main/scheduled scopes only)";
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
  if (ctx.ref) run.branchRef = ctx.ref;
  if (/^[0-9a-f]{7,40}$/.test(ctx.sha ?? "")) run.commitSha = ctx.sha;
  if (ctx.serverUrl && ctx.repository && ctx.runId) run.ciRunUrl = `${ctx.serverUrl}/${ctx.repository}/actions/runs/${ctx.runId}`;
  return {
    schema: SCHEMA_ID,
    run,
    reports: reports.map((r) => {
      const entry = { tool: r.tool, content: Buffer.from(r.text, "utf8").toString("base64"), encoding: "base64", sha256: sha256(Buffer.from(r.text, "utf8")) };
      if (r.format) entry.format = r.format;
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
function readDefaultBranch() {
  try { return JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"))?.repository?.default_branch; } catch { return undefined; }
}
async function errorCode(res) {
  try { const j = await res.json(); return `${j?.error ?? "error"}${j?.message ? ` — ${String(j.message).slice(0, 200)}` : ""}`; } catch { return "unreadable error body"; }
}

async function postWithRetries(url, body, headers, timeoutMs) {
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(url, { method: "POST", body, headers, signal: AbortSignal.timeout(timeoutMs) });
      if (res.ok) return { ok: true, status: res.status, json: await res.json() };
      const detail = await errorCode(res);
      if (isRetryable(res.status) && attempt < MAX_ATTEMPTS) {
        const wait = retryDelayMs(attempt, res.headers.get("retry-after"));
        log.warn(`ssdlc-upload: HTTP ${res.status} ${detail} — retry ${attempt}/${MAX_ATTEMPTS - 1} in ${wait / 1000}s`);
        await new Promise((r) => setTimeout(r, wait));
        continue;
      }
      return { ok: false, error: `HTTP ${res.status} ${detail}` };
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

async function pollRuns(endpoint, runs, token, timeoutMs) {
  const deadline = Date.now() + POLL_BUDGET_MS;
  const out = runs.map((r) => ({ ...r }));
  while (Date.now() < deadline && out.some((r) => !isTerminal(r.status))) {
    await new Promise((r) => setTimeout(r, 2000));
    for (const [i, r] of out.entries()) {
      if (isTerminal(r.status) || !r.scanRunId) continue;
      try {
        const res = await fetch(`${endpoint}/${encodeURIComponent(r.scanRunId)}`, { headers: { authorization: `Bearer ${token}`, "user-agent": USER_AGENT }, signal: AbortSignal.timeout(timeoutMs) });
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
  const skipped = skipReason({ token, eventName, allowPr: truthy(input("allow-pr", "false")) });
  const emptyOutputs = () => { writeOutput("scan-run-ids", ""); writeOutput("gate-pass", ""); writeOutput("summary-json", "[]"); };
  if (skipped) { log.notice(`ssdlc-upload: ${skipped}`); if (truthy(input("summary", "true"))) writeSummary(renderSummary({ skipped })); emptyOutputs(); return 0; }

  const endpoint = input("endpoint", "https://platform.cybertis.co.il/api/ingest/ssdlc/v1/scans").replace(/\/+$/, "");
  const timeoutMs = Math.max(5, Number(input("timeout-seconds", "60")) || 60) * 1000;
  const mask = truthy(input("mask-secrets", "true"));
  const reports = [];
  for (const spec of parseReportSpecs(input("reports"))) {
    const files = expandGlob(spec.pattern);
    if (!files.length) { log.warn(`ssdlc-upload: no file for ${spec.tool} (${spec.pattern})`); continue; }
    if (files.length > 1) log.warn(`ssdlc-upload: ${spec.tool}: ${files.length} files match ${spec.pattern} — using ${path.relative(process.cwd(), files[0])}`);
    if (reports.some((r) => r.tool === spec.tool)) { log.warn(`ssdlc-upload: ${spec.tool} listed twice — keeping the first`); continue; }
    const raw = readFileSync(files[0], "utf8");
    const { text, changed } = mask ? maskReport(spec.tool, spec.format, raw) : { text: raw, changed: 0 };
    console.log(`ssdlc-upload: ${spec.tool} ← ${path.relative(process.cwd(), files[0])} (${raw.length} chars${changed ? `, ${changed} field(s) masked` : ""})`);
    reports.push({ tool: spec.tool, format: spec.format, text });
  }
  if (!reports.length) { log.warn("ssdlc-upload: no reports found — nothing uploaded"); writeSummary(renderSummary({ skipped: "no report files found" })); emptyOutputs(); return 0; }

  const repository = process.env.GITHUB_REPOSITORY ?? "";
  const targetKey = input("target-key", `github:${repository}`);
  const envelope = buildEnvelope({
    repository, runId: input("run-id", process.env.GITHUB_RUN_ID ?? ""), runAttempt: process.env.GITHUB_RUN_ATTEMPT,
    targetKey, targetKind: input("target-kind"), displayName: input("target-display-name", targetKey.startsWith("github:") ? repository.split("/").pop() : ""),
    defaultBranch: readDefaultBranch(), internetFacing: input("internet-facing").toLowerCase(), scope: input("scope"), eventName,
    ref: process.env.GITHUB_REF, sha: process.env.GITHUB_SHA, serverUrl: process.env.GITHUB_SERVER_URL,
  }, reports);
  const { body, headers, gzip, jsonBytes } = encodeBody(envelope, { sign: truthy(input("sign", "true")), token });
  console.log(`ssdlc-upload: POST ${endpoint} — ${reports.length} report(s), ${jsonBytes} bytes json${gzip ? `, ${body.length} bytes gzip` : ""}, externalId ${envelope.run.externalId}`);

  const res = await postWithRetries(endpoint, body, headers, timeoutMs);
  if (!res.ok) { log.warn(`ssdlc-upload: upload failed — ${res.error}`); writeSummary(renderSummary({ error: res.error })); emptyOutputs(); return 0; }
  let runs = Array.isArray(res.json?.runs) ? res.json.runs : [res.json];
  if (runs.some((r) => !isTerminal(r.status))) runs = await pollRuns(endpoint, runs, token, timeoutMs);
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
