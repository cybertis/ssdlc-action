// Unit tests for the pure parts of upload.mjs — no network, no GitHub env.
// Run: node --test .github/actions/ssdlc-upload/upload.test.mjs
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";
import {
  AUTH_MODES, fetchIdToken, main, oidcAudienceFor, resolveAuthMode, shouldFallBackToToken,
  buildEnvelope, encodeBody, expandGlob, globToRegExp, GZIP_THRESHOLD, isRetryable, isTerminal, maskReport,
  COVERAGES, DEFAULT_COVERAGE, EXECUTION_STATUSES, isKnownScopeInput, parseReportSpecs, pullRequestFromEvent, SCOPES, parseToolValues, renderSummary, resolveScope, retryDelayMs, SCHEMA_ID, signHeaders, skipReason, SNIPPET_MAX, targetKindFor,
} from "./upload.mjs";

const hex = (s) => createHash("sha256").update(s).digest("hex");

test("parseReportSpecs: tool=path[:format], comments, blanks, lower-cased tool", () => {
  const specs = parseReportSpecs("gitleaks=out/gitleaks.json\n# comment\n\n Zizmor = zizmor.sarif:sarif \nnuclei=out/nuclei.jsonl:jsonl\nzap=C:/weird/path.json");
  assert.deepEqual(specs, [
    { tool: "gitleaks", pattern: "out/gitleaks.json", format: undefined },
    { tool: "zizmor", pattern: "zizmor.sarif", format: "sarif" },
    { tool: "nuclei", pattern: "out/nuclei.jsonl", format: "jsonl" },
    { tool: "zap", pattern: "C:/weird/path.json", format: undefined },
  ]);
  assert.throws(() => parseReportSpecs("no-equals"), /expected tool=path/);
  assert.throws(() => parseReportSpecs("tool="), /empty path/);
});

test("parseReportSpecs: @coverage suffix (after :format), unknown suffix stays in the path", () => {
  const specs = parseReportSpecs("gitleaks=gitleaks.json@range\nzizmor=z.sarif:sarif@tree\nsemgrep=me@host/semgrep.json\nosv=osv.json@bogus");
  assert.deepEqual(specs, [
    { tool: "gitleaks", pattern: "gitleaks.json", format: undefined, coverage: "range" },
    { tool: "zizmor", pattern: "z.sarif", format: "sarif", coverage: "tree" },
    { tool: "semgrep", pattern: "me@host/semgrep.json", format: undefined },
    { tool: "osv", pattern: "osv.json@bogus", format: undefined },
  ]);
  assert.deepEqual(COVERAGES, ["full", "range", "tree", "diff"]);
});

test("parseToolValues: bare default + per-tool lines, validation", () => {
  const cov = parseToolValues("tree\ngitleaks=range", { name: "coverage", allowed: COVERAGES });
  assert.equal(cov("gitleaks"), "range");
  assert.equal(cov("semgrep"), "tree");
  const prof = parseToolValues("semgrep=p/default", { name: "profile", max: 80 });
  assert.equal(prof("semgrep"), "p/default");
  assert.equal(prof("gitleaks"), undefined);
  assert.equal(parseToolValues("")("x"), undefined);
  assert.throws(() => parseToolValues("gitleaks=everything", { name: "coverage", allowed: COVERAGES }), /expected one of/);
  assert.throws(() => parseToolValues(`semgrep=${"x".repeat(81)}`, { name: "profile", max: 80 }), /longer than 80/);
  assert.throws(() => parseToolValues("semgrep=", { name: "profile" }), /empty value/);
});

test("buildEnvelope: per-report coverage + profile reach the wire", () => {
  const env = buildEnvelope({ repository: "a/b", runId: "1", targetKey: "github:a/b", eventName: "push" }, [
    { tool: "gitleaks", text: "[]", coverage: "range" },
    { tool: "semgrep", text: "{}", coverage: "full", profile: "in-repo" },
  ]);
  assert.equal(env.reports[0].coverage, "range");
  assert.ok(!("profile" in env.reports[0]));
  assert.equal(env.reports[1].coverage, "full");
  assert.equal(env.reports[1].profile, "in-repo");
  assert.ok(!("execution" in env.reports[0]), "no execution claim unless one was given");
});

test("execution: input values validated; reaches the wire as { status }", () => {
  const exec = parseToolValues("nuclei=ok\ntestssl=ok\nzap=error", { name: "execution", allowed: EXECUTION_STATUSES });
  assert.equal(exec("nuclei"), "ok");
  assert.equal(exec("zap"), "error");
  assert.equal(exec("semgrep"), undefined);
  assert.equal(parseToolValues("unknown", { name: "execution", allowed: EXECUTION_STATUSES })("anything"), "unknown");
  assert.throws(() => parseToolValues("nuclei=fine", { name: "execution", allowed: EXECUTION_STATUSES }), /expected one of ok, error, unknown/);
  const env = buildEnvelope({ repository: "a/b", runId: "1", targetKey: "url:https://x.io", eventName: "schedule" }, [
    { tool: "nuclei", text: "", execution: "ok" },
    { tool: "testssl", text: "[]" },
  ]);
  assert.deepEqual(env.reports[0].execution, { status: "ok" });
  assert.ok(!("execution" in env.reports[1]));
});

test("globToRegExp: *, ?, ** semantics", () => {
  assert.ok(globToRegExp("*.json").test("a.json"));
  assert.ok(!globToRegExp("*.json").test("dir/a.json"));
  assert.ok(globToRegExp("**/*.json").test("a/b/c.json"));
  assert.ok(globToRegExp("**/*.json").test("c.json"));
  assert.ok(globToRegExp("shard-?.json").test("shard-1.json"));
  assert.ok(!globToRegExp("shard-?.json").test("shard-12.json"));
  assert.ok(!globToRegExp("a.json").test("aXjson"), "dot is literal");
});

test("expandGlob: plain path, glob, missing → []", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "ssdlc-"));
  mkdirSync(path.join(dir, "reports", "ssdlc-vitest-1"), { recursive: true });
  mkdirSync(path.join(dir, "reports", "ssdlc-vitest-2"), { recursive: true });
  writeFileSync(path.join(dir, "reports", "ssdlc-vitest-1", "vitest-shard-1.json"), "{}");
  writeFileSync(path.join(dir, "reports", "ssdlc-vitest-2", "vitest-shard-2.json"), "{}");
  writeFileSync(path.join(dir, "gitleaks.json"), "[]");
  assert.deepEqual(expandGlob("gitleaks.json", dir), [path.join(dir, "gitleaks.json")]);
  assert.deepEqual(expandGlob("missing.json", dir), []);
  assert.deepEqual(expandGlob("reports/**/*.json", dir).map((p) => path.basename(p)), ["vitest-shard-1.json", "vitest-shard-2.json"]);
  assert.deepEqual(expandGlob("reports/ssdlc-vitest-?/vitest-shard-2.json", dir).length, 1);
  assert.deepEqual(expandGlob("reports", dir), [], "a directory is not a report");
});

test("resolveScope / targetKindFor / skipReason", () => {
  assert.equal(resolveScope("", "schedule"), "SCHEDULED");
  assert.equal(resolveScope("", "push"), "DEFAULT_BRANCH");
  assert.equal(resolveScope("", "workflow_dispatch"), "DEFAULT_BRANCH");
  assert.equal(resolveScope("scheduled", "push"), "SCHEDULED");
  assert.equal(targetKindFor("github:a/b"), "REPOSITORY");
  assert.equal(targetKindFor("url:https://x"), "WEB_APP");
  assert.equal(targetKindFor("host:x"), "HOST");
  assert.equal(targetKindFor("url:https://x", "host"), "HOST");
  assert.match(skipReason({ token: "", eventName: "push", allowPr: false }), /api-token is empty/);
  assert.match(skipReason({ token: "t", eventName: "pull_request", allowPr: false }), /pull_request/);
  assert.equal(skipReason({ token: "t", eventName: "pull_request", allowPr: true }), null);
  assert.equal(skipReason({ token: "t", eventName: "push", allowPr: false }), null);
});

test("resolveScope: auto from the event, the four input forms, v1.1 wire values, unknown → auto", () => {
  assert.deepEqual(SCOPES, ["DEFAULT_BRANCH", "SCHEDULED", "PULL_REQUEST"]);
  assert.equal(resolveScope("", "pull_request"), "PULL_REQUEST");
  assert.equal(resolveScope("auto", "pull_request_target"), "PULL_REQUEST");
  assert.equal(resolveScope("auto", "schedule"), "SCHEDULED");
  assert.equal(resolveScope("push", "schedule"), "DEFAULT_BRANCH");
  assert.equal(resolveScope("schedule", "workflow_dispatch"), "SCHEDULED");
  assert.equal(resolveScope(" Pull_Request ", "push"), "PULL_REQUEST");
  assert.equal(resolveScope("SCHEDULED", "workflow_dispatch"), "SCHEDULED");
  assert.equal(resolveScope("DEFAULT_BRANCH", "schedule"), "DEFAULT_BRANCH");
  assert.equal(resolveScope("PULL_REQUEST", "pull_request"), "PULL_REQUEST");
  for (const bad of ["nightly", "constructor", "__proto__", "toString"]) {
    assert.equal(isKnownScopeInput(bad), false, bad);
    assert.equal(resolveScope(bad, "push"), "DEFAULT_BRANCH", bad);
  }
  for (const ok of ["", "auto", "push", "schedule", "pull_request", "SCHEDULED", "default_branch"]) assert.equal(isKnownScopeInput(ok), true, ok);
});

test("skipReason: a PR event uploads only on opt-in (scope: pull_request or allow-pr)", () => {
  assert.match(skipReason({ token: "t", eventName: "pull_request", allowPr: false, scopeInput: "" }), /without scope: pull_request/);
  assert.match(skipReason({ token: "t", eventName: "pull_request", allowPr: false, scopeInput: "auto" }), /without scope: pull_request/);
  assert.match(skipReason({ token: "t", eventName: "pull_request_target", allowPr: false }), /pull_request_target/);
  assert.equal(skipReason({ token: "t", eventName: "pull_request", allowPr: false, scopeInput: "pull_request" }), null);
  assert.equal(skipReason({ token: "", eventName: "pull_request", allowPr: false, scopeInput: "pull_request", oidc: true }), null);
});

const SHA_H = "a".repeat(40);
const SHA_B = "b".repeat(40);
const PR_EVENT = { pull_request: { number: 42, head: { sha: SHA_H, ref: "feat/x" }, base: { sha: SHA_B, ref: "main" } }, repository: { default_branch: "main" } };

test("pullRequestFromEvent: number, head/base sha, base ref; anything malformed → null", () => {
  assert.deepEqual(pullRequestFromEvent(PR_EVENT), { number: 42, headSha: SHA_H, baseSha: SHA_B, baseRef: "main" });
  assert.equal(pullRequestFromEvent(null), null);
  assert.equal(pullRequestFromEvent({ ref: "refs/heads/main" }), null);
  const pr = (over) => ({ pull_request: { ...PR_EVENT.pull_request, ...over } });
  assert.equal(pullRequestFromEvent(pr({ number: 0 })), null);
  assert.equal(pullRequestFromEvent(pr({ number: "42" })), null);
  assert.equal(pullRequestFromEvent(pr({ head: { sha: "abc123" } })), null);
  assert.equal(pullRequestFromEvent(pr({ base: { sha: SHA_B.toUpperCase(), ref: "main" } })), null);
  assert.equal(pullRequestFromEvent(pr({ base: { sha: SHA_B, ref: "" } })), null);
  assert.equal(pullRequestFromEvent(pr({ base: { sha: SHA_B, ref: "ma\nin" } })), null);
  assert.equal(pullRequestFromEvent(pr({ base: { sha: SHA_B, ref: "x".repeat(256) } })), null);
});

test("buildEnvelope: run.pullRequest only for PULL_REQUEST; externalId per run (+ :a<N> on re-runs)", () => {
  const prFields = pullRequestFromEvent(PR_EVENT);
  const env = buildEnvelope({ repository: "o/r", runId: "900", runAttempt: "1", targetKey: "github:o/r", scope: "pull_request", eventName: "pull_request", pullRequest: prFields, ref: "refs/pull/42/merge" }, [{ tool: "semgrep", text: "{}" }]);
  assert.equal(env.run.scope, "PULL_REQUEST");
  assert.deepEqual(env.run.pullRequest, { number: 42, headSha: SHA_H, baseSha: SHA_B, baseRef: "main" });
  assert.equal(env.run.externalId, "gha:o/r:900");
  assert.equal(env.run.branchRef, "refs/pull/42/merge");
  const rerun = buildEnvelope({ repository: "o/r", runId: "900", runAttempt: "3", targetKey: "github:o/r", scope: "PULL_REQUEST", eventName: "pull_request", pullRequest: prFields }, [{ tool: "semgrep", text: "{}" }]);
  assert.equal(rerun.run.externalId, "gha:o/r:900:a3");
  const push = buildEnvelope({ repository: "o/r", runId: "901", targetKey: "github:o/r", scope: "", eventName: "push", pullRequest: prFields }, [{ tool: "semgrep", text: "{}" }]);
  assert.equal(push.run.scope, "DEFAULT_BRANCH");
  assert.equal(push.run.pullRequest, undefined);
});

test("maskReport gitleaks: Secret → bare sha256 hex (server-compatible), Match/Line dropped, already-hashed untouched", () => {
  const secret = "AKIAIOSFODNN7EXAMPLE";
  const input = JSON.stringify([{ RuleID: "aws", Secret: secret, Match: `KEY=${secret}`, Line: `export KEY=${secret}`, File: "a.sh" }, { RuleID: "x", Secret: hex("already") }]);
  const { text, changed } = maskReport("gitleaks", undefined, input);
  const out = JSON.parse(text);
  assert.equal(changed, 3);
  assert.equal(out[0].Secret, hex(secret));
  assert.ok(!("Match" in out[0]) && !("Line" in out[0]));
  assert.equal(out[0].File, "a.sh");
  assert.equal(out[1].Secret, hex("already"));
  assert.ok(!text.includes(secret), "the secret must not survive anywhere in the text");
  assert.equal(maskReport("gitleaks", undefined, "not json").text, "not json");
});

test("maskReport semgrep: extra.lines dropped, everything else kept", () => {
  const input = JSON.stringify({ results: [{ check_id: "r", extra: { lines: "const x = 'p@ss'", severity: "ERROR", message: "m" } }, { check_id: "s", extra: { severity: "WARNING" } }], errors: [] });
  const { text, changed } = maskReport("semgrep", undefined, input);
  const out = JSON.parse(text);
  assert.equal(changed, 1);
  assert.equal(out.results[0].extra.lines, undefined);
  assert.equal(out.results[0].extra.message, "m");
  assert.deepEqual(out.errors, []);
});

test("maskReport SARIF (by format or by $schema): snippets truncated, codeFlows/relatedLocations dropped", () => {
  const long = "x".repeat(SNIPPET_MAX + 50);
  const doc = { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [{ results: [
    { ruleId: "a", codeFlows: [{}], relatedLocations: [{}], locations: [{ physicalLocation: { region: { snippet: { text: long } }, contextRegion: { snippet: { text: long } } } }] },
    { ruleId: "b", locations: [{ physicalLocation: { region: { startLine: 1 } } }] },
  ] }] };
  for (const [tool, format] of [["zizmor", "sarif"], ["sarif", undefined], ["zizmor", undefined]]) {
    const { text, changed } = maskReport(tool, format, JSON.stringify(doc));
    const out = JSON.parse(text);
    assert.equal(changed, 4, `${tool}/${format}`);
    assert.equal(out.runs[0].results[0].locations[0].physicalLocation.region.snippet.text.length, SNIPPET_MAX);
    assert.ok(!("codeFlows" in out.runs[0].results[0]) && !("relatedLocations" in out.runs[0].results[0]));
    assert.equal(out.runs[0].results[1].locations[0].physicalLocation.region.startLine, 1);
  }
});

test("maskReport: other tools pass through byte-identical", () => {
  const raw = '{"results": [ {"packages": []} ]}';
  assert.deepEqual(maskReport("osv", undefined, raw), { text: raw, changed: 0 });
});

test("buildEnvelope: contract fields, externalId recipe, target kind/flags, base64 + sha256 per report", () => {
  const now = new Date("2026-09-14T06:00:00Z");
  const env = buildEnvelope({
    repository: "acme/webapp", runId: "1234567890", runAttempt: "1", targetKey: "github:acme/webapp",
    displayName: "webapp", defaultBranch: "main", internetFacing: "true", scope: "", eventName: "push",
    ref: "refs/heads/main", sha: "3b02c255a1f0b2c3d4e5f60718293a4b5c6d7e8f", serverUrl: "https://github.com", now,
  }, [{ tool: "semgrep", format: "json", text: '{"results":[]}' }, { tool: "gitleaks", text: "[]" }]);
  assert.equal(env.schema, SCHEMA_ID);
  assert.equal(env.run.externalId, "gha:acme/webapp:1234567890");
  assert.deepEqual(env.run.target, { kind: "REPOSITORY", key: "github:acme/webapp", displayName: "webapp", defaultBranch: "main", internetFacing: true });
  assert.equal(env.run.scope, "DEFAULT_BRANCH");
  assert.equal(env.run.branchRef, "refs/heads/main");
  assert.equal(env.run.commitSha, "3b02c255a1f0b2c3d4e5f60718293a4b5c6d7e8f");
  assert.equal(env.run.ciProvider, "github-actions");
  assert.equal(env.run.ciRunUrl, "https://github.com/acme/webapp/actions/runs/1234567890");
  assert.equal(env.run.completedAt, "2026-09-14T06:00:00.000Z");
  assert.equal(env.reports.length, 2);
  assert.deepEqual(env.reports[0], { tool: "semgrep", format: "json", content: Buffer.from('{"results":[]}').toString("base64"), encoding: "base64", sha256: hex('{"results":[]}'), coverage: DEFAULT_COVERAGE });
  assert.equal(env.reports[1].format, undefined);
  assert.equal(env.reports[1].coverage, "full", "coverage defaults to full");
  assert.ok(!("profile" in env.reports[1]), "no profile unless one was given");
  assert.equal(Buffer.from(env.reports[1].content, "base64").toString(), "[]");
});

test("buildEnvelope: rerun attempt suffix, url target, unset flags omitted, bad sha omitted", () => {
  const env = buildEnvelope({ repository: "o/r", runId: "7", runAttempt: "2", targetKey: "url:https://platform.cybertis.co.il", internetFacing: "", scope: "", eventName: "schedule", sha: "HEAD" }, [{ tool: "zap", text: "{}" }]);
  assert.equal(env.run.externalId, "gha:o/r:7:a2");
  assert.equal(env.run.scope, "SCHEDULED");
  assert.deepEqual(env.run.target, { kind: "WEB_APP", key: "url:https://platform.cybertis.co.il" });
  assert.equal(env.run.commitSha, undefined);
  assert.equal(env.run.ciRunUrl, undefined);
});

test("signHeaders: v1=HMAC-SHA256(token, '<ts>.<sha256(body)>')", () => {
  const body = Buffer.from("hello");
  const h = signHeaders("ctk_secret", body, 1757829600);
  const expected = createHmac("sha256", "ctk_secret").update(`1757829600.${hex(body)}`).digest("hex");
  assert.deepEqual(h, { "x-cybertis-timestamp": "1757829600", "x-cybertis-signature": `v1=${expected}` });
});

test("encodeBody: plain below the threshold, gzip above it, signature over the WIRE bytes", () => {
  const small = encodeBody({ a: 1 }, { sign: true, token: "t", now: 1000_000 });
  assert.equal(small.gzip, false);
  assert.equal(small.headers["content-type"], "application/json");
  assert.equal(small.headers["user-agent"], "cybertis-ssdlc-upload/1");
  assert.equal(small.headers.authorization, "Bearer t");
  assert.equal(small.headers["content-encoding"], undefined);
  assert.equal(small.headers["x-cybertis-timestamp"], "1000");
  assert.equal(small.headers["x-cybertis-signature"], signHeaders("t", small.body, 1000)["x-cybertis-signature"]);
  const big = encodeBody({ pad: "y".repeat(GZIP_THRESHOLD + 1) }, { sign: false, token: "t" });
  assert.equal(big.gzip, true);
  assert.equal(big.headers["content-encoding"], "gzip");
  assert.equal(big.headers["x-cybertis-signature"], undefined);
  assert.equal(JSON.parse(gunzipSync(big.body).toString()).pad.length, GZIP_THRESHOLD + 1);
});

test("retry policy: 429/5xx retryable, Retry-After honoured (capped 30 s), exponential otherwise", () => {
  assert.ok(isRetryable(429) && isRetryable(500) && isRetryable(503));
  assert.ok(!isRetryable(400) && !isRetryable(403) && !isRetryable(409) && !isRetryable(413));
  assert.equal(retryDelayMs(1), 1000);
  assert.equal(retryDelayMs(2), 2000);
  assert.equal(retryDelayMs(3), 4000);
  assert.equal(retryDelayMs(1, "7"), 7000);
  assert.equal(retryDelayMs(1, "600"), 30000);
  assert.equal(retryDelayMs(2, "garbage"), 2000);
  assert.ok(isTerminal("COMPLETED") && isTerminal("PARTIAL") && isTerminal("FAILED") && isTerminal("DUPLICATE"));
  assert.ok(!isTerminal("QUEUED") && !isTerminal("PARSING"));
});

test("renderSummary: per-tool table, tiers, warnings, gate line; skipped and error variants", () => {
  const md = renderSummary({
    runs: [
      { tool: "semgrep", status: "COMPLETED", summary: { total: 3, new: 1, reopened: 0, resolved: 2, byTier: { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 0, INFO: 0 } }, links: { dashboard: "https://p/x" } },
      { tool: "gitleaks", status: "DUPLICATE", duplicate: true, summary: null, warnings: ["truncated | 5000"] },
    ],
    gate: { mode: "REPORT_ONLY", pass: true, reasons: [] },
  });
  assert.match(md, /^### Cybertis SSDLC upload/);
  assert.match(md, /\| semgrep \| COMPLETED \| 3 \| 1 \| 0 \| 2 \| 0 \/ 1 \/ 2 \/ 0 \/ 0 \| \[open\]\(https:\/\/p\/x\) \|/);
  assert.match(md, /\| gitleaks \| DUPLICATE \(dup\) \| — \| — \| — \| — \| — \| — \|/);
  assert.match(md, /⚠ truncated \\\| 5000/);
  assert.match(md, /Gate: \*\*REPORT_ONLY\*\* — :white_check_mark: pass/);
  assert.match(renderSummary({ gate: { mode: "BLOCKING", pass: false, reasons: ["2 CRITICAL"] } }), /:x: fail \(2 CRITICAL\)/);
  assert.match(renderSummary({ skipped: "api-token is empty" }), /_Skipped: api-token is empty_/);
  assert.match(renderSummary({ error: "HTTP 403 feature_disabled" }), /:warning: HTTP 403 feature_disabled/);
});

// ── auth: token | oidc | auto ───────────────────────────────────────────────
test("resolveAuthMode: auto prefers OIDC only without a token or with prefer-oidc; fails SAFE to the token", () => {
  assert.deepEqual(AUTH_MODES, ["token", "oidc", "auto"]);
  const r = (o) => resolveAuthMode({ auth: "auto", token: "", preferOidc: false, oidcAvailable: false, ...o }).mode;
  // auto
  assert.equal(r({ token: "t", oidcAvailable: true }), "token"); // v1.1 behaviour: a token still wins
  assert.equal(r({ token: "t", oidcAvailable: true, preferOidc: true }), "oidc");
  assert.equal(r({ token: "", oidcAvailable: true }), "oidc");
  assert.equal(r({ token: "t", oidcAvailable: false, preferOidc: true }), "token"); // no id-token permission
  assert.equal(r({ token: "", oidcAvailable: false }), null);
  // token
  assert.equal(r({ auth: "token", token: "t", oidcAvailable: true, preferOidc: true }), "token");
  assert.equal(r({ auth: "token", token: "", oidcAvailable: true }), null);
  // oidc
  assert.equal(r({ auth: "oidc", token: "t", oidcAvailable: true }), "oidc");
  assert.equal(r({ auth: "oidc", token: "t", oidcAvailable: false }), "token");
  assert.match(resolveAuthMode({ auth: "oidc", token: "t", oidcAvailable: false }).note, /id-token: write/);
  assert.equal(r({ auth: "oidc", token: "", oidcAvailable: false }), null);
  // unknown value → auto, with a note
  const odd = resolveAuthMode({ auth: "magic", token: "t", oidcAvailable: true });
  assert.equal(odd.mode, "token");
  assert.match(odd.note, /unknown auth "magic"/);
  assert.equal(resolveAuthMode({ auth: "", token: "t", oidcAvailable: true }).note, null);
});

test("skipReason: an OIDC upload needs no api-token", () => {
  assert.match(skipReason({ token: "", eventName: "push", allowPr: false }), /api-token is empty/);
  assert.equal(skipReason({ token: "", eventName: "push", allowPr: false, oidc: true }), null);
  assert.match(skipReason({ token: "", eventName: "pull_request", allowPr: false, oidc: true }), /pull_request/);
});

test("oidcAudienceFor: explicit input, else the endpoint origin", () => {
  assert.equal(oidcAudienceFor("https://platform.cybertis.co.il/api/ingest/ssdlc/v1/scans"), "https://platform.cybertis.co.il");
  assert.equal(oidcAudienceFor("https://staging.example.com:8443/api/x", ""), "https://staging.example.com:8443");
  assert.equal(oidcAudienceFor("https://platform.cybertis.co.il/api", "cybertis-ssdlc"), "cybertis-ssdlc");
});

test("fetchIdToken: audience appended to the runner URL, bearer = request token; failures throw", async () => {
  const calls = [];
  const ok = async (url, init) => { calls.push({ url, init }); return new Response(JSON.stringify({ value: "h.p.s" }), { status: 200 }); };
  const value = await fetchIdToken({ requestUrl: "https://runner.example/token?api-version=2.0", requestToken: "rt", audience: "https://platform.example.com", fetchImpl: ok });
  assert.equal(value, "h.p.s");
  const u = new URL(calls[0].url);
  assert.equal(u.searchParams.get("api-version"), "2.0");
  assert.equal(u.searchParams.get("audience"), "https://platform.example.com");
  assert.equal(calls[0].init.headers.authorization, "bearer rt");
  await assert.rejects(fetchIdToken({ requestUrl: "https://runner.example/t", requestToken: "rt", audience: "a", fetchImpl: async () => new Response("{}", { status: 403 }) }), /HTTP 403/);
  await assert.rejects(fetchIdToken({ requestUrl: "https://runner.example/t", requestToken: "rt", audience: "a", fetchImpl: async () => new Response(JSON.stringify({ value: "nope" }), { status: 200 }) }), /no token/);
});

// main() end to end with a stubbed fetch: which credential reaches the ingest endpoint.
async function runMain({ inputs = {}, env = {}, idTokenStatus = 200, failFirstPost = false, firstPost = null, event = null } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "ssdlc-auth-"));
  const report = path.join(dir, "semgrep.json");
  writeFileSync(report, JSON.stringify({ results: [], errors: [], paths: { scanned: ["a.ts"] } }));
  const eventPath = path.join(dir, "event.json");
  writeFileSync(eventPath, JSON.stringify(event ?? { repository: { default_branch: "main" } }));
  const vars = {
    INPUT_REPORTS: `semgrep=${report}`, INPUT_ENDPOINT: "https://platform.example.com/api/ingest/ssdlc/v1/scans", INPUT_SUMMARY: "false",
    GITHUB_EVENT_NAME: "push", GITHUB_REPOSITORY: "acme/app", GITHUB_RUN_ID: "77", GITHUB_SHA: "3b02c255", GITHUB_REF: "refs/heads/main",
    GITHUB_OUTPUT: "", GITHUB_STEP_SUMMARY: "", ACTIONS_ID_TOKEN_REQUEST_URL: "", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "", GITHUB_EVENT_PATH: eventPath, GITHUB_RUN_ATTEMPT: "1",
    ...Object.fromEntries(Object.entries(inputs).map(([k, v]) => [`INPUT_${k.replace(/-/g, "_").toUpperCase()}`, v])),
    ...env,
  };
  const saved = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  Object.assign(process.env, vars);
  const realFetch = globalThis.fetch;
  const realLog = console.log;
  const calls = [];
  const logs = [];
  let n = 0;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body });
    if (String(url).startsWith("https://runner.example/")) {
      return idTokenStatus === 200 ? new Response(JSON.stringify({ value: `h.jwt${++n}.s` }), { status: 200 }) : new Response("{}", { status: idTokenStatus });
    }
    if (firstPost && calls.filter((c) => c.method === "POST").length === 1) return new Response(JSON.stringify({ error: firstPost.error, message: "x" }), { status: firstPost.status });
    if (failFirstPost && calls.filter((c) => c.method === "POST").length === 1) return new Response(JSON.stringify({ error: "storage_unavailable" }), { status: 503, headers: { "retry-after": "1" } });
    return new Response(JSON.stringify({ runs: [{ tool: "semgrep", status: "COMPLETED", scanRunId: "r1" }], gate: { mode: "REPORT_ONLY", pass: true } }), { status: 200 });
  };
  console.log = (m) => logs.push(String(m));
  try {
    const code = await main();
    return { code, calls, logs, posts: calls.filter((c) => c.method === "POST") };
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
}
const OIDC_ENV = { ACTIONS_ID_TOKEN_REQUEST_URL: "https://runner.example/token?api-version=2.0", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "rt" };

test("main: token mode (the v1.1 path) — bearer api-token + HMAC, no id token requested", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test" }, env: OIDC_ENV });
  assert.equal(r.code, 0);
  assert.equal(r.posts.length, 1);
  assert.equal(r.posts[0].headers.authorization, "Bearer ctk_test");
  assert.ok(r.posts[0].headers["x-cybertis-signature"]);
  assert.ok(!r.calls.some((c) => c.url.startsWith("https://runner.example/")));
});

test("main: prefer-oidc with id-token permission — bearer id token minted for the endpoint origin, no HMAC", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test", "prefer-oidc": "true" }, env: OIDC_ENV });
  assert.equal(r.code, 0);
  const idCalls = r.calls.filter((c) => c.url.startsWith("https://runner.example/"));
  assert.equal(idCalls.length, 1);
  assert.equal(new URL(idCalls[0].url).searchParams.get("audience"), "https://platform.example.com");
  assert.equal(r.posts[0].headers.authorization, "Bearer h.jwt1.s");
  assert.equal(r.posts[0].headers["x-cybertis-signature"], undefined);
  assert.ok(r.logs.includes("::add-mask::h.jwt1.s"));
});

test("main: auto with no api-token and an OIDC-capable job uploads with OIDC", async () => {
  const r = await runMain({ env: OIDC_ENV });
  assert.equal(r.posts.length, 1);
  assert.equal(r.posts[0].headers.authorization, "Bearer h.jwt1.s");
});

test("main: prefer-oidc but the job lacks id-token: write — falls back to the api-token", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test", "prefer-oidc": "true" } });
  assert.equal(r.posts[0].headers.authorization, "Bearer ctk_test");
});

test("main: the id token request fails — falls back to the api-token; without one nothing is uploaded (exit 0)", async () => {
  const withToken = await runMain({ inputs: { "api-token": "ctk_test", auth: "oidc" }, env: OIDC_ENV, idTokenStatus: 500 });
  assert.equal(withToken.posts[0].headers.authorization, "Bearer ctk_test");
  assert.ok(withToken.logs.some((l) => /falling back to api-token/.test(l)));
  const without = await runMain({ inputs: { auth: "oidc" }, env: OIDC_ENV, idTokenStatus: 500 });
  assert.equal(without.code, 0);
  assert.equal(without.posts.length, 0);
});

test("main: auth: token ignores the OIDC environment even with prefer-oidc", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test", auth: "token", "prefer-oidc": "true" }, env: OIDC_ENV });
  assert.equal(r.posts[0].headers.authorization, "Bearer ctk_test");
});

test("main: a retried POST carries a FRESH id token (the server consumes each jti once)", async () => {
  const r = await runMain({ inputs: { "prefer-oidc": "true", "api-token": "ctk_test" }, env: OIDC_ENV, failFirstPost: true });
  assert.equal(r.posts.length, 2);
  assert.equal(r.posts[0].headers.authorization, "Bearer h.jwt1.s");
  assert.equal(r.posts[1].headers.authorization, "Bearer h.jwt2.s");
});

test("shouldFallBackToToken: only refusals of the OIDC credential itself", () => {
  assert.equal(shouldFallBackToToken(401, "unauthorized"), true);
  assert.equal(shouldFallBackToToken(422, "oidc_target_unknown"), true);
  assert.equal(shouldFallBackToToken(403, "oidc_claims_rejected"), true);
  assert.equal(shouldFallBackToToken(503, "oidc_unavailable"), true);
  assert.equal(shouldFallBackToToken(503, "replay_cache_unavailable"), true);
  assert.equal(shouldFallBackToToken(400, "invalid_body"), false);
  assert.equal(shouldFallBackToToken(403, "feature_disabled"), false);
  assert.equal(shouldFallBackToToken(409, "externalid_conflict"), false);
});

test("main: server refuses the OIDC upload (repo not inventoried yet) → one retry with the signed api-token", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test", "prefer-oidc": "true" }, env: OIDC_ENV, firstPost: { status: 422, error: "oidc_target_unknown" } });
  assert.equal(r.code, 0);
  assert.equal(r.posts.length, 2);
  assert.equal(r.posts[0].headers.authorization, "Bearer h.jwt1.s");
  assert.equal(r.posts[1].headers.authorization, "Bearer ctk_test");
  assert.ok(r.posts[1].headers["x-cybertis-signature"]);
  assert.ok(r.logs.some((l) => /retrying with api-token/.test(l)));
});

test("main: a body error is not retried with the token; no token means no fallback", async () => {
  const bad = await runMain({ inputs: { "api-token": "ctk_test", "prefer-oidc": "true" }, env: OIDC_ENV, firstPost: { status: 400, error: "invalid_body" } });
  assert.equal(bad.posts.length, 1);
  const noToken = await runMain({ env: OIDC_ENV, firstPost: { status: 422, error: "oidc_target_unknown" } });
  assert.equal(noToken.posts.length, 1);
});

test("main: auth: oidc without id-token permission and no token names the missing permission", async () => {
  const r = await runMain({ inputs: { auth: "oidc" } });
  assert.equal(r.posts.length, 0);
  assert.ok(r.logs.some((l) => /::notice::.*id-token: write.*skipping upload/.test(l)));
  assert.ok(!r.logs.some((l) => /create CYBERTIS_SSDLC_TOKEN/.test(l)));
});

// The PR lane (v1.2.0): scope from the event, run.pullRequest from the payload.
const envelopeOf = (post) => JSON.parse(Buffer.from(post.body).toString("utf8"));
const PR_ENV = { GITHUB_EVENT_NAME: "pull_request", GITHUB_REF: "refs/pull/42/merge", GITHUB_SHA: "c".repeat(40), GITHUB_RUN_ID: "9001" };

test("main: pull_request + scope: pull_request + OIDC → PULL_REQUEST envelope with the payload's PR fields", async () => {
  const r = await runMain({ inputs: { scope: "pull_request", auth: "oidc" }, env: { ...OIDC_ENV, ...PR_ENV }, event: PR_EVENT });
  assert.equal(r.code, 0);
  assert.equal(r.posts.length, 1);
  assert.equal(r.posts[0].headers.authorization, "Bearer h.jwt1.s");
  const run = envelopeOf(r.posts[0]).run;
  assert.equal(run.scope, "PULL_REQUEST");
  assert.deepEqual(run.pullRequest, { number: 42, headSha: SHA_H, baseSha: SHA_B, baseRef: "main" });
  assert.equal(run.externalId, "gha:acme/app:9001");
  assert.equal(run.branchRef, "refs/pull/42/merge");
  assert.equal(run.target.defaultBranch, "main");
});

test("main: pull_request with token + allow-pr (auto scope) → PULL_REQUEST, signed", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test", "allow-pr": "true" }, env: { ...PR_ENV }, event: PR_EVENT });
  assert.equal(r.posts.length, 1);
  assert.ok(r.posts[0].headers["x-cybertis-signature"]);
  assert.equal(envelopeOf(r.posts[0]).run.scope, "PULL_REQUEST");
});

test("main: a pull_request event without opt-in is still skipped (v1.1 behaviour)", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test" }, env: { ...PR_ENV }, event: PR_EVENT });
  assert.equal(r.posts.length, 0);
  assert.ok(r.logs.some((l) => /::notice::.*without scope: pull_request/.test(l)));
});

test("main: scope: pull_request on a push (no pull_request in the payload) is skipped with a notice", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test", scope: "pull_request" } });
  assert.equal(r.posts.length, 0);
  assert.ok(r.logs.some((l) => /::notice::.*no pull_request.*skipping upload/.test(l)));
});

test("main: a run-id override keys the externalId only — ciRunUrl names the real run", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test", "run-id": "77-community" }, env: { GITHUB_SERVER_URL: "https://github.com" } });
  const run = envelopeOf(r.posts[0]).run;
  assert.equal(run.externalId, "gha:acme/app:77-community");
  assert.equal(run.ciRunUrl, "https://github.com/acme/app/actions/runs/77");
});

test("main: push keeps DEFAULT_BRANCH and no pullRequest; an unknown scope warns and falls back to auto", async () => {
  const r = await runMain({ inputs: { "api-token": "ctk_test", scope: "nightly" }, event: PR_EVENT });
  assert.equal(r.posts.length, 1);
  const run = envelopeOf(r.posts[0]).run;
  assert.equal(run.scope, "DEFAULT_BRANCH");
  assert.equal(run.pullRequest, undefined);
  assert.ok(r.logs.some((l) => /::warning::.*unknown scope "nightly"/.test(l)));
});

test("action.yml passes every input the script reads (scope included)", () => {
  const yml = readFileSync(new URL("./action.yml", import.meta.url), "utf8");
  const script = readFileSync(new URL("./upload.mjs", import.meta.url), "utf8");
  const read = [...script.matchAll(/(?:input|safeToolValues)\("([a-z-]+)"/g)].map((m) => m[1]);
  for (const name of ["scope", "coverage", "profile", "execution", "run-id"]) assert.ok(read.includes(name), `${name} not detected`);
  for (const name of new Set(read)) {
    assert.match(yml, new RegExp(`^  ${name}:$`, "m"), `input ${name} not declared`);
    assert.match(yml, new RegExp(`INPUT_${name.replace(/-/g, "_").toUpperCase()}: \\$\\{\\{ inputs\\.${name} \\}\\}`), `input ${name} not passed`);
  }
});
