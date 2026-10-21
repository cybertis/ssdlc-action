// Unit tests for the pure parts of upload.mjs — no network, no GitHub env.
// Run: node --test .github/actions/ssdlc-upload/upload.test.mjs
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";
import {
  buildEnvelope, encodeBody, expandGlob, globToRegExp, GZIP_THRESHOLD, isRetryable, isTerminal, maskReport,
  COVERAGES, DEFAULT_COVERAGE, EXECUTION_STATUSES, parseReportSpecs, parseToolValues, renderSummary, resolveScope, retryDelayMs, SCHEMA_ID, signHeaders, skipReason, SNIPPET_MAX, targetKindFor,
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
