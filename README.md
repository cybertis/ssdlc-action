# Cybertis SSDLC upload (GitHub Action)

Pushes the scan reports your CI already produces (gitleaks, Semgrep, OSV-Scanner,
SARIF, ZAP, nuclei, testssl, CycloneDX, …) to your **Cybertis SSDLC dashboard**.

- Composite action + **one dependency-free Node ≥ 20 file** (`upload.mjs`) — nothing
  to install, easy to audit before you pin it.
- **It never fails your job** unless you opt in with `fail-on: gate`. An empty
  token, a missing report file, a network error or a 4xx from the API is a
  `::warning::` / `::notice::` and exit 0.
- Secrets and code snippets are **masked locally before upload** (details below).

[עברית למטה](#עברית)

## Quick start

1. Your Cybertis consultant mints an ingest token (`ctk_…`) in the client's SSDLC
   settings. Save it as the repository (or organisation) secret
   `CYBERTIS_SSDLC_TOKEN`.
2. Add the step **after** the steps that write the reports:

```yaml
- uses: cybertis/ssdlc-action@v1
  with:
    api-token: ${{ secrets.CYBERTIS_SSDLC_TOKEN }}
    reports: |
      semgrep=semgrep.json
      gitleaks=gitleaks.json
      osv=osv.json
```

Prefer a full-SHA pin (`cybertis/ssdlc-action@<40-hex sha> # v1.x.y`) if your
policy requires immutable action references — see the
[releases](https://github.com/cybertis/ssdlc-action/releases).

If your organisation restricts which actions may run, allow
`cybertis/ssdlc-action@*` under *Settings → Actions → General → Allow select
actions*.

### Full example workflow

No scanners yet? This workflow runs three open-source scanners on every push to
the default branch and once a week, then uploads the results. The scanners are
report-only here (`|| true`) — add your own gates as you see fit.

```yaml
name: cybertis-ssdlc
on:
  push:
    branches: [main]
  schedule:
    - cron: "17 3 * * 1"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: gitleaks (secrets)
        run: |
          docker run --rm -v "$PWD:/repo" -w /repo ghcr.io/gitleaks/gitleaks:v8.30.1 \
            git --no-banner --redact --report-format json --report-path gitleaks.json || true

      - name: Semgrep (SAST)
        run: |
          docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:1.176.0 \
            semgrep scan --metrics=off --config p/default --quiet --json -o semgrep.json || true

      - name: OSV-Scanner (dependencies)
        run: |
          docker run --rm -v "$PWD:/src" -w /src ghcr.io/google/osv-scanner:v2.5.1 \
            scan source --recursive --format=json --output-file=/src/osv.json /src || true

      - uses: cybertis/ssdlc-action@v1
        with:
          api-token: ${{ secrets.CYBERTIS_SSDLC_TOKEN }}
          reports: |
            gitleaks=gitleaks.json
            semgrep=semgrep.json
            osv=osv.json
```

## Inputs

| Input | Default | Notes |
|---|---|---|
| `api-token` | — (required) | Client-scoped token `ctk_…`. **Empty → skip with a notice.** Masked with `::add-mask::` first thing. |
| `endpoint` | `https://platform.cybertis.co.il/api/ingest/ssdlc/v1/scans` | |
| `reports` | — (required) | One per line: `tool=path[:format][@coverage]`. Globs `*` `?` `**`; first match wins; missing → warning. Tools: `sarif semgrep gitleaks osv npm-audit zap nuclei testssl cyclonedx dependabot vitest playwright snyk sonarqube zizmor`. Formats: `json jsonl sarif cyclonedx`. |
| `coverage` | `full` | What each report covers: `full` \| `tree` \| `range` \| `diff`. Only `full` / `tree` let the dashboard auto-resolve findings a report no longer contains; a `range` scan (e.g. gitleaks over a push's commits) or a `diff` scan never resolves. One bare value for every report, or `tool=value` lines; `@coverage` in `reports` wins. *(v1.1.0)* |
| `profile` | `""` | Ruleset / scan profile, ≤ 80 chars (`p/default`, `in-repo`, `community`, …). A finding created by a profile is only auto-resolved by a run of the same profile, so two rulesets on one repo never close each other's findings. Bare value or `tool=value` lines. *(v1.1.0)* |
| `execution` | `""` | How each scanner process ended: `ok` \| `error` \| `unknown`. `ok` is the only proof that an **empty** report (e.g. an empty nuclei JSONL) is a clean scan; `error` marks the run incomplete, so it resolves nothing. Bare value or `tool=value` lines; empty = no claim. *(v1.1.0)* |
| `target-key` | `github:<owner/repo>` | `github:` `gitlab:` `url:` `host:` `custom:` prefix. |
| `target-kind` | derived | `REPOSITORY` (github/gitlab/custom), `WEB_APP` (url), `HOST` (host). |
| `target-display-name` | repo name for `github:` keys | |
| `internet-facing` | `""` | `"true"` / `"false"` update the target; empty leaves it as is. |
| `scope` | auto | `schedule` event → `SCHEDULED`, otherwise `DEFAULT_BRANCH`. |
| `run-id` | `${{ github.run_id }}` | `externalId = gha:<owner/repo>:<run-id>` (`:a<N>` appended on re-runs, N ≥ 2). |
| `mask-secrets` | `true` | Local masking before upload (below). The server strips again regardless. |
| `sign` | `true` | `X-Cybertis-Timestamp` + `X-Cybertis-Signature: v1=<hex HMAC-SHA256(token, "<ts>.<sha256(wire bytes)>")>`. |
| `summary` | `true` | Per-tool table in `$GITHUB_STEP_SUMMARY`. |
| `allow-pr` | `false` | v1 ingest has no PR scope: on `pull_request` the step exits 0 with a notice. |
| `fail-on` | `none` | `gate` → fail only when the server answers `gate.pass === false`. |
| `timeout-seconds` | `60` | Per HTTP request. |

An invalid `coverage` / `profile` / `execution` value is a `::warning::` and is
ignored — it never costs the upload.

```yaml
# v1.1.0 — declare what each report covers and how the scanner ended
- uses: cybertis/ssdlc-action@v1
  with:
    api-token: ${{ secrets.CYBERTIS_SSDLC_TOKEN }}
    coverage: |
      gitleaks=range            # scanned only the pushed commits — never auto-resolves
    profile: |
      semgrep=p/default
    execution: |
      nuclei=ok                 # the scanner ran; an empty report is a clean scan
    reports: |
      gitleaks=gitleaks.json
      semgrep=semgrep.json
      nuclei=nuclei.jsonl:jsonl
```

## Outputs

`scan-run-ids` (comma-separated), `gate-pass` (`true` / `false` / empty),
`summary-json` (`[{ tool, scanRunId, status, duplicate, summary, warnings }]`).

## What it does

1. Reads each report and masks it locally: **gitleaks** `Secret` → its sha256 hex,
   `Match` + `Line` removed; **semgrep** `extra.lines` removed; **SARIF**
   (`:sarif`, tool `sarif`, or a SARIF `$schema`) snippets cut to 300 chars,
   `codeFlows` / `relatedLocations` removed. Other tools pass through unchanged.
2. Builds the envelope (schema `cybertis.ssdlc.ingest/1`): `run.externalId`,
   target, scope, `branchRef` = `GITHUB_REF`, `commitSha` = `GITHUB_SHA`,
   `ciProvider: github-actions`, `ciRunUrl`, `defaultBranch` from the event
   payload; each report is base64 + sha256, with its `coverage` (default
   `full`) and, when given, `profile` and `execution: { status }`.
3. Gzips the body above 256 KB, signs the wire bytes, POSTs with
   `Authorization: Bearer`. Retries ×3 on 429 / 5xx / network errors
   (1 s, 2 s, 4 s; `Retry-After` honoured, capped at 30 s).
4. Polls the run for up to 20 s while it is `QUEUED` / `PARSING`, then writes
   the step summary + outputs.

Nothing from the reports is ever printed to the log — only tool names, file
paths, byte counts and the server's status / error code. The only network
destination is `endpoint`.

## Versioning

`v1` is a moving tag that follows the latest `v1.x.y` release; breaking changes
get a new major tag.

- **v1.1.0** — new optional inputs `coverage`, `profile`, `execution` and the
  `@coverage` suffix in `reports`; every report now carries a `coverage`
  (default `full`, which is how the server read v1.0.0 reports too).
- **v1.0.0** — first public release.

## Development

`node --test upload.test.mjs` — pure parts only, no network.

## Security

Please report vulnerabilities privately to security@cybertis.co.il rather than
in a public issue.

---

## עברית

Action שמעלה את דוחות הסריקה שה-CI שלכם כבר מפיק (gitleaks, Semgrep,
OSV-Scanner, SARIF, ZAP, nuclei, testssl, CycloneDX ועוד) אל לוח ה-SSDLC של
Cybertis. קובץ Node אחד ללא תלויות — קל לבדוק אותו לפני שמאמצים.

**לעולם לא מפיל את ה-job** אלא אם ביקשתם במפורש `fail-on: gate`. טוקן ריק,
קובץ חסר, שגיאת רשת או 4xx מהשרת → `::warning::` / `::notice::` ויציאה 0.

### התחלה מהירה

1. היועץ של Cybertis מנפיק טוקן (`ctk_…`) במסך הגדרות ה-SSDLC של הלקוח. שמרו
   אותו כ-secret של הריפו (או של הארגון) בשם `CYBERTIS_SSDLC_TOKEN`.
2. הוסיפו את הצעד **אחרי** הצעדים שכותבים את הדוחות:

```yaml
- uses: cybertis/ssdlc-action@v1
  with:
    api-token: ${{ secrets.CYBERTIS_SSDLC_TOKEN }}
    reports: |
      semgrep=semgrep.json
      gitleaks=gitleaks.json
      osv=osv.json
```

אין לכם עדיין סורקים? ראו את ה-workflow המלא בחלק האנגלי למעלה.

אם הארגון שלכם מגביל אילו Actions מותרים — הוסיפו את
`cybertis/ssdlc-action@*` תחת *Settings → Actions → General → Allow select actions*.

### קלטים עיקריים

| קלט | ברירת מחדל | הערות |
|---|---|---|
| `api-token` | חובה | טוקן לקוח `ctk_…`. **ריק → דילוג עם הודעה.** |
| `reports` | חובה | שורה לכל דוח: `tool=path[:format][@coverage]`. תווים כלליים (`*`, `**`) מותרים; קובץ חסר = אזהרה בלבד. |
| `coverage` | `full` | מה הדוח מכסה: `full` / `tree` / `range` / `diff`. רק `full` ו-`tree` סוגרים אוטומטית ממצאים שנעלמו; סריקת `range` (למשל gitleaks על טווח הקומיטים של push) או `diff` לעולם לא סוגרת. ערך אחד לכל הדוחות או שורות `tool=value`. *(v1.1.0)* |
| `profile` | ריק | פרופיל / סט חוקים (עד 80 תווים: `p/default`, `in-repo`, `community`). ממצא שנוצר בפרופיל נסגר אוטומטית רק בריצה של אותו פרופיל. *(v1.1.0)* |
| `execution` | ריק | איך הסתיים תהליך הסורק: `ok` / `error` / `unknown`. `ok` הוא ההוכחה היחידה שדוח **ריק** הוא סריקה נקייה; `error` מסמן את הריצה כחלקית ולא נסגר דבר. *(v1.1.0)* |
| `target-key` | `github:<owner/repo>` | לאתרי web: `url:https://…` (הסוג נגזר אוטומטית). |
| `internet-facing` | ריק | `"true"` / `"false"` מעדכן את היעד. |
| `scope` | אוטומטי | `schedule` → `SCHEDULED`, אחרת `DEFAULT_BRANCH`. |
| `mask-secrets` | `true` | מיסוך מקומי לפני השליחה: סוד gitleaks → sha256, `Match`/`Line` נמחקים; `extra.lines` של Semgrep נמחק; קטעי קוד ב-SARIF נחתכים ל-300 תווים. השרת ממסך שוב בכל מקרה. |
| `sign` | `true` | חתימת HMAC-SHA256 על גוף הבקשה. |
| `allow-pr` | `false` | באירועי `pull_request` הצעד מדלג (אין scope ל-PR בגרסה 1). |
| `fail-on` | `none` | `gate` → כישלון רק כשהשרת מחזיר `gate.pass === false`. |

### פלטים

`scan-run-ids`, `gate-pass`, `summary-json` — ובנוסף טבלה לכל כלי ב-Step Summary.
