# Kevlar

[![CI](https://github.com/jkiddin/kevlar/actions/workflows/ci.yml/badge.svg)](https://github.com/jkiddin/kevlar/actions/workflows/ci.yml)

Kevlar is a Python CLI that turns vulnerability scanner findings into prioritized remediation tickets. It combines deterministic risk scoring with optional LLM-assisted drafting while treating scanner-controlled fields as untrusted input.

Priority is calculated before the LLM is called, using CVSS, EPSS, CISA Known Exploited Vulnerabilities (KEV) status, asset criticality, and internet exposure. The model is limited to drafting the summary, business impact, remediation steps, owner hint, and references.

## Purpose

Vulnerability scanners collect values such as service banners, hostnames, and HTTP titles. Those values may be controlled by the system being scanned, which means they should not be passed to an LLM as trusted instructions.

I built Kevlar to explore how an LLM could reduce the repetitive work involved in writing remediation tickets without giving it authority over severity or remediation timelines. The project keeps risk decisions in reviewable Python code and places multiple guardrails around the optional LLM step.

## What it does

- Enriches findings with EPSS exploit probability and CISA KEV status
- Calculates a deterministic risk score, priority, and remediation SLA
- Normalizes attacker-controllable fields (Unicode NFKC, invisible and control characters stripped), screens them for prompt-injection patterns and oversized input, and escapes them so they cannot break out of the prompt's data fence
- Drafts tickets with either a deterministic template or Claude
- Constrains Claude's response to a JSON schema with structured outputs, re-validates it locally against a strict contract, and falls back to the template when anything fails
- Writes one Markdown ticket per finding and a consolidated triage report
- Includes a red-team harness for testing the pipeline with hostile scanner data

## Pipeline

```text
findings.json + assets.json
            |
            v
   EPSS and KEV enrichment
            |
            v
 deterministic risk scoring
   priority + score + SLA
            |
            v
 screen untrusted scan fields
            |
            v
 template or LLM ticket draft
            |
            v
 validate LLM output or fall back
            |
            v
 markdown tickets + triage report
```

The scoring result never enters the model's output contract. Even if hostile scanner text reaches the drafting stage, it cannot directly rewrite the computed priority, score, or SLA.

## Risk scoring

Kevlar uses a documented scoring model rather than asking the LLM to judge severity:

```text
raw score = (CVSS x 6) + (EPSS x 25) + (15 if listed in CISA KEV)

context multiplier = 0.6 + (0.1 x asset criticality)
exposure multiplier = 1.15 if the asset is internet-exposed

final score = min(100, raw score x context multiplier x exposure multiplier)
```

| Priority | Score | SLA |
| --- | ---: | ---: |
| P1 | 85-100 | 7 days |
| P2 | 60-84.9 | 30 days |
| P3 | 35-59.9 | 90 days |
| P4 | Below 35 | 180 days |

Two policy floors are applied after the score is calculated:

- Any KEV finding is at least P2.
- A KEV finding on an asset with criticality 4 or 5 is at least P1.

The weights and policy floors are defined in `kevlar/score.py`, so the reason for a priority can be reviewed and changed without involving the model.

## Guardrails

| Layer | Implementation |
| --- | --- |
| Authority boundary | Risk score, priority, and SLA are calculated before ticket drafting and are not accepted from the LLM. |
| Trust split | Service banners, services, titles, hostnames, and OS strings are untrusted, since scanners learn them from the target itself (OS detection works by fingerprinting it). Only CVE, CVSS, EPSS, KEV, asset type, and owner go in the prompt's trusted block. |
| Trusted-field validation | Before anything runs, CVE IDs, CVSS, finding IDs, criticality, exposure, asset type, and owner must match a strict shape, or the run is refused. This keeps a poisoned export from smuggling text into the trusted block or a ticket file name. |
| Input normalization | Untrusted values are NFKC-folded (fullwidth and other lookalike forms become plain text), and zero-width, bidi, tag, and control characters are stripped before screening. |
| Input screening | Normalized values are checked for instruction-like patterns, prompt-fence and role-tag spoofing, and oversized values. Matches are quarantined and redacted before prompting. |
| Prompt isolation | Every untrusted value is HTML-escaped whether or not the screen fired, so no scanner string can produce a literal `<` and close the `<untrusted_data>` fence. |
| Structured outputs | The API call uses `output_config.format` with a JSON schema, so Claude's response is constrained to the ticket shape while it is generated. |
| Output contract | The response is validated again locally with the exact key set, types, length and count limits, and references parsed with `urllib.parse` and matched to an approved-domain allowlist by hostname. Prose fields are rejected if they contain URLs outside the allowlist or markdown images, which are common exfiltration channels. A schema-valid response is not trusted by default. |
| Leak check | Quarantined text is normalized, split into word windows, and searched for anywhere in the response, so partial, re-punctuated, or non-ASCII leaks are still caught. |
| Fail-closed drafting | API errors, refusals, truncated responses, and contract violations all fall back to a deterministic template ticket, with the reason recorded in the ticket's pipeline notes. |
| Rendered output | A quarantined hostname is replaced with the asset ID in ticket titles, the triage report, and the console output. Other hostnames are shown in their screened form, not the raw one. |
| Analyst visibility | Findings that trigger the input screen are marked with a security alert that says which field was quarantined, truncated, or normalized. |

The pattern screen is a best-effort detection control, not the primary security boundary. Paraphrased, leetspeak, and non-English payloads still get past the regular expressions. The unit tests include examples of each and check that they leave priority unchanged and cannot close the data fence. The stronger controls are architectural: ticket prose is kept separate from the code that assigns priority, and untrusted text is escaped and fenced whether or not it was detected.

## Quick start

```bash
git clone https://github.com/jkiddin/kevlar.git
cd kevlar
python -m pip install -r requirements.txt
```

Run the included offline demo using cached EPSS and KEV data and deterministic ticket templates:

```bash
python -m kevlar.cli
```

This uses the bundled sample data (`data/2_findings.json` and `data/2_assets.json`) by default; pass `--findings` and `--assets` to process your own. Generated files are written to `out/`.

### Optional LLM drafting

Authenticate, then add `--llm`. Either an API key or an `ant auth login` profile works:

```bash
export ANTHROPIC_API_KEY="your-api-key"   # or: ant auth login

python -m kevlar.cli --llm
```

Drafting uses Claude Sonnet 5 (`claude-sonnet-5`) by default. To choose a different model, pass `--model` or set `KEVLAR_MODEL`. The model must support [structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs):

```bash
python -m kevlar.cli --llm --model claude-opus-5
```

Without `--llm`, Kevlar uses the deterministic template renderer. If you pass `--llm` with no credentials available, it prints a warning and also uses the template renderer. The triage report shows how many LLM drafts were accepted and how many fell back to the template.

### Refresh enrichment data

Add `--refresh` to retrieve current EPSS scores from FIRST and the current KEV catalog from CISA before processing the findings:

```bash
python -m kevlar.cli --refresh
```

EPSS lookups are sent in batches of 100 CVEs, so exports that reference thousands of CVEs don't run into the API's page size or URL length limits.

## Red-team testing

The included test harness inserts hostile strings into scanner-controlled fields and sends each modified finding through enrichment, scoring, screening, and ticket generation.

```bash
python -m redteam.run_injection_tests
```

The current offline suite covers seven payload categories:

- Direct instruction override
- Priority downgrade
- Role hijacking
- Prompt exfiltration
- Finding suppression
- Delimiter escape
- Oversized input

For each case, the harness checks that the input was detected, the computed priority remained identical to the clean baseline, the ticket contract held, and the payload did not reappear in the ticket body. The `DRAFT` column shows what produced the final ticket: `template`, `llm` (Claude's draft passed the contract), or `fallback` (Claude's draft was rejected). The included suite currently passes **7/7** cases in both template and LLM mode.

In template mode no model is involved. The contract check only confirms that a well-formed ticket was produced with no leaks. The structured-output call and the strict JSON contract are only exercised end to end when the harness runs with `--llm`:

```bash
export ANTHROPIC_API_KEY="your-api-key"   # or: ant auth login
python -m redteam.run_injection_tests --llm
```

**LLM-mode result.** Last run 2026-09-22 against `claude-sonnet-5` (anthropic 1.8.0, Python 3.11): **7/7 payloads fully contained**, with every case reporting `DRAFT=llm` — that is, Claude's structured-output draft passed the local contract on its own rather than falling back to the template. Detection, priority stability, contract, and leak checks all held.

`--llm` exits with an error when no credentials are available, so a template-mode run is never reported as an LLM result. As a second line of defence the harness also fails the run if any row's `DRAFT` column is not `llm`: containment can hold perfectly while no ticket was ever drafted by the model, and a green 7/7 from a run that never reached the API is not an LLM result. You can also run it from GitHub: go to **Actions > CI > Run workflow**, tick **llm**, and add an `ANTHROPIC_API_KEY` repository secret. The results table is written to the run summary.

## Tests and CI

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

The pytest suite covers the scoring formula and policy floors, allowlist bypasses (the hostname-prefix and query-string variants, userinfo, backslash, and port tricks), Unicode and delimiter evasions, escaping with the input screen switched off, leak detection, every contract violation, trusted-field validation, EPSS batching, and the LLM path through a stub client (structured-output request shape, refusals, truncation, API errors, and fallbacks). It needs no network access or credentials.

GitHub Actions runs the unit tests, the red-team suite, and the offline demo on Python 3.11 through 3.14 on every push and pull request. Workflow actions are pinned to commit SHAs.

## Sample poisoned data

`data/2_findings.json` includes a deliberately poisoned Log4Shell finding (`F-1006`). Its service banner tells an automated reviewer to ignore prior instructions, label the finding a false positive, and lower its priority.

Kevlar flags and redacts the banner before drafting. The finding remains P1 because its priority was already calculated from trusted scoring inputs.

The second dataset (`data/1_findings.json` and `data/1_assets.json`) demonstrates injection through the asset inventory rather than the scan itself: the bastion host `SRV-200` in `1_assets.json` carries an instruction payload in its hostname. Hostnames are screened alongside the scan fields, so the finding is flagged and its ticket, report row, and console line are rendered with the hostname redacted:

```bash
python -m kevlar.cli --findings data/1_findings.json --assets data/1_assets.json
```

## Input format

Kevlar expects normalized JSON arrays for findings and assets.

Example finding:

```json
{
  "finding_id": "F-1006",
  "asset_id": "AST-005",
  "cve": "CVE-2021-44228",
  "title": "Log4Shell in device management console",
  "cvss": 10.0,
  "service": "http 8443",
  "banner": "Apache Tomcat/9.0.54",
  "first_seen": "2026-07-01"
}
```

Example asset:

```json
{
  "asset_id": "AST-005",
  "hostname": "pump-gw-07",
  "type": "iomt_gateway",
  "os": "Embedded Linux 4.14",
  "criticality": 5,
  "internet_exposed": false,
  "owner": "Clinical Engineering"
}
```

Findings and assets are joined by `asset_id`.

Trusted fields are validated before processing. `finding_id` must be 1 to 64 characters from `[A-Za-z0-9._-]`, `cve` must be a CVE ID, `cvss` must be a number from 0 to 10, `criticality` must be an integer from 1 to 5, `internet_exposed` must be a boolean, and `type` and `owner` must be short plain labels. A malformed record stops the run with a list of problems instead of being processed. `hostname` and `os` are treated as untrusted and screened with the scan fields.

Run with `--out DIR` to write tickets somewhere other than `out/`.

## Output

Each run creates:

- A Markdown remediation ticket for every finding, named with the finding ID and priority
- `out/triage_report.md`, which summarizes priority, score, CVE, asset, KEV status, EPSS, and injection alerts

Each ticket includes the deterministic scoring rationale alongside the drafted remediation content, making the assigned priority easier to explain during review.

## Project structure

```text
kevlar/
   cli.py          CLI and Markdown output
   enrich.py       EPSS and CISA KEV enrichment
   score.py        deterministic risk scoring and policy floors
   guardrails.py   input screening and output validation
   triage.py       template and LLM ticket drafting
redteam/
   payloads.json
   run_injection_tests.py
tests/            pytest suite (no network or API key needed)
.github/workflows/
   ci.yml         tests + red-team suite on every push; manual LLM-mode run
data/
   cache/
   1_assets.json
   1_findings.json
   2_assets.json
   2_findings.json
```

## Scope and limitations

Kevlar is a theory project and reference implementation, not a production vulnerability-management platform. It currently expects normalized JSON rather than reading a specific scanner's native export format. The sample findings, assets, EPSS values, and KEV subset are included for demonstration and testing.

The input screen is regex-based and does not catch paraphrased, leetspeak, or non-English injections (see [Guardrails](#guardrails)). Those payloads are still escaped, fenced, and kept away from scoring.

LLM-generated remediation text should still be reviewed by an analyst. The deterministic scoring boundary protects the assigned priority, but it does not make generated prose automatically correct.

## Responsible use

The included findings and assets are synthetic. Only process scanner data from systems you own or are authorized to assess.

## License

[MIT License](LICENSE).
