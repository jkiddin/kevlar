# Kevlar

Kevlar is a Python CLI that turns vulnerability scanner findings into prioritized remediation tickets. It combines deterministic risk scoring with optional LLM-assisted drafting while treating scanner-controlled fields as untrusted input.

Priority is calculated before the LLM is called, using CVSS, EPSS, CISA Known Exploited Vulnerabilities (KEV) status, asset criticality, and internet exposure. The model is limited to drafting the summary, business impact, remediation steps, owner hint, and references.

## Purpose

Vulnerability scanners collect values such as service banners, hostnames, and HTTP titles. Those values may be controlled by the system being scanned, which means they should not be passed to an LLM as trusted instructions.

I built Kevlar to explore how an LLM could reduce the repetitive work involved in writing remediation tickets without giving it authority over severity or remediation timelines. The project keeps risk decisions in reviewable Python code and places multiple guardrails around the optional LLM step.

## What it does

- Enriches findings with EPSS exploit probability and CISA KEV status
- Calculates a deterministic risk score, priority, and remediation SLA
- Screens attacker-controllable fields for prompt-injection patterns and oversized input
- Drafts tickets with either a deterministic template or Claude
- Validates LLM output against a strict JSON contract and falls back to the template when validation fails
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
| Input screening | Service banners, services, titles, and hostnames are checked for instruction-like patterns and oversized values before prompting. |
| Prompt isolation | Scanner-controlled values are placed inside `<untrusted_data>` tags and described as inert data. |
| Output contract | LLM responses must be JSON with an exact key set, non-empty remediation steps, and references checked against an approved-domain list. |
| Leak check | Quarantined text is checked for resurfacing in an LLM response before that response is accepted. |
| Fail-closed drafting | Invalid LLM output is rejected and replaced with a deterministic template ticket. |
| Analyst visibility | Findings that trigger the input screen are marked with a security alert in the generated ticket. |

The pattern screen is a best-effort detection control, not the primary security boundary. A new or obfuscated payload may avoid a regular expression. The stronger control is architectural: ticket prose is separated from the code that assigns priority.

## Quick start

```bash
git clone https://github.com/jkiddin/kevlar.git
cd kevlar
python -m pip install -r requirements.txt
```

Run the included offline demo using cached EPSS and KEV data and deterministic ticket templates:

```bash
python -m kevlar.cli \
  --findings data/2_findings.json \
  --assets data/2_assets.json
```

Generated files are written to `out/`.

### Optional LLM drafting

Set an Anthropic API key and add `--llm`:

```bash
export ANTHROPIC_API_KEY="your-api-key"

python -m kevlar.cli \
  --findings data/2_findings.json \
  --assets data/2_assets.json \
  --llm
```

Without `--llm`, or without an API key, Kevlar uses the deterministic template renderer.

### Refresh enrichment data

Add `--refresh` to retrieve current EPSS scores from FIRST and the current KEV catalog from CISA before processing the findings:

```bash
python -m kevlar.cli \
  --findings data/2_findings.json \
  --assets data/2_assets.json \
  --refresh
```

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

For each case, the harness checks that the input was detected, the computed priority remained identical to the clean baseline, the ticket contract held, and the payload did not reappear in the ticket body. The included suite currently passes **7/7** cases in template mode.

To run the same harness with LLM drafting enabled:

```bash
export ANTHROPIC_API_KEY="your-api-key"
python -m redteam.run_injection_tests --llm
```

## Sample poisoned finding

`data/2_findings.json` includes a deliberately poisoned Log4Shell finding (`F-1006`). Its service banner tells an automated reviewer to ignore prior instructions, label the finding a false positive, and lower its priority.

Kevlar flags and redacts the banner before drafting. The finding remains P1 because its priority was already calculated from trusted scoring inputs.

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
data/
   cache/
   1_assets.json
   1_findings.json
   2_assets.json
   2_findings.json
```

## Scope and limitations

Kevlar is a theory project and reference implementation, not a production vulnerability-management platform. It currently expects normalized JSON rather than reading a specific scanner's native export format. The sample findings, assets, EPSS values, and KEV subset are included for demonstration and testing.

LLM-generated remediation text should still be reviewed by an analyst. The deterministic scoring boundary protects the assigned priority, but it does not make generated prose automatically correct.

## Responsible use

The included findings and assets are synthetic. Only process scanner data from systems you own or are authorized to assess.

## License

[MIT License](LICENSE).
