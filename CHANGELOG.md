# Changelog

## v1.0.0

Hardening release. Scoring weights, priority thresholds, and SLAs are unchanged.

### Security

- **Reference allowlist bypass fixed.** References were accepted if an approved domain appeared anywhere in the string, so `https://nvd.nist.gov.attacker.example/...` and `https://evil.example/?r=cisa.gov` passed. URLs are now parsed, and a reference must be `https` on the default port with no userinfo, backslashes, whitespace, or control characters, and its hostname must equal an approved domain or be a subdomain of one.
- **Prompt fence can no longer be closed from scanner data.** Every untrusted value is HTML-escaped before it reaches the prompt or a rendered ticket, whether or not the input screen fired. Before this change, an undetected `</untrusted_data>` closed the fence. Fence-closing and chat-role tags (`<system>`, `</untrusted_data>`) are also flagged now.
- **Unicode normalization before screening.** Untrusted values are NFKC-folded and stripped of zero-width, bidi, tag, soft-hyphen, and control characters (including terminal escapes), and whitespace is collapsed, before the patterns run. Zero-width, fullwidth, and whitespace-padded variants of known payloads are now detected. When invisible characters are removed from a value, it is reported as `normalized`.
- **`os` moved to the untrusted fields.** Scanners usually learn the OS by fingerprinting the target, so the target can influence it. It is now screened, escaped, and placed inside `<untrusted_data>`.
- **Trusted-field validation.** CVE IDs, CVSS, finding IDs, criticality, exposure, asset type, and owner must match a strict shape, or the run is refused. This closes injection through the prompt's trusted block and path traversal through `finding_id` in ticket file names.
- **Stronger leak check.** The old check only compared the first 60 characters of quarantined text, and non-ASCII text was compared against `\uXXXX`-escaped JSON. It now normalizes both sides and searches for every six-word window of the quarantined text.
- **Prose fields checked for URLs.** `summary`, `business_impact`, `owner_hint`, and the remediation steps are rejected if they contain URLs outside the allowlist or markdown images.

### LLM path

- Uses structured outputs (`output_config.format` with a JSON schema) so responses are constrained to the ticket shape while they are generated. The local contract is still enforced, and markdown-fenced JSON is no longer accepted.
- Responses that end with a stop reason other than `end_turn` (a refusal or `max_tokens`) are rejected, and API errors fall back to the template instead of crashing the run.
- Type, length, and count limits are enforced locally, since the schema cannot express `maxLength` or `maxItems`.
- The model is configurable with `--model` or `KEVLAR_MODEL`. The default is `claude-sonnet-5`.
- Credential detection follows the SDK's own resolution chain, so an `ant auth login` profile enables `--llm` just as an `ANTHROPIC_API_KEY` does. Previously only the environment variable was recognised.
- The red-team suite has been run end to end against `claude-sonnet-5`: 7/7 payloads contained, every case drafted by the model and accepted by the local contract.
- `--llm` without an API key now warns (CLI) or exits with an error (red-team harness) instead of silently producing template results.
- The triage report shows how many LLM drafts were accepted and how many fell back, and the red-team harness has a `DRAFT` column.

### Other

- EPSS lookups are batched (100 CVEs per request, with an explicit `limit`).
- Dependencies are pinned to compatible ranges (`anthropic>=1.7,<2`, `requests>=2.31,<3`).
- Added a pytest suite (no network or API key needed) and a GitHub Actions workflow that runs the tests, the red-team suite, and the offline demo on every push, plus a manually triggered LLM-mode red-team job.
- Added a `--out` flag. Rendered hostnames use the screened value, and ticket alerts say whether each field was quarantined, truncated, or normalized.
