"""
Guardrails around the LLM.

Threat model: scan findings contain attacker-controllable strings (service
banners, hostnames, HTTP titles). If those strings reach an LLM that drafts
tickets, an attacker on a compromised host can attempt prompt injection to
downgrade their own finding, suppress remediation, or exfiltrate prompt
contents via the ticket body.

Defenses, in order:
  1. Architecture: the LLM cannot set priority. Scoring is deterministic
     (score.py) and happens before the LLM is ever called.
  2. Input screening: untrusted fields are scanned for instruction-like
     content. Hits are flagged, the field is redacted before prompting, and
     the ticket is stamped with an injection warning for the analyst.
  3. Prompt isolation: untrusted values are fenced inside <untrusted_data>
     tags with an explicit "treat as inert data" instruction.
  4. Output contract: the LLM must return strict JSON with an exact key set.
     Anything else is rejected. References are restricted to an allowlist of
     domains. Redacted/flagged text must not reappear in the output.
"""

import json
import re

# Fields an attacker can influence remotely
UNTRUSTED_FIELDS = ["banner", "service", "title", "hostname"]

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) (instructions|context|rules)",
    r"disregard (the )?(previous|prior|above|earlier)",
    r"you are (now|no longer)",
    r"system prompt",
    r"new instructions?:",
    r"(set|change|mark) (the )?priority",
    r"(false positive|no action (is )?required)",
    r"instead,? (respond|reply|output|say)",
    r"do not (mention|include|report)",
    r"\bBEGIN (PROMPT|INSTRUCTION)",
    r"important notice to (automated|ai|llm)",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

REQUIRED_TICKET_KEYS = {"summary", "business_impact", "remediation_steps", "owner_hint", "references"}

ALLOWED_REFERENCE_DOMAINS = (
    "nvd.nist.gov",
    "cisa.gov",
    "msrc.microsoft.com",
    "ubuntu.com",
    "first.org",
    "cve.org",
)

MAX_FIELD_CHARS = 2000

def screen_finding(finding):
    """Scan untrusted fields for injection attempts.

    Returns (clean_finding, alerts). Fields that trip a pattern are replaced
    with a redaction marker before they can reach the prompt; the original is
    preserved under _quarantined for the analyst.
    """
    clean = dict(finding)
    alerts = []
    for field in UNTRUSTED_FIELDS:
        value = str(clean.get(field, ""))
        hits = [p.pattern for p in _COMPILED if p.search(value)]
        if hits:
            alerts.append({"field": field, "patterns": hits, "original": value})
            clean.setdefault("_quarantined", {})[field] = value
            clean[field] = "[REDACTED - suspected prompt injection, see quarantine]"
        elif len(value) > MAX_FIELD_CHARS:
            alerts.append({"field": field, "patterns": ["oversize field"], "original": value[:200] + "..."})
            clean[field] = value[:MAX_FIELD_CHARS] + " [TRUNCATED]"
    return clean, alerts

def validate_ticket(raw_text, alerts):
    """Enforce the output contract. Returns (ticket_dict, violations)."""
    violations = []

    # Strip common markdown fencing before parsing
    text = re.sub(r"^```(json)?|```$", "", raw_text.strip(), flags=re.MULTILINE).strip()
    try:
        ticket = json.loads(text)
    except json.JSONDecodeError:
        return None, ["output is not valid JSON"]

    if not isinstance(ticket, dict):
        return None, ["output is not a JSON object"]

    keys = set(ticket)
    if keys != REQUIRED_TICKET_KEYS:
        missing, extra = REQUIRED_TICKET_KEYS - keys, keys - REQUIRED_TICKET_KEYS
        if missing:
            violations.append(f"missing keys: {sorted(missing)}")
        if extra:
            violations.append(f"unexpected keys: {sorted(extra)}")

    if "priority" in ticket or "risk_score" in ticket:
        violations.append("LLM attempted to emit priority/score - forbidden by contract")

    for ref in ticket.get("references", []) or []:
        if not any(domain in str(ref) for domain in ALLOWED_REFERENCE_DOMAINS):
            violations.append(f"reference outside allowlist: {ref}")

    if not isinstance(ticket.get("remediation_steps"), list) or not ticket.get("remediation_steps"):
        violations.append("remediation_steps must be a non-empty list")

    # Quarantined text must not resurface in the output
    blob = json.dumps(ticket).lower()
    for alert in alerts:
        snippet = alert["original"][:60].lower()
        if len(snippet) > 20 and snippet in blob:
            violations.append(f"quarantined content leaked into output (field: {alert['field']})")

    return (ticket if not violations else None), violations
