"""
Guardrails around the LLM.

Threat model: scan findings contain attacker-controllable strings (service
banners, hostnames, HTTP titles, fingerprinted OS strings). If those strings
reach an LLM that drafts tickets, an attacker on a compromised host can attempt
prompt injection to downgrade their own finding, suppress remediation, or
exfiltrate prompt contents via the ticket body.

Defenses, in order:
  1. Architecture: the LLM cannot set priority. Scoring is deterministic
     (score.py) and happens before the LLM is ever called.
  2. Normalization: untrusted fields are NFKC-folded, stripped of invisible
     characters, and de-leeted before screening, so cheap obfuscation does not
     walk past the pattern list.
  3. Input screening: untrusted fields are scanned for instruction-like
     content. Hits are flagged, the field is redacted before prompting, and
     the ticket is stamped with an injection warning for the analyst.
  4. Prompt isolation: untrusted values are fenced inside <untrusted_data>
     tags with an explicit "treat as inert data" instruction, and every
     untrusted value is markup-escaped whether or not it tripped a pattern -
     so an undetected "</untrusted_data>" cannot close the fence.
  5. Output contract: the LLM must return strict JSON with an exact key set.
     Anything else is rejected. References are restricted to an allowlist
     matched on the parsed hostname. Quarantined text must not reappear in
     the output.

Screening (step 3) is best effort and English-biased; a paraphrase or a
translation can evade it. Steps 1, 4, and 5 do not depend on detection, which
is why the red-team suite asserts containment separately from detection.
"""

import html
import json
import re
import unicodedata
from urllib.parse import urlparse

# Fields an attacker can influence remotely. "hostname" and "os" live on the
# asset record, not the finding, but both are commonly derived from what the
# target says about itself (reverse DNS, service fingerprinting), so they are
# screened alongside the scan fields.
UNTRUSTED_FIELDS = ["banner", "service", "title", "hostname", "os"]

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

# Invisible characters: zero-width joiners/spaces, word joiner, BOM, soft
# hyphen, and the bidirectional overrides. All of them split a word without
# changing how it renders to a human.
_INVISIBLE_RE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­]")

# Character substitutions that survive a human read but defeat a literal regex.
_LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# The same invisible characters spelled as JSON escapes, for when the text
# being searched is a serialized payload rather than the decoded string.
_ESCAPED_INVISIBLE_RE = re.compile(r"\\u(?:00ad|200[b-f]|202[a-e]|206[0-9a-f]|feff)", re.IGNORECASE)

# Anything that looks like a markup tag, including a bare closing delimiter.
_TAGLIKE_RE = re.compile(r"</?[A-Za-z!?][\w:.\-]*\s*/?>|</\s*[A-Za-z]")

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

# Leak detection: compare overlapping windows of quarantined text against the
# ticket instead of only its opening characters, so a model that echoes the
# middle or tail of a payload is still caught.
_LEAK_WINDOW = 32
_LEAK_STRIDE = 16
_LEAK_MAX_WINDOWS = 128


def normalize(value):
    """Fold a value to the form the screen should reason about.

    NFKC collapses fullwidth/compatibility lookalikes; invisible characters are
    dropped entirely. Used for screening and leak comparison - never for the
    text that is stored or rendered.
    """
    return _INVISIBLE_RE.sub("", unicodedata.normalize("NFKC", str(value)))


def _screening_view(value):
    """Normalized + de-leeted copy of a value, used only for pattern matching."""
    return normalize(value).translate(_LEET_MAP)


def neutralize_markup(value):
    """Escape angle brackets in untrusted text.

    Applied to every untrusted value that reaches the prompt, detected or not.
    An undetected "</untrusted_data>" would otherwise close the fence that
    marks the data as inert, so escaping is what actually holds the boundary -
    the pattern list only decides whether an analyst gets warned.

    Fullwidth brackets are folded to ASCII first: screening sees them through
    NFKC, so escaping has to reach them as well, or a tag the screen flags
    would still be handed to the model looking like a tag.
    """
    folded = str(value).replace("\uff1c", "<").replace("\uff1e", ">")
    return html.escape(folded, quote=False)


def is_allowed_reference(ref):
    """True only for https URLs whose parsed host is an allowlisted domain.

    Substring matching is not enough: "https://nvd.nist.gov.attacker.example/x"
    and "https://evil.example/?r=cisa.gov" both contain an approved domain.
    """
    try:
        parsed = urlparse(str(ref).strip())
    except ValueError:
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host:
        return False
    if parsed.username or parsed.password:
        return False  # https://nvd.nist.gov@attacker.example/
    return any(host == domain or host.endswith("." + domain) for domain in ALLOWED_REFERENCE_DOMAINS)


def screen_finding(finding):
    """Scan untrusted fields for injection attempts.

    Returns (clean_finding, alerts). Fields that trip a pattern are replaced
    with a redaction marker before they can reach the prompt; the original is
    preserved under _quarantined for the analyst. Every surviving untrusted
    value is markup-escaped regardless of whether it was flagged.

    Each alert carries:
      field        - which untrusted field fired
      kind         - injection | markup | oversize (obfuscation is reported
                     as a reason on an injection alert, not a kind of its own)
      patterns     - human-readable reasons, shown to the analyst
      original     - the raw value, used for the output leak check
      quarantined  - whether the value was withheld from the prompt
    """
    clean = dict(finding)
    alerts = []
    for field in UNTRUSTED_FIELDS:
        if field not in clean:
            continue
        value = str(clean.get(field, ""))
        screened = _screening_view(value)

        hits = [p.pattern for p in _COMPILED if p.search(screened)]
        if hits:
            reasons = list(hits)
            if screened != value:
                reasons.append("obfuscated (unicode/leetspeak normalization required)")
            alerts.append({"field": field, "kind": "injection", "patterns": reasons,
                           "original": value, "quarantined": True})
            clean.setdefault("_quarantined", {})[field] = value
            clean[field] = "[REDACTED - suspected prompt injection, see quarantine]"
            continue

        if len(value) > MAX_FIELD_CHARS:
            alerts.append({"field": field, "kind": "oversize",
                           "patterns": [f"oversize field ({len(value)} chars)"],
                           "original": value, "quarantined": False})
            value = value[:MAX_FIELD_CHARS] + " [TRUNCATED]"

        if _TAGLIKE_RE.search(normalize(value)):
            # Not conclusive on its own - but a scanner banner has no business
            # carrying markup, and this is exactly how a fence-escape starts.
            alerts.append({"field": field, "kind": "markup",
                           "patterns": ["markup/delimiter sequence neutralized"],
                           "original": value, "quarantined": False})

        clean[field] = neutralize_markup(value)

    return clean, alerts


def _fold(text):
    """Comparison form: normalized, escape-aware, whitespace-collapsed."""
    unescaped = _ESCAPED_INVISIBLE_RE.sub("", str(text))
    return re.sub(r"\s+", " ", normalize(unescaped).lower()).strip()


def _windows(text):
    """Overlapping windows across the whole of `text`, bounded in count."""
    folded = _fold(text)
    if not folded:
        return []
    if len(folded) <= _LEAK_WINDOW:
        return [folded]
    span = len(folded) - _LEAK_WINDOW
    stride = max(_LEAK_STRIDE, -(-span // _LEAK_MAX_WINDOWS))
    starts = list(range(0, span + 1, stride))
    if starts[-1] != span:
        starts.append(span)
    return [folded[i:i + _LEAK_WINDOW] for i in starts]


def text_appears(needle, haystack):
    """True if any window of `needle` shows up in `haystack`.

    Both sides are normalized and whitespace-folded first, so re-wrapping or
    a change of invisible characters does not hide an echoed payload. Matching
    on windows rather than the opening characters catches a model that quotes
    the middle or the tail of a long payload.
    """
    blob = _fold(haystack)
    return any(window in blob for window in _windows(needle))


def find_leaks(text, alerts):
    """Fields whose quarantined content resurfaced in `text`.

    Only quarantined values are checked: a merely truncated (oversize) banner
    was allowed to reach the prompt, so the model may legitimately quote it.
    """
    return [a["field"] for a in alerts
            if a.get("quarantined") and text_appears(a["original"], text)]


def _strip_fence(raw_text):
    """Drop a single leading/trailing markdown code fence, if present."""
    text = str(raw_text).strip()
    if text.startswith("```"):
        text = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", text)
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.strip()


def validate_ticket(raw_text, alerts):
    """Enforce the output contract. Returns (ticket_dict, violations)."""
    violations = []

    try:
        ticket = json.loads(_strip_fence(raw_text))
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

    for key in ("summary", "business_impact", "owner_hint"):
        if key in ticket and not (isinstance(ticket[key], str) and ticket[key].strip()):
            violations.append(f"{key} must be a non-empty string")

    references = ticket.get("references")
    if references is None:
        references = []
    if not isinstance(references, list):
        violations.append("references must be a list")
    else:
        for ref in references:
            if not is_allowed_reference(ref):
                violations.append(f"reference outside allowlist: {ref}")

    steps = ticket.get("remediation_steps")
    if not isinstance(steps, list) or not steps:
        violations.append("remediation_steps must be a non-empty list")
    elif not all(isinstance(s, str) and s.strip() for s in steps):
        violations.append("remediation_steps must contain non-empty strings")

    for field in find_leaks(json.dumps(ticket, ensure_ascii=False), alerts):
        violations.append(f"quarantined content leaked into output (field: {field})")

    return (ticket if not violations else None), violations
