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
  2. Trusted-field validation: the values that are placed in the prompt's
     trusted block (CVE, CVSS, asset type, owner) must match a strict shape,
     so a poisoned export cannot smuggle text in through them.
  3. Input normalization and screening: untrusted fields are NFKC-folded,
     stripped of invisible/control characters, and whitespace-collapsed to a
     single line, then scanned for instruction-like content. Hits are quarantined and redacted before
     prompting, and the ticket is stamped with an alert for the analyst.
  4. Prompt isolation: every untrusted value is HTML-escaped whether or not
     the screen fired, so no scanner string can emit a literal "<" and close
     the <untrusted_data> fence. The fence carries an explicit "treat as inert
     data" instruction.
  5. Output contract: the API constrains the response to TICKET_SCHEMA
     (structured outputs), and validate_ticket re-checks it independently:
     exact key set, types and lengths, references parsed and matched against
     an allowlist by hostname, no off-allowlist URLs or markdown images in
     prose, and no quarantined text resurfacing anywhere in the output.

Detection (layer 3) is best effort. Layers 1, 2, 4 and 5 do not depend on it.
"""

import html
import json
import re
import unicodedata
from urllib.parse import urlparse

# Fields an attacker can influence remotely. hostname and os live on the asset
# record, but scanners usually learn them by fingerprinting the target (DNS and
# NetBIOS names, TCP/IP stack and banner fingerprints), so the target controls
# them too.
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
    # Attempts to close or reopen the prompt fence, or to spoof chat-role tags.
    # Escaping already neutralizes these; the patterns make the attempt visible.
    r"</?\s*untrusted[\s_-]*data",
    r"<\s*/?\s*(system|assistant|human|user|instructions?)\s*>",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

REDACTION_MARKER = "[REDACTED - suspected prompt injection, see quarantine]"

MAX_FIELD_CHARS = 2000

# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------

REQUIRED_TICKET_KEYS = {"summary", "business_impact", "remediation_steps", "owner_hint", "references"}

ALLOWED_REFERENCE_DOMAINS = (
    "nvd.nist.gov",
    "cisa.gov",
    "msrc.microsoft.com",
    "ubuntu.com",
    "first.org",
    "cve.org",
)

# Length and count limits the JSON schema cannot express (structured outputs
# does not support maxLength or maxItems), enforced in validate_ticket instead.
MAX_PROSE_CHARS = 1200
MAX_STEP_CHARS = 300
MAX_STEPS = 8
MAX_REFERENCES = 8

# Sent to the API as output_config.format so the model is constrained to this
# shape at generation time. Only keywords the structured-outputs feature
# supports are used here.
TICKET_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "2-3 sentences, plain business English."},
        "business_impact": {"type": "string", "description": "1-2 sentences."},
        "remediation_steps": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "description": "3-6 short imperative steps.",
        },
        "owner_hint": {"type": "string", "description": "One team name."},
        "references": {
            "type": "array",
            "items": {"type": "string", "format": "uri"},
            "description": "https URLs on: " + ", ".join(ALLOWED_REFERENCE_DOMAINS),
        },
    },
    "required": sorted(REQUIRED_TICKET_KEYS),
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Trusted-field validation
# ---------------------------------------------------------------------------

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
FINDING_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# Asset type and owning team come from the asset inventory and are placed in
# the prompt's trusted block, so they are restricted to label-like values.
LABEL_RE = re.compile(r"^[A-Za-z0-9 _.,&/()'-]{1,64}$")


def validate_record(finding, asset):
    """Check the shape of every field Kevlar treats as trusted.

    Returns a list of problems (empty when the record is well formed). These
    fields feed scoring, file names, and the trusted block of the LLM prompt,
    so a malformed value is refused rather than passed through.
    """
    fid = finding.get("finding_id")
    label = fid if isinstance(fid, str) and FINDING_ID_RE.match(fid) else repr(fid)
    problems = []

    if not (isinstance(fid, str) and FINDING_ID_RE.match(fid)):
        problems.append("finding_id must be 1-64 chars of [A-Za-z0-9._-]")
    cve = finding.get("cve")
    if not (isinstance(cve, str) and CVE_RE.match(cve)):
        problems.append(f"cve {cve!r} is not a CVE identifier")
    cvss = finding.get("cvss")
    if isinstance(cvss, bool) or not isinstance(cvss, (int, float)) or not 0 <= cvss <= 10:
        problems.append(f"cvss {cvss!r} must be a number from 0 to 10")

    if "criticality" in asset:
        crit = asset["criticality"]
        if isinstance(crit, bool) or not isinstance(crit, int) or not 1 <= crit <= 5:
            problems.append(f"asset criticality {crit!r} must be an integer from 1 to 5")
    if "internet_exposed" in asset and not isinstance(asset["internet_exposed"], bool):
        problems.append("asset internet_exposed must be true or false")
    for key in ("type", "owner"):
        if key in asset and not (isinstance(asset[key], str) and LABEL_RE.match(asset[key])):
            problems.append(f"asset {key} must be a short label (1-64 chars, no markup)")

    return [f"{label}: {p}" for p in problems]


# ---------------------------------------------------------------------------
# Input normalization, screening, escaping
# ---------------------------------------------------------------------------

_KEEP_CONTROLS = {"\t", "\n", "\r"}


def normalize_untrusted(value):
    """Fold compatibility characters and drop invisible ones.

    Strips Unicode format characters (zero-width spaces and joiners, bidi
    overrides, soft hyphens, tag characters) and control characters (such as
    terminal escape sequences), then applies NFKC so fullwidth and other
    lookalike forms become their plain equivalents.

    Returns (text, removed_count).
    """
    text = str(value)
    kept = [
        ch for ch in text
        if ch in _KEEP_CONTROLS or unicodedata.category(ch) not in ("Cf", "Cc")
    ]
    removed = len(text) - len(kept)
    return unicodedata.normalize("NFKC", "".join(kept)), removed


def _collapse_ws(text):
    """Fold every run of whitespace down to a single space.

    Two reasons. Screening: "ignore\n  previous   instructions" has to match
    the same pattern as the one-line form. Isolation: untrusted values are
    rendered as "field: value" lines inside the <untrusted_data> fence, so an
    embedded newline lets one field forge another ("nginx/1.0\nhostname:
    evil.example" reads as a hostname line). The fence still marks the whole
    block inert, so this is not the boundary - it just removes the ambiguity.
    """
    return re.sub(r"\s+", " ", text).strip()


def escape_markup(text):
    """Escape &, < and > so untrusted text cannot open or close a tag."""
    return html.escape(text, quote=False)


def screen_finding(finding):
    """Normalize, screen, and escape the untrusted fields of a finding.

    Returns (clean_finding, alerts). Every alert carries an "action":
      quarantined - an injection pattern matched; the field is replaced with a
                    redaction marker and the original kept under _quarantined
      truncated   - the field exceeded MAX_FIELD_CHARS
      normalized  - invisible or control characters were removed
    Every untrusted value in clean_finding is escaped, whether or not it
    raised an alert.
    """
    clean = dict(finding)
    alerts = []
    for field in UNTRUSTED_FIELDS:
        if field not in clean:
            continue
        raw = "" if clean[field] is None else str(clean[field])
        text, removed = normalize_untrusted(raw)
        # Collapsed before screening and before storing, so the value that is
        # screened is exactly the value that reaches the prompt.
        text = _collapse_ws(text)
        hidden_note = f"{removed} invisible/control character(s) removed" if removed else None

        hits = [p.pattern for p in _COMPILED if p.search(text)]
        if hits:
            alerts.append({"field": field, "action": "quarantined",
                           "patterns": hits + ([hidden_note] if hidden_note else []),
                           "original": raw})
            clean.setdefault("_quarantined", {})[field] = raw
            clean[field] = REDACTION_MARKER
            continue

        if hidden_note:
            alerts.append({"field": field, "action": "normalized",
                           "patterns": [hidden_note], "original": raw})
        if len(text) > MAX_FIELD_CHARS:
            alerts.append({"field": field, "action": "truncated",
                           "patterns": ["oversize field"], "original": text[:200] + "..."})
            text = text[:MAX_FIELD_CHARS] + " [TRUNCATED]"
        clean[field] = escape_markup(text)
    return clean, alerts


# ---------------------------------------------------------------------------
# Output validation
# ---------------------------------------------------------------------------

def is_allowed_reference(ref):
    """True only for https URLs whose host is an allowlisted domain or a
    subdomain of one. Parses the URL rather than substring-matching, so
    "https://nvd.nist.gov.attacker.example/" and
    "https://evil.example/?r=cisa.gov" are rejected."""
    if not isinstance(ref, str) or not ref:
        return False
    # Whitespace, backslashes, and control characters cause parser
    # differentials between urllib and browsers; refuse them outright.
    if any(ch.isspace() or ch == "\\" or unicodedata.category(ch).startswith("C") for ch in ref):
        return False
    try:
        u = urlparse(ref)
        port = u.port
    except ValueError:
        return False
    if u.scheme != "https" or u.username is not None or u.password is not None:
        return False
    if port not in (None, 443):
        return False
    host = (u.hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in ALLOWED_REFERENCE_DOMAINS)


_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s<>\"')\]]+", re.IGNORECASE)
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(")
_WORD_RE = re.compile(r"\w+")
LEAK_WINDOW_WORDS = 6


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _canonical_words(text):
    text, _ = normalize_untrusted(text)
    return _WORD_RE.findall(text.casefold())


def find_leaks(ticket, alerts):
    """Return the fields whose quarantined text resurfaces in the ticket.

    Both sides are normalized and reduced to word tokens, then every run of
    LEAK_WINDOW_WORDS consecutive words from the quarantined value is looked
    for in the ticket, so a payload leaked from its middle, re-punctuated, or
    in non-ASCII text is still caught.
    """
    blob = " " + " ".join(_canonical_words(" ".join(_strings(ticket)))) + " "
    leaked = []
    for alert in alerts:
        if alert.get("action") != "quarantined":
            continue
        words = _canonical_words(alert["original"])
        n = LEAK_WINDOW_WORDS
        if len(words) >= n:
            windows = (" ".join(words[i:i + n]) for i in range(len(words) - n + 1))
        else:
            joined = " ".join(words)
            windows = [joined] if len(joined) >= 20 else []
        if any(f" {w} " in blob for w in windows):
            leaked.append(alert["field"])
    return leaked


def _check_prose(name, value, limit, violations):
    if not isinstance(value, str) or not value.strip():
        violations.append(f"{name} must be a non-empty string")
        return
    if len(value) > limit:
        violations.append(f"{name} exceeds {limit} characters")
    if _MD_IMAGE_RE.search(value):
        violations.append(f"{name} contains a markdown image")
    for url in _URL_RE.findall(value):
        if not is_allowed_reference(url):
            violations.append(f"{name} contains a URL outside the allowlist: {url}")


def validate_ticket(raw_text, alerts, stop_reason=None):
    """Enforce the output contract. Returns (ticket_dict, violations).

    stop_reason is the API's stop reason. Structured outputs guarantees the
    schema only when generation ends normally; a refusal or a max_tokens cut
    can yield non-conforming text, so anything other than end_turn is
    rejected.
    """
    if stop_reason is not None and stop_reason != "end_turn":
        return None, [f"LLM response ended early (stop_reason={stop_reason})"]

    try:
        ticket = json.loads(raw_text)
    except (TypeError, json.JSONDecodeError):
        return None, ["output is not valid JSON"]
    if not isinstance(ticket, dict):
        return None, ["output is not a JSON object"]

    violations = []
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
        if key in ticket:
            _check_prose(key, ticket[key], MAX_PROSE_CHARS, violations)

    steps = ticket.get("remediation_steps")
    if not isinstance(steps, list) or not steps:
        violations.append("remediation_steps must be a non-empty list")
    else:
        if len(steps) > MAX_STEPS:
            violations.append(f"remediation_steps has more than {MAX_STEPS} items")
        for i, step in enumerate(steps, 1):
            _check_prose(f"remediation_steps[{i}]", step, MAX_STEP_CHARS, violations)

    refs = ticket.get("references", [])
    if not isinstance(refs, list):
        violations.append("references must be a list")
    else:
        if len(refs) > MAX_REFERENCES:
            violations.append(f"references has more than {MAX_REFERENCES} items")
        for ref in refs:
            if not is_allowed_reference(ref):
                violations.append(f"reference outside allowlist: {ref!r}")

    for field in find_leaks(ticket, alerts):
        violations.append(f"quarantined content leaked into output (field: {field})")

    return (ticket if not violations else None), violations
