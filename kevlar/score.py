"""
Deterministic risk scoring.

Priority is computed from CVSS, EPSS, KEV membership, asset criticality, and
internet exposure. Weights are deliberately simple and documented so an analyst
can defend every number in a remediation meeting.

    base   = CVSS x 6              (0-60)
    epss   = EPSS probability x 25 (0-25)   exploitation likelihood
    kev    = +15 if in CISA KEV             confirmed exploitation in the wild
    ------------------------------------------------
    raw    = 0-100
    context multiplier = 0.6 + 0.1 x asset criticality (1-5)  -> 0.7 - 1.1
    exposure multiplier = 1.15 if internet exposed
    score  = min(100, raw x multipliers)

Floors (non-negotiable, encode policy not math):
    - KEV finding on a criticality >= 4 asset          -> at least P1
    - Any KEV finding                                  -> at least P2
"""

PRIORITY_THRESHOLDS = [(85, "P1"), (60, "P2"), (35, "P3"), (0, "P4")]

SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}

def score_finding(finding, asset):
    raw = finding["cvss"] * 6 + finding["epss"] * 25 + (15 if finding["kev"] else 0)
    multiplier = 0.6 + 0.1 * asset.get("criticality", 3)
    if asset.get("internet_exposed"):
        multiplier *= 1.15
    value = min(100.0, raw * multiplier)

    priority = next(p for threshold, p in PRIORITY_THRESHOLDS if value >= threshold)

    # Policy floors
    if finding["kev"]:
        if asset.get("criticality", 3) >= 4 and priority != "P1":
            priority = "P1"
        elif priority in ("P3", "P4"):
            priority = "P2"

    return {
        "risk_score": round(value, 1),
        "priority": priority,
        "sla_days": SLA_DAYS[priority],
        "rationale": _rationale(finding, asset),
    }

def _rationale(finding, asset):
    parts = [f"CVSS {finding['cvss']}", f"EPSS {finding['epss']:.1%}"]
    if finding["kev"]:
        parts.append("listed in CISA KEV (known exploited)")
    parts.append(f"asset criticality {asset.get('criticality', 3)}/5")
    if asset.get("internet_exposed"):
        parts.append("internet exposed")
    return "; ".join(parts)