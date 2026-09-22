"""Scoring is the authority boundary: these numbers are never model output."""

import pytest

from kevlar import score

LOW_ASSET = {"criticality": 1, "internet_exposed": False}
HIGH_ASSET = {"criticality": 5, "internet_exposed": True}


def finding(cvss=7.0, epss=0.1, kev=False):
    return {"cvss": cvss, "epss": epss, "kev": kev}


def test_score_is_capped_at_100():
    verdict = score.score_finding(finding(cvss=10.0, epss=1.0, kev=True), HIGH_ASSET)
    assert verdict["risk_score"] == 100.0


def test_criticality_and_exposure_raise_the_score():
    low = score.score_finding(finding(), LOW_ASSET)["risk_score"]
    high = score.score_finding(finding(), HIGH_ASSET)["risk_score"]
    assert high > low


def test_kev_on_a_critical_asset_floors_at_p1():
    # Score alone would land well below P1; policy overrides the arithmetic.
    verdict = score.score_finding(finding(cvss=3.0, epss=0.01, kev=True),
                                  {"criticality": 4, "internet_exposed": False})
    assert verdict["risk_score"] < 85 and verdict["priority"] == "P1"


def test_any_kev_finding_floors_at_p2():
    verdict = score.score_finding(finding(cvss=2.0, epss=0.0, kev=True), LOW_ASSET)
    assert verdict["priority"] == "P2"


def test_low_risk_non_kev_finding_stays_p4():
    verdict = score.score_finding(finding(cvss=2.0, epss=0.0), LOW_ASSET)
    assert verdict["priority"] == "P4"


@pytest.mark.parametrize("priority,days", [("P1", 7), ("P2", 30), ("P3", 90), ("P4", 180)])
def test_sla_matches_priority(priority, days):
    assert score.SLA_DAYS[priority] == days


def test_rationale_explains_the_inputs():
    verdict = score.score_finding(finding(cvss=9.8, epss=0.5, kev=True), HIGH_ASSET)
    assert "CVSS 9.8" in verdict["rationale"]
    assert "CISA KEV" in verdict["rationale"]
    assert "internet exposed" in verdict["rationale"]


def test_missing_criticality_defaults_to_mid():
    assert (score.score_finding(finding(), {})["risk_score"]
            == score.score_finding(finding(), {"criticality": 3})["risk_score"])
