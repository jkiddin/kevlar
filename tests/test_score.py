import pytest

from kevlar import score


def f(cvss=5.0, epss=0.0, kev=False):
    return {"cvss": cvss, "epss": epss, "kev": kev}


def a(criticality=3, exposed=False):
    return {"criticality": criticality, "internet_exposed": exposed}


def test_formula_matches_documented_weights():
    # (7.0*6 + 0.4*25) * (0.6 + 0.1*3) = 52 * 0.9 = 46.8
    assert score.score_finding(f(7.0, 0.4), a(3))["risk_score"] == 46.8


def test_exposure_multiplier():
    closed = score.score_finding(f(7.0, 0.4), a(3, exposed=False))["risk_score"]
    exposed = score.score_finding(f(7.0, 0.4), a(3, exposed=True))["risk_score"]
    assert exposed == pytest.approx(closed * 1.15, abs=0.1)


def test_score_is_capped_at_100():
    assert score.score_finding(f(10.0, 1.0, kev=True), a(5, exposed=True))["risk_score"] == 100.0


@pytest.mark.parametrize("finding,asset,priority,sla", [
    (f(5.0, 0.0), a(3), "P4", 180),    # 30.0 * 0.9 = 27.0
    (f(7.0, 0.4), a(3), "P3", 90),     # 52.0 * 0.9 = 46.8
    (f(9.0, 0.5), a(4), "P2", 30),     # 66.5 * 1.0 = 66.5
    (f(10.0, 1.0), a(5), "P1", 7),     # 85.0 * 1.1 = 93.5
])
def test_thresholds_and_slas(finding, asset, priority, sla):
    verdict = score.score_finding(finding, asset)
    assert (verdict["priority"], verdict["sla_days"]) == (priority, sla)


def test_kev_floor_lifts_low_score_to_p2():
    verdict = score.score_finding(f(4.0, 0.0, kev=True), a(1))
    assert verdict["risk_score"] < 35
    assert verdict["priority"] == "P2"


def test_kev_on_critical_asset_is_p1():
    verdict = score.score_finding(f(4.0, 0.0, kev=True), a(4))
    assert verdict["risk_score"] < 60
    assert verdict["priority"] == "P1"
    assert verdict["sla_days"] == 7


def test_rationale_names_every_input():
    text = score.score_finding(f(9.8, 0.969, kev=True), a(4, exposed=True))["rationale"]
    for part in ("CVSS 9.8", "EPSS 96.9%", "CISA KEV", "criticality 4/5", "internet exposed"):
        assert part in text
