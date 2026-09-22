"""End-to-end runs over the bundled sample data."""

import pathlib

from kevlar import cli

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

POISONED_BANNER_FRAGMENT = "ignore previous instructions"


def _run(dataset, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "OUT", tmp_path)
    return cli.run(DATA / f"{dataset}_findings.json", DATA / f"{dataset}_assets.json")


def test_poisoned_finding_keeps_its_computed_priority(tmp_path, monkeypatch):
    results = _run(2, tmp_path, monkeypatch)
    poisoned = next(r for r in results if r["finding"]["finding_id"] == "F-1006")
    assert poisoned["verdict"]["priority"] == "P1"
    assert [a["field"] for a in poisoned["alerts"]] == ["banner"]
    assert poisoned["alerts"][0]["quarantined"]


def test_no_payload_text_reaches_any_rendered_file(tmp_path, monkeypatch):
    _run(2, tmp_path, monkeypatch)
    for path in tmp_path.glob("*.md"):
        assert POISONED_BANNER_FRAGMENT not in path.read_text().lower()


def test_report_and_tickets_are_written(tmp_path, monkeypatch):
    results = _run(2, tmp_path, monkeypatch)
    report = (tmp_path / "triage_report.md").read_text()
    assert report.startswith("# Kevlar triage report")
    assert "Mode: template tickets" in report
    assert len(list(tmp_path.glob("*.md"))) == len(results) + 1


def test_results_are_sorted_by_priority_then_score(tmp_path, monkeypatch):
    results = _run(2, tmp_path, monkeypatch)
    keys = [(cli.PRIORITY_ORDER[r["verdict"]["priority"]], -r["verdict"]["risk_score"])
            for r in results]
    assert keys == sorted(keys)


def test_quarantined_hostname_is_redacted_everywhere(tmp_path, monkeypatch):
    results = _run(1, tmp_path, monkeypatch)
    flagged = next(r for r in results if r["asset"].get("asset_id") == "SRV-200")
    assert cli._hostname(flagged) == "SRV-200 [hostname redacted]"
    for path in tmp_path.glob("*.md"):
        assert "NOTICE TO AI REVIEWER" not in path.read_text()


def test_clean_hostname_is_shown_as_is(tmp_path, monkeypatch):
    results = _run(1, tmp_path, monkeypatch)
    clean = next(r for r in results if r["asset"].get("asset_id") != "SRV-200")
    assert "[hostname redacted]" not in cli._hostname(clean)


def test_rendered_hostname_is_escaped(tmp_path, monkeypatch):
    # A hostname carrying markup trips no injection pattern, so it is shown -
    # but it must not reach an analyst-facing file as live markup.
    results = _run(1, tmp_path, monkeypatch)
    hostile = dict(results[0]["asset"], hostname="web-01<img src=x onerror=alert(1)>")
    assert cli._hostname({"asset": hostile, "alerts": []}) == (
        "web-01&lt;img src=x onerror=alert(1)&gt;")
