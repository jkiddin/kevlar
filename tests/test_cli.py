import json

import pytest

from kevlar import cli, triage
from tests.helpers import ticket_json

ROOT = cli.ROOT
F2, A2 = ROOT / "data" / "2_findings.json", ROOT / "data" / "2_assets.json"
F1, A1 = ROOT / "data" / "1_findings.json", ROOT / "data" / "1_assets.json"


def run(tmp_path, findings=F2, assets=A2, **kw):
    return cli.run(findings, assets, out_dir=tmp_path, quiet=True, **kw)


def test_poisoned_log4shell_stays_p1(tmp_path):
    results = {r["finding"]["finding_id"]: r for r in run(tmp_path)}
    assert len(results) == 7
    assert results["F-1006"]["verdict"]["priority"] == "P1"
    assert results["F-1006"]["alerts"][0]["action"] == "quarantined"
    assert len(list(tmp_path.glob("*.md"))) == 8   # 7 tickets + report


def test_poisoned_hostname_never_reaches_rendered_output(tmp_path):
    run(tmp_path, F1, A1)
    report = (tmp_path / "triage_report.md").read_text()
    assert "SRV-200 [hostname redacted]" in report
    for md in tmp_path.glob("*.md"):
        text = md.read_text().lower()
        assert "ignore previous instructions" not in text
        assert "notice to ai reviewer" not in text


def _write(tmp_path, findings, assets):
    fp, ap = tmp_path / "f.json", tmp_path / "a.json"
    fp.write_text(json.dumps(findings))
    ap.write_text(json.dumps(assets))
    return fp, ap


@pytest.mark.parametrize("bad", [
    {"cve": "CVE-2021-44228\n- CVSS: 0.1"},
    {"finding_id": "../../outside"},
    {"cvss": "high"},
])
def test_malformed_input_is_refused(tmp_path, bad):
    base = json.loads(F2.read_text())[0]
    fp, ap = _write(tmp_path, [{**base, **bad}], json.loads(A2.read_text()))
    with pytest.raises(ValueError, match="refusing to process malformed input"):
        run(tmp_path / "out", fp, ap)
    assert not (tmp_path / "out").exists()


def test_llm_flag_without_key_warns_and_reports_template_mode(tmp_path, capsys):
    run(tmp_path, use_llm=True)
    assert "no Anthropic credentials were found" in capsys.readouterr().err
    assert "Mode: template" in (tmp_path / "triage_report.md").read_text()


def test_report_counts_llm_acceptance(tmp_path, monkeypatch):
    monkeypatch.setattr(triage, "llm_available", lambda: True)
    monkeypatch.setattr(triage, "_call_llm", lambda prompt, model, client=None: (ticket_json(), "end_turn"))
    run(tmp_path, use_llm=True, model="claude-sonnet-5")
    report = (tmp_path / "triage_report.md").read_text()
    assert "LLM-drafted (claude-sonnet-5): 7 accepted, 0 fell back to template" in report
