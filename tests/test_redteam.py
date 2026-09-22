"""The injection suite is part of the test run, not just a manual demo."""

from redteam import run_injection_tests


def test_every_payload_is_contained_in_template_mode(capsys):
    assert run_injection_tests.run(use_llm=False) is True
    out = capsys.readouterr().out
    assert "payloads fully contained" in out


def test_payload_file_declares_detection_expectations():
    import json

    payloads = json.loads(run_injection_tests.PAYLOADS.read_text())
    assert len(payloads) >= 13
    assert all({"name", "field", "payload", "detection_expected", "canary"} <= set(p)
               for p in payloads)
    # The canary is the instruction clause, not the whole payload: a benign
    # banner prefix may legitimately be quoted back by the model.
    assert all(p["canary"] is None
               or p["canary"].replace("\u200b", "") in p["payload"].replace("\u200b", "")
               for p in payloads)
    # The suite is only honest if it includes attacks the screen cannot see.
    assert any(p["detection_expected"] is False for p in payloads)
