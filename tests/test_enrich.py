import json
from types import SimpleNamespace

import pytest

from kevlar import enrich


def test_cached_values_are_attached():
    [f] = enrich.enrich([{"cve": "CVE-2021-44228"}])
    assert f["epss"] == pytest.approx(0.976) and f["kev"] is True


def test_unknown_cve_defaults():
    [f] = enrich.enrich([{"cve": "CVE-1999-0001"}])
    assert f["epss"] == 0.0 and f["kev"] is False


def test_refresh_batches_epss_requests(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "EPSS_CACHE", tmp_path / "epss.json")
    monkeypatch.setattr(enrich, "KEV_CACHE", tmp_path / "kev.json")
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append((url, params))
        if url == enrich.EPSS_URL:
            data = [{"cve": c, "epss": "0.5"} for c in params["cve"].split(",")]
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"data": data})
        vulns = [{"cveID": "CVE-2024-0001"}, {"cveID": "CVE-2024-0002"}]
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"vulnerabilities": vulns})

    monkeypatch.setattr("requests.get", fake_get)
    cves = [f"CVE-2024-{i:04d}" for i in range(1, 251)] + ["CVE-2024-0001"]  # 250 unique + a duplicate
    enrich.refresh_caches(cves)

    epss_calls = [p for u, p in calls if u == enrich.EPSS_URL]
    sizes = [len(p["cve"].split(",")) for p in epss_calls]
    assert sizes == [100, 100, 50]
    assert [p["limit"] for p in epss_calls] == sizes
    assert len(json.loads((tmp_path / "epss.json").read_text())) == 250
    assert json.loads((tmp_path / "kev.json").read_text())["cves"] == ["CVE-2024-0001", "CVE-2024-0002"]
