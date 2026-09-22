"""Enrichment: cache reads and batched EPSS lookups."""

import json
import sys
import types

from kevlar import enrich


def test_enrich_attaches_cached_values(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "EPSS_CACHE", tmp_path / "epss.json")
    monkeypatch.setattr(enrich, "KEV_CACHE", tmp_path / "kev.json")
    (tmp_path / "epss.json").write_text(json.dumps({"CVE-2021-44228": 0.97}))
    (tmp_path / "kev.json").write_text(json.dumps({"cves": ["CVE-2021-44228"]}))

    findings = enrich.enrich([{"cve": "CVE-2021-44228"}, {"cve": "CVE-2030-0001"}])
    assert findings[0]["epss"] == 0.97 and findings[0]["kev"] is True
    assert findings[1]["epss"] == 0.0 and findings[1]["kev"] is False


def test_missing_caches_degrade_to_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "EPSS_CACHE", tmp_path / "absent.json")
    monkeypatch.setattr(enrich, "KEV_CACHE", tmp_path / "absent-too.json")
    findings = enrich.enrich([{"cve": "CVE-2021-44228"}])
    assert findings[0]["epss"] == 0.0 and findings[0]["kev"] is False


def test_batches_chunk_evenly():
    assert list(enrich._batches(list(range(5)), 2)) == [[0, 1], [2, 3], [4]]
    assert list(enrich._batches([], 10)) == []


def test_refresh_splits_epss_into_batched_requests(tmp_path, monkeypatch):
    """A real scan export is thousands of CVEs; one URL cannot carry them."""
    monkeypatch.setattr(enrich, "EPSS_CACHE", tmp_path / "epss.json")
    monkeypatch.setattr(enrich, "KEV_CACHE", tmp_path / "kev.json")
    monkeypatch.setattr(enrich, "EPSS_BATCH_SIZE", 50)

    calls = []

    class _Response:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self._payload

    def fake_get(url, params=None, timeout=None):
        calls.append((url, params))
        if url == enrich.EPSS_URL:
            cves = params["cve"].split(",")
            return _Response({"data": [{"cve": c, "epss": "0.5"} for c in cves]})
        return _Response({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})

    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=fake_get))

    cves = [f"CVE-2026-{i:04d}" for i in range(120)]
    enrich.refresh_caches(cves)

    epss_calls = [c for c in calls if c[0] == enrich.EPSS_URL]
    assert len(epss_calls) == 3  # 120 CVEs / 50 per request
    assert all(len(params["cve"].split(",")) <= 50 for _, params in epss_calls)
    assert len(json.loads((tmp_path / "epss.json").read_text())) == 120
    assert json.loads((tmp_path / "kev.json").read_text())["cves"] == ["CVE-2021-44228"]


def test_refresh_skips_synthetic_cve_ids(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "EPSS_CACHE", tmp_path / "epss.json")
    monkeypatch.setattr(enrich, "KEV_CACHE", tmp_path / "kev.json")
    requested = []

    class _Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [], "vulnerabilities": []}

    def fake_get(url, params=None, timeout=None):
        if url == enrich.EPSS_URL:
            requested.extend(params["cve"].split(","))
        return _Response()

    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=fake_get))
    enrich.refresh_caches(["CVE-2021-44228", "_INTERNAL-001"])
    assert requested == ["CVE-2021-44228"]
