import copy

import pytest

from kevlar import enrich
from redteam.run_injection_tests import BASE_ASSET, BASE_FINDING


@pytest.fixture
def finding():
    return enrich.enrich([copy.deepcopy(BASE_FINDING)])[0]


@pytest.fixture
def asset():
    return copy.deepcopy(BASE_ASSET)


@pytest.fixture(autouse=True)
def no_real_credentials(monkeypatch, tmp_path):
    # Tests never talk to the real API; LLM paths use FakeClient. Point the
    # SDK's config dir somewhere empty as well, or llm_available() would find
    # a developer's `ant auth login` profile and the suite would stop being
    # hermetic on their machine.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("KEVLAR_MODEL", raising=False)
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path / "no-anthropic-config"))
