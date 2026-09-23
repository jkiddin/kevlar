import json
from types import SimpleNamespace


def ticket_json(**overrides):
    ticket = {
        "summary": "MOVEit Transfer on the DMZ web server is vulnerable to SQL injection.",
        "business_impact": "Attackers could steal files exchanged with partners.",
        "remediation_steps": ["Apply the vendor patch", "Review access logs", "Rescan the host"],
        "owner_hint": "AppDev",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-34362"],
    }
    ticket.update(overrides)
    return json.dumps(ticket)


class FakeClient:
    """Stands in for anthropic.Anthropic(); records every messages.create call."""

    def __init__(self, text=None, stop_reason="end_turn", exc=None):
        self.text = ticket_json() if text is None else text
        self.stop_reason = stop_reason
        self.exc = exc
        self.calls = []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.text)],
                               stop_reason=self.stop_reason)
