"""
Usage:
    python -m kevlar.cli                      # offline demo, template tickets
    python -m kevlar.cli --llm                # Claude-drafted tickets (needs a credential)
    python -m kevlar.cli --llm --model ...    # override the drafting model
    python -m kevlar.cli --refresh            # pull live EPSS + KEV before running
"""

import argparse
import json
import pathlib
import sys

from . import enrich, guardrails, score, triage

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "out"

PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

def run(findings_path, assets_path, use_llm=False, refresh=False, model=None):
    findings = json.loads(pathlib.Path(findings_path).read_text())
    assets = {a["asset_id"]: a for a in json.loads(pathlib.Path(assets_path).read_text())}

    findings = enrich.enrich(findings, refresh=refresh)

    results = []
    for f in findings:
        asset = assets.get(f["asset_id"], {})
        verdict = score.score_finding(f, asset)
        ticket, alerts, violations = triage.draft_ticket(f, asset, use_llm=use_llm, model=model)
        results.append({"finding": f, "asset": asset, "verdict": verdict,
                        "ticket": ticket, "alerts": alerts, "violations": violations})

    results.sort(key=lambda r: (PRIORITY_ORDER[r["verdict"]["priority"]], -r["verdict"]["risk_score"]))
    OUT.mkdir(exist_ok=True)
    _write_tickets(results)
    _write_report(results, use_llm, model)
    _print_summary(results)
    return results

def _quarantined_fields(r):
    return [a["field"] for a in r["alerts"] if a.get("quarantined")]

def _flag(r):
    if _quarantined_fields(r):
        return "QUARANTINED"
    return "flagged" if r["alerts"] else "-"

def _hostname(r):
    # Hostnames are attacker-controllable; a quarantined one must not resurface
    # in rendered output. Fall back to the asset_id so the analyst can still
    # identify the machine. A hostname that was only sanitized (markup escaped)
    # is still shown - it was never withheld from the model either.
    if "hostname" in _quarantined_fields(r):
        return f"{r['asset'].get('asset_id', '?')} [hostname redacted]"
    # Escaped on the way out: a hostname that carried markup but tripped no
    # pattern is still attacker-controlled text in an analyst-facing file.
    return guardrails.neutralize_markup(r["asset"].get("hostname", "?"))

def _write_tickets(results):
    for r in results:
        f, v, t = r["finding"], r["verdict"], r["ticket"]
        lines = [
            f"# [{v['priority']}] {f['cve']} on {_hostname(r)}",
            "",
            f"**Risk score:** {v['risk_score']}/100 | **SLA:** {v['sla_days']} days | **Owner:** {t['owner_hint']}",
            f"**Scoring rationale:** {v['rationale']}",
            "",
        ]
        if r["alerts"]:
            quarantined = _quarantined_fields(r)
            headline = ("SECURITY ALERT: suspected prompt injection in scanner data."
                        if quarantined else
                        "NOTICE: scanner data was sanitized before LLM processing.")
            lines += [f"> **{headline}**",
                      "> " + ("Affected fields were quarantined before LLM processing. Investigate the source host."
                              if quarantined else
                              "No instruction-like content matched, but the fields below were altered on the way in."),
                      ">"]
            for a in r["alerts"]:
                state = "quarantined" if a.get("quarantined") else "sanitized"
                lines.append(f"> - `{a['field']}` ({state}): {', '.join(a['patterns'][:3])}")
            lines.append("")
        lines += ["## Summary", t["summary"], "", "## Business impact", t["business_impact"],
                  "", "## Remediation steps"]
        lines += [f"{i}. {s}" for i, s in enumerate(t["remediation_steps"], 1)]
        lines += ["", "## References"] + [f"- {ref}" for ref in t["references"]]
        if r["violations"]:
            lines += ["", "## Pipeline notes"] + [f"- {v_}" for v_ in r["violations"]]
        (OUT / f"{f['finding_id']}_{v['priority']}.md").write_text("\n".join(lines))

def _write_report(results, use_llm, model=None):
    mode = f"LLM-drafted ({model or triage.DEFAULT_MODEL})" if use_llm else "template"
    lines = ["# Kevlar triage report", "",
             f"Mode: {mode} tickets | Findings: {len(results)}", "",
             "| Priority | Score | CVE | Asset | KEV | EPSS | Screen |",
             "|---|---|---|---|---|---|---|"]
    for r in results:
        f, v = r["finding"], r["verdict"]
        lines.append(
            f"| {v['priority']} | {v['risk_score']} | {f['cve']} | "
            f"{_hostname(r)} | {'Y' if f['kev'] else 'N'} | "
            f"{f['epss']:.0%} | {_flag(r)} |")
    (OUT / "triage_report.md").write_text("\n".join(lines))

def _print_summary(results):
    print(f"\n{'PRI':<4} {'SCORE':<6} {'CVE':<16} {'ASSET':<20} {'SCREEN'}")
    print("-" * 70)
    for r in results:
        print(f"{r['verdict']['priority']:<4} {r['verdict']['risk_score']:<6} "
              f"{r['finding']['cve']:<16} {_hostname(r):<20} {_flag(r)}")
    print(f"\nTickets written to {OUT}/")

def main():
    ap = argparse.ArgumentParser(description="Kevlar: guarded AI-assisted vulnerability triage")
    ap.add_argument("--findings", default=str(ROOT / "data" / "2_findings.json"))
    ap.add_argument("--assets", default=str(ROOT / "data" / "2_assets.json"))
    ap.add_argument("--llm", action="store_true", help="draft tickets with Claude (needs an Anthropic credential)")
    ap.add_argument("--model", default=None,
                    help=f"drafting model (default: {triage.DEFAULT_MODEL}, or $KEVLAR_MODEL)")
    ap.add_argument("--refresh", action="store_true", help="pull live EPSS/KEV data first")
    args = ap.parse_args()
    try:
        run(args.findings, args.assets, use_llm=args.llm, refresh=args.refresh, model=args.model)
    except triage.LLMUnavailable as exc:
        # Never degrade to template tickets while still reporting an LLM run.
        sys.exit(f"error: --llm requested but no usable Anthropic credential: {exc}")

if __name__ == "__main__":
    main()
