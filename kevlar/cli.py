"""
Usage:
    python -m kevlar.cli                      # offline demo, template tickets
    python -m kevlar.cli --llm                # Claude-drafted tickets (needs ANTHROPIC_API_KEY)
    python -m kevlar.cli --refresh            # pull live EPSS + KEV before running
"""

import argparse
import json
import pathlib

from . import enrich, score, triage

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "out"

PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

def run(findings_path, assets_path, use_llm=False, refresh=False):
    findings = json.loads(pathlib.Path(findings_path).read_text())
    assets = {a["asset_id"]: a for a in json.loads(pathlib.Path(assets_path).read_text())}

    findings = enrich.enrich(findings, refresh=refresh)

    results = []
    for f in findings:
        asset = assets.get(f["asset_id"], {})
        verdict = score.score_finding(f, asset)
        ticket, alerts, violations = triage.draft_ticket(f, asset, use_llm=use_llm)
        results.append({"finding": f, "asset": asset, "verdict": verdict,
                        "ticket": ticket, "alerts": alerts, "violations": violations})

    results.sort(key=lambda r: (PRIORITY_ORDER[r["verdict"]["priority"]], -r["verdict"]["risk_score"]))
    OUT.mkdir(exist_ok=True)
    _write_tickets(results)
    _write_report(results, use_llm)
    _print_summary(results)
    return results

def _hostname(r):
    # Hostnames are attacker-controllable; a quarantined one must not resurface
    # in rendered output. Fall back to the asset_id so the analyst can still
    # identify the machine.
    if any(a["field"] == "hostname" for a in r["alerts"]):
        return f"{r['asset'].get('asset_id', '?')} [hostname redacted]"
    return r["asset"].get("hostname", "?")

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
            lines += ["> **SECURITY ALERT: suspected prompt injection in scanner data.**",
                      "> Affected fields were quarantined before LLM processing. Investigate the source host.",
                      ""]
            for a in r["alerts"]:
                lines.append(f"> - `{a['field']}` matched: {', '.join(a['patterns'][:3])}")
            lines.append("")
        lines += ["## Summary", t["summary"], "", "## Business impact", t["business_impact"],
                  "", "## Remediation steps"]
        lines += [f"{i}. {s}" for i, s in enumerate(t["remediation_steps"], 1)]
        lines += ["", "## References"] + [f"- {ref}" for ref in t["references"]]
        if r["violations"]:
            lines += ["", "## Pipeline notes"] + [f"- {v_}" for v_ in r["violations"]]
        (OUT / f"{f['finding_id']}_{v['priority']}.md").write_text("\n".join(lines))

def _write_report(results, use_llm):
    lines = ["# Kevlar triage report", "",
             f"Mode: {'LLM-drafted' if use_llm else 'template'} tickets | Findings: {len(results)}", "",
             "| Priority | Score | CVE | Asset | KEV | EPSS | Injection? |",
             "|---|---|---|---|---|---|---|"]
    for r in results:
        f, v = r["finding"], r["verdict"]
        lines.append(
            f"| {v['priority']} | {v['risk_score']} | {f['cve']} | "
            f"{_hostname(r)} | {'Y' if f['kev'] else 'N'} | "
            f"{f['epss']:.0%} | {'FLAGGED' if r['alerts'] else '-'} |")
    (OUT / "triage_report.md").write_text("\n".join(lines))

def _print_summary(results):
    print(f"\n{'PRI':<4} {'SCORE':<6} {'CVE':<16} {'ASSET':<20} {'FLAGS'}")
    print("-" * 70)
    for r in results:
        flags = "INJECTION-FLAGGED" if r["alerts"] else ""
        print(f"{r['verdict']['priority']:<4} {r['verdict']['risk_score']:<6} "
              f"{r['finding']['cve']:<16} {_hostname(r):<20} {flags}")
    print(f"\nTickets written to {OUT}/")

def main():
    ap = argparse.ArgumentParser(description="Kevlar: guarded AI-assisted vulnerability triage")
    ap.add_argument("--findings", default=str(ROOT / "data" / "2_findings.json"))
    ap.add_argument("--assets", default=str(ROOT / "data" / "2_assets.json"))
    ap.add_argument("--llm", action="store_true", help="draft tickets with Claude (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--refresh", action="store_true", help="pull live EPSS/KEV data first")
    args = ap.parse_args()
    run(args.findings, args.assets, use_llm=args.llm, refresh=args.refresh)

if __name__ == "__main__":
    main()