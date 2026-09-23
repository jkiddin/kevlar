"""
Usage:
    python -m kevlar.cli                      # offline demo, template tickets
    python -m kevlar.cli --llm                # Claude-drafted tickets (needs Anthropic credentials)
    python -m kevlar.cli --llm --model M      # choose the model (or set KEVLAR_MODEL)
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

ACTION_LABELS = {"quarantined": "quarantined", "truncated": "truncated", "normalized": "normalized"}


def run(findings_path, assets_path, use_llm=False, refresh=False, model=None, out_dir=OUT, quiet=False):
    findings = json.loads(pathlib.Path(findings_path).read_text())
    assets = {a["asset_id"]: a for a in json.loads(pathlib.Path(assets_path).read_text())}

    problems = [p for f in findings for p in guardrails.validate_record(f, assets.get(f.get("asset_id"), {}))]
    if problems:
        raise ValueError("refusing to process malformed input:\n  " + "\n  ".join(problems))

    if use_llm and not triage.llm_available():
        print("[kevlar] --llm requested but no Anthropic credentials were found; using template tickets.",
              file=sys.stderr)
        use_llm = False

    findings = enrich.enrich(findings, refresh=refresh)

    results = []
    for f in findings:
        asset = assets.get(f["asset_id"], {})
        verdict = score.score_finding(f, asset)
        draft = triage.draft_ticket(f, asset, use_llm=use_llm, model=model)
        results.append({"finding": f, "asset": asset, "verdict": verdict, **draft._asdict()})

    results.sort(key=lambda r: (PRIORITY_ORDER[r["verdict"]["priority"]], -r["verdict"]["risk_score"]))
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_tickets(results, out_dir)
    _write_report(results, use_llm, triage.resolve_model(model), out_dir)
    if not quiet:
        _print_summary(results, out_dir)
    return results


def _hostname(r):
    # Hostnames are attacker-controllable; a quarantined one must not resurface
    # in rendered output. Fall back to the asset_id so the analyst can still
    # identify the machine. Otherwise show the screened (normalized, escaped)
    # value, never the raw one.
    if any(a["field"] == "hostname" and a["action"] == "quarantined" for a in r["alerts"]):
        return f"{r['asset'].get('asset_id', '?')} [hostname redacted]"
    return guardrails.safe_echo(r["clean"].get("hostname") or "?")


def _cell(text):
    return str(text).replace("|", "\\|")


def _write_tickets(results, out_dir):
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
            lines += ["> **SECURITY ALERT: suspicious content in scanner-controlled fields.**",
                      "> Quarantined fields were redacted before LLM processing. Investigate the source host.",
                      ""]
            for a in r["alerts"]:
                lines.append(f"> - `{a['field']}` {ACTION_LABELS[a['action']]}: {', '.join(a['patterns'][:3])}")
            lines.append("")
        lines += ["## Summary", t["summary"], "", "## Business impact", t["business_impact"],
                  "", "## Remediation steps"]
        lines += [f"{i}. {s}" for i, s in enumerate(t["remediation_steps"], 1)]
        lines += ["", "## References"] + [f"- {ref}" for ref in t["references"]]
        if r["violations"]:
            lines += ["", "## Pipeline notes"] + [f"- {v_}" for v_ in r["violations"]]
        (out_dir / f"{f['finding_id']}_{v['priority']}.md").write_text("\n".join(lines))


def _write_report(results, use_llm, model, out_dir):
    if use_llm:
        accepted = sum(r["mode"] == "llm" for r in results)
        mode = (f"LLM-drafted ({model}): {accepted} accepted, "
                f"{len(results) - accepted} fell back to template")
    else:
        mode = "template"
    lines = ["# Kevlar triage report", "",
             f"Mode: {mode} | Findings: {len(results)}", "",
             "| Priority | Score | CVE | Asset | KEV | EPSS | Injection? |",
             "|---|---|---|---|---|---|---|"]
    for r in results:
        f, v = r["finding"], r["verdict"]
        lines.append(
            f"| {v['priority']} | {v['risk_score']} | {f['cve']} | "
            f"{_cell(_hostname(r))} | {'Y' if f['kev'] else 'N'} | "
            f"{f['epss']:.0%} | {'FLAGGED' if r['alerts'] else '-'} |")
    (out_dir / "triage_report.md").write_text("\n".join(lines))


def _print_summary(results, out_dir):
    print(f"\n{'PRI':<4} {'SCORE':<6} {'CVE':<16} {'ASSET':<20} {'FLAGS'}")
    print("-" * 70)
    for r in results:
        flags = "INJECTION-FLAGGED" if r["alerts"] else ""
        if r["mode"] == "template-fallback":
            flags = (flags + " LLM-FALLBACK").strip()
        print(f"{r['verdict']['priority']:<4} {r['verdict']['risk_score']:<6} "
              f"{r['finding']['cve']:<16} {_hostname(r):<20} {flags}")
    print(f"\nTickets written to {out_dir}/")


def main():
    ap = argparse.ArgumentParser(description="Kevlar: guarded AI-assisted vulnerability triage")
    ap.add_argument("--findings", default=str(ROOT / "data" / "2_findings.json"))
    ap.add_argument("--assets", default=str(ROOT / "data" / "2_assets.json"))
    ap.add_argument("--out", default=str(OUT), help="directory for tickets and the report (default: out/)")
    ap.add_argument("--llm", action="store_true", help="draft tickets with Claude (needs Anthropic credentials)")
    ap.add_argument("--model", default=None,
                    help=f"Claude model for --llm (default: $KEVLAR_MODEL or {triage.DEFAULT_MODEL})")
    ap.add_argument("--refresh", action="store_true", help="pull live EPSS/KEV data first")
    args = ap.parse_args()
    try:
        run(args.findings, args.assets, use_llm=args.llm, refresh=args.refresh,
            model=args.model, out_dir=args.out)
    except ValueError as exc:
        sys.exit(f"[kevlar] {exc}")


if __name__ == "__main__":
    main()
