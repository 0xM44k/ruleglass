from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyze import SEV, analyze
from . import diffrules
from .parse import ParseError, parse
from .trace import Packet, trace


def read_input(path):
    if path == "-":
        return sys.stdin.read()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as e:
        raise ParseError(f"{path}: {e.strerror}") from e


SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(findings, path):
    rules, seen, results = [], set(), []
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            rules.append({"id": f["id"], "name": f["title"], "shortDescription": {"text": f["title"]},
                          "fullDescription": {"text": f["detail"]},
                          "defaultConfiguration": {"level": SARIF_LEVEL.get(f["severity"], "note")}})
        loc = {"physicalLocation": {"artifactLocation": {"uri": path}}}
        if f["line"]:
            loc["physicalLocation"]["region"] = {"startLine": f["line"]}
        results.append({"ruleId": f["id"], "level": SARIF_LEVEL.get(f["severity"], "note"),
                        "message": {"text": f"{f['title']} ({f['chain'] or 'no chain'}). {f['detail']}"},
                        "locations": [loc]})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "ruleglass", "version": __version__, "rules": rules}},
                                "results": results}]}, indent=2)


def cmd_analyze(a):
    parsed = parse(read_input(a.file))
    findings = analyze(parsed)
    if a.format == "json":
        print(json.dumps({"findings": findings}, indent=2))
    elif a.format == "sarif":
        print(to_sarif(findings, a.file))
    else:
        if not findings:
            print("No findings. This is not a guarantee: only the checks in the README were run.")
        for f in findings:
            where = f" line {f['line']}" if f["line"] else ""
            print(f"{f['severity'].upper():<6} {f['id']} [{f['chain'] or '-'}{where}] {f['title']}\n       {f['detail']}")
    worst = min((SEV[f["severity"]] for f in findings if f["id"] != "RG000"), default=9)
    return 1 if a.fail_on != "never" and worst <= SEV[a.fail_on] else 0


def cmd_trace(a):
    parsed = parse(read_input(a.file))
    pkt = Packet(a.proto, a.src, a.dst, a.sport, a.dport, a.iif, a.oif, a.state)
    res = trace(parsed, a.chain, pkt)
    if a.format == "json":
        print(json.dumps(res, indent=2))
        return 0
    v = res["verdict"]
    if v == "UNCERTAIN":
        print(f"UNCERTAIN: could be {' or '.join(res['possible']) or 'anything'}. It depends on the rules listed below as uncertain: either a packet field you did not give, or a match ruleglass cannot evaluate.")
    else:
        print(f"{v}")
    for n in res["notes"]:
        print("note:", n)
    for o in res["outcomes"]:
        print(f"\nPath to {o['verdict']} ({o['by']}):")
        for s in o["path"]:
            print(f"  [{s['chain']}] line {s['line']}: {s['rule']}   <- {s['match']}")
        if not o["path"]:
            print(f"  (no rule matched; {o['by']})")
        if o["uncertain"]:
            print("  depends on:")
            for u in sorted(set(o["uncertain"])):
                print("    -", u)
    tables = parsed["tables"]
    if any(c["rules"] for t, tb in tables.items() if t != "filter" for c in tb["chains"].values()):
        print("\nnote: nat/mangle/raw rules exist and are not simulated; they may change this packet first.")
    return 0


def cmd_diff(a):
    old, new = parse(read_input(a.old)), parse(read_input(a.new))
    states = diffrules.STATES if a.states == "all" else ("NEW",)
    res = diffrules.diff_rulesets(old, new, a.chain, states)
    if a.format == "json":
        print(json.dumps(res, indent=2))
    else:
        sys.stdout.write(diffrules.to_text(res))
    s = res["summary"]
    if a.fail_on == "opened" and s["opened"]:
        return 1
    if a.fail_on == "any" and (s["opened"] or s["closed"] or s["changed"] or s["undetermined"]):
        return 1
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="ruleglass", description="Analyse and trace iptables-save rulesets offline. Reads text only; never runs iptables.")
    p.add_argument("--version", action="version", version=f"ruleglass {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze"); an.add_argument("file", help="iptables-save output file, or - for stdin")
    an.add_argument("--format", choices=["text", "json", "sarif"], default="text"); an.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="never")
    tr = sub.add_parser("trace"); tr.add_argument("file")
    tr.add_argument("--chain", default="INPUT", choices=["INPUT", "FORWARD", "OUTPUT"])
    tr.add_argument("--proto"); tr.add_argument("--src"); tr.add_argument("--dst")
    tr.add_argument("--sport", type=int); tr.add_argument("--dport", type=int)
    tr.add_argument("--in", dest="iif"); tr.add_argument("--out", dest="oif"); tr.add_argument("--state", default="NEW", choices=["NEW", "ESTABLISHED", "RELATED", "INVALID"])
    tr.add_argument("--format", choices=["text", "json"], default="text")
    df = sub.add_parser("diff", help="what does the new ruleset newly allow or block compared with the old one?")
    df.add_argument("old"); df.add_argument("new")
    df.add_argument("--chain", default="INPUT", choices=["INPUT", "FORWARD", "OUTPUT"])
    df.add_argument("--states", choices=["new", "all"], default="new", help="connection states to probe (default NEW only; used only when a rule matches on state)")
    df.add_argument("--format", choices=["text", "json"], default="text")
    df.add_argument("--fail-on", choices=["opened", "any", "never"], default="never", help="exit 1 when the new ruleset newly allows something (opened) or changes anything (any)")
    a = p.parse_args(argv)
    try:
        return {"analyze": cmd_analyze, "trace": cmd_trace, "diff": cmd_diff}[a.cmd](a)
    except (ParseError, ValueError) as e:
        print(f"ruleglass: {e}", file=sys.stderr)
        return 2
