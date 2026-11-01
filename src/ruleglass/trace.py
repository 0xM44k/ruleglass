"""Trace a packet through the filter table with three-valued matching."""
from __future__ import annotations

import ipaddress

from .parse import NONTERMINAL, TERMINAL, norm_proto

MAX_STEPS = 20000


class Packet:
    def __init__(self, proto=None, src=None, dst=None, sport=None, dport=None, iif=None, oif=None, state="NEW"):
        self.proto = norm_proto(proto) if proto else None
        self.src = ipaddress.ip_address(src) if src else None
        self.dst = ipaddress.ip_address(dst) if dst else None
        self.sport, self.dport = sport, dport
        self.iif, self.oif, self.state = iif, oif, (state or "NEW").upper()


def _iface(pattern, actual):
    if actual is None:
        return None
    return actual.startswith(pattern[:-1]) if pattern.endswith("+") else actual == pattern


def eval_cond(cond, pkt):
    """True / False / None (cannot tell)."""
    kind, val, neg = cond
    r = None
    if kind == "unknown":
        return None
    if kind == "proto":
        r = True if val == "all" else (None if pkt.proto is None else pkt.proto == val)
    elif kind in ("src", "dst"):
        ip = pkt.src if kind == "src" else pkt.dst
        r = None if ip is None else any(ip.version == n.version and ip in n for n in val)
    elif kind in ("sport", "dport"):
        port = pkt.sport if kind == "sport" else pkt.dport
        if pkt.proto is not None and pkt.proto not in ("tcp", "udp", "sctp"):
            r = False
        else:
            r = None if port is None else any(lo <= port <= hi for lo, hi in val)
    elif kind in ("iif", "oif"):
        r = _iface(val, pkt.iif if kind == "iif" else pkt.oif)
    elif kind == "state":
        r = pkt.state in val
    return r if r is None else (not r if neg else r)


FLAG = {"proto": "--proto", "src": "--src", "dst": "--dst", "sport": "--sport", "dport": "--dport", "iif": "--in", "oif": "--out"}


def why_unknown(rule, pkt):
    out = []
    for c in rule["conds"]:
        if eval_cond(c, pkt) is None:
            out.append(f"cannot evaluate {c[1]}" if c[0] == "unknown" else f"packet field not given: {FLAG.get(c[0], c[0])}")
    return sorted(set(out))


def match_rule(rule, pkt):
    results = [eval_cond(c, pkt) for c in rule["conds"]]
    if any(r is False for r in results):
        return "no"
    return "maybe" if any(r is None for r in results) else "yes"


def trace(parsed, chain, pkt):
    """Returns {"verdict": ..., "outcomes": [...], "notes": [...]}"""
    table = parsed["tables"].get("filter")
    if table is None or chain not in table["chains"]:
        raise ValueError(f"no chain {chain!r} in the filter table")
    chains = table["chains"]
    steps = [0]
    outcomes, truncated = [], [False]

    def walk(name, idx, path, unc, stack):
        rules = chains[name]["rules"]
        for i in range(idx, len(rules)):
            steps[0] += 1
            if steps[0] > MAX_STEPS:
                truncated[0] = True
                return
            r = rules[i]
            m = match_rule(r, pkt)
            if m == "no":
                continue
            step = {"chain": name, "line": r["line"], "rule": r["raw"], "match": m}
            if m == "maybe":
                yield from walk(name, i + 1, path + [dict(step, match="treated as not matching")], unc + [f"{r['raw']}  [{'; '.join(why_unknown(r, pkt))}]"], stack)
                unc = unc + [f"{r['raw']}  [{'; '.join(why_unknown(r, pkt))}]"]
            tgt = r["target"]
            path = path + [step]
            if tgt in TERMINAL:
                yield (tgt, path, unc)
                return
            if tgt == "RETURN":
                yield ("END", path, unc)
                return
            if tgt in NONTERMINAL or tgt == "":
                continue
            if tgt in chains:
                if tgt in stack or tgt == name:
                    yield ("LOOP", path, unc)
                    return
                if r["goto"]:
                    yield from walk(tgt, 0, path, unc, stack + [name])   # END here ends this chain too
                    return
                for out in walk(tgt, 0, path, unc, stack + [name]):
                    if out[0] == "END":
                        yield from walk(name, i + 1, out[1], out[2], stack)
                    else:
                        yield out
                return
            yield ("UNKNOWN:" + tgt, path, unc)
            return
        yield ("END", path, unc)

    for status, path, unc in walk(chain, 0, [], [], []):
        if status == "END":
            pol = chains[chain]["policy"] or "ACCEPT"
            outcomes.append({"verdict": pol, "by": f"policy of {chain}", "path": path, "uncertain": unc})
        else:
            outcomes.append({"verdict": status, "by": "rule", "path": path, "uncertain": unc})
    notes = []
    if truncated[0]:
        notes.append("Stopped after too many uncertain branches; the verdict is not reliable.")
        return {"verdict": "UNCERTAIN", "possible": [], "outcomes": outcomes[:5], "notes": notes}
    verdicts = sorted({o["verdict"] for o in outcomes})
    if len(verdicts) == 1 and not verdicts[0].startswith(("UNKNOWN", "LOOP")):
        return {"verdict": verdicts[0], "possible": verdicts, "outcomes": _dedupe(outcomes)[:3], "notes": notes}
    return {"verdict": "UNCERTAIN", "possible": verdicts, "outcomes": _dedupe(outcomes)[:6], "notes": notes}


def _dedupe(outcomes):
    seen, out = set(), []
    for o in outcomes:
        k = (o["verdict"], tuple(s["line"] for s in o["path"]))
        if k not in seen:
            seen.add(k)
            out.append(o)
    return out
