"""Compare two rulesets by what they do to representative packets.

The question answered is "what would this change newly allow or block?". Both
rulesets are traced with the existing three-valued tracer over a set of probe
packets built from the values the rulesets themselves mention.

Why a finite probe set is enough for the fields it varies: a rule matches a
port by range and an address by network, so the verdict only changes at range
and network boundaries. Probes are placed at the start of every cell those
boundaries create (each range's low end, the port after each range's high end,
each network's first and one-past-last address) plus one address that matches no
network. This is exhaustive for ports, addresses and interface names as the
rules express them, and says nothing about fields the rules do not mention or
matches ruleglass cannot evaluate (those yield UNCERTAIN, reported separately).
"""
from __future__ import annotations

import ipaddress
import itertools

from .trace import Packet, trace

PORT_PROTOS = ("tcp", "udp", "sctp")
MAX_PROBES = 20000
OUTSIDER_V4, OUTSIDER_V6 = "203.0.113.77", "2001:db8::77"
OTHER_IF = "other0"      # stands for any interface the rulesets do not name
STATES = ("NEW", "ESTABLISHED", "RELATED", "INVALID")


def _rules(parsed):
    table = parsed["tables"].get("filter")
    if not table:
        return []
    return [r for c in table["chains"].values() for r in c["rules"]]


def _collect(parsed_list):
    kinds = {"proto": set(), "sport": [], "dport": [], "src": [], "dst": [], "iif": set(), "oif": set(), "state": False}
    for parsed in parsed_list:
        for r in _rules(parsed):
            for kind, val, _neg in r["conds"]:
                if kind in ("proto",):
                    if val != "all":
                        kinds["proto"].add(val)
                elif kind in ("sport", "dport"):
                    kinds[kind] += val
                elif kind in ("src", "dst"):
                    kinds[kind] += val
                elif kind in ("iif", "oif"):
                    kinds[kind].add(val)
                elif kind == "state":
                    kinds["state"] = True
    return kinds


def _port_points(ranges):
    pts = {1}                       # real traffic uses ports 1-65535
    for lo, hi in ranges:
        pts.add(max(lo, 1))
        if hi + 1 <= 65535:
            pts.add(hi + 1)
    return sorted(p for p in pts if 0 <= p <= 65535)


def _addr_points(nets):
    if not nets:
        return [None]
    pts = {OUTSIDER_V4}
    if any(n.version == 6 for n in nets):
        pts.add(OUTSIDER_V6)
    for n in nets:
        pts.add(str(n.network_address))
        nxt = int(n.broadcast_address) + 1
        if nxt < 2 ** n.max_prefixlen:
            pts.add(str(ipaddress.ip_address(nxt) if n.version == 4 else ipaddress.IPv6Address(nxt)))
    return sorted(pts, key=lambda a: (ipaddress.ip_address(a).version, int(ipaddress.ip_address(a))))


def _iface_points(patterns):
    if not patterns:
        return [None]
    pts = {OTHER_IF}
    for p in patterns:
        pts.add(p[:-1] + "0" if p.endswith("+") else p)
    return sorted(pts)


def build_probes(parsed_list, states=("NEW",)):
    """Return (probes, capped). Each probe is a dict of Packet keyword arguments."""
    k = _collect(parsed_list)
    protos = sorted(k["proto"] | {"tcp", "udp"})
    srcs, dsts = _addr_points(k["src"]), _addr_points(k["dst"])
    iifs, oifs = _iface_points(k["iif"]), _iface_points(k["oif"])
    st = list(states) if k["state"] else ["NEW"]
    probes, capped = [], False
    for proto in protos:
        if proto in PORT_PROTOS:
            sports = _port_points(k["sport"]) if k["sport"] else [None]
            dports = _port_points(k["dport"]) if k["dport"] else [None]
        else:
            sports = dports = [None]
        for combo in itertools.product(srcs, dsts, sports, dports, iifs, oifs, st):
            if len(probes) >= MAX_PROBES:
                return probes, True
            s, d, sp, dp, i, o, state = combo
            probes.append(dict(proto=proto, src=s, dst=d, sport=sp, dport=dp, iif=i, oif=o, state=state))
    return probes, capped


def _verdict(parsed, chain, probe):
    try:
        return trace(parsed, chain, Packet(**probe))["verdict"]
    except ValueError:
        return "NO-CHAIN"


def _kind(old, new):
    if old == new:
        return None
    if "UNCERTAIN" in (old, new):
        return "undetermined"
    if new == "ACCEPT":
        return "opened"
    if old == "ACCEPT":
        return "closed"
    return "changed"


def diff_rulesets(old, new, chain="INPUT", states=("NEW",)):
    probes, capped = build_probes([old, new], states)
    changes, tallies = [], {"opened": 0, "closed": 0, "changed": 0, "undetermined": 0, "same": 0}
    for p in probes:
        a, b = _verdict(old, chain, p), _verdict(new, chain, p)
        kind = _kind(a, b)
        if kind is None:
            tallies["same"] += 1
            continue
        tallies[kind] += 1
        changes.append({"kind": kind, "old": a, "new": b, **p})
    notes = ["Probes are representative packets built from the values the two rulesets mention; this compares filter-table behaviour only. NAT, mangle and raw rules are not simulated, and matches ruleglass cannot evaluate make a verdict UNCERTAIN."]
    if any(c.get("iif") == OTHER_IF or c.get("oif") == OTHER_IF for c in changes):
        notes.append(f"{OTHER_IF} stands for any interface the rulesets do not name.")
    if capped:
        notes.append(f"Stopped at {MAX_PROBES} probes; the comparison is incomplete.")
    if not _rules(old) and not _rules(new):
        notes.append("Neither ruleset has a filter table.")
    return {"chain": chain, "probes": len(probes), "summary": tallies, "changes": changes, "groups": group(changes), "notes": notes}


def group(changes):
    """Merge changes that differ only by destination port into port ranges."""
    buckets = {}
    for c in changes:
        key = (c["kind"], c["old"], c["new"], c["proto"], c["src"], c["dst"], c["sport"], c["iif"], c["oif"], c["state"])
        buckets.setdefault(key, []).append(c["dport"])
    rows = {}
    for (kind, old, new, proto, src, dst, sport, iif, oif, state), ports in buckets.items():
        rk = (kind, old, new, proto, tuple(sorted(ports, key=lambda x: -1 if x is None else x)), sport, state)
        row = rows.setdefault(rk, {"kind": kind, "old": old, "new": new, "proto": proto, "dports": [p for p in rk[4]],
                                   "sport": sport, "state": state, "src": set(), "dst": set(), "iif": set(), "oif": set()})
        for fld, val in (("src", src), ("dst", dst), ("iif", iif), ("oif", oif)):
            if val is not None:
                row[fld].add(val)
    out = []
    for r in rows.values():
        for fld in ("src", "dst", "iif", "oif"):
            r[fld] = sorted(r[fld])
        out.append(r)
    order = {"opened": 0, "undetermined": 1, "changed": 2, "closed": 3}
    out.sort(key=lambda r: (order[r["kind"]], r["proto"], r["dports"][0] if r["dports"] and r["dports"][0] is not None else -1))
    return out


def _ports(ps):
    if ps == [None]:
        return ""
    return "/" + ",".join(str(p) for p in ps)


def to_text(res):
    s = res["summary"]
    out = [f"ruleglass diff ({res['chain']}): {res['probes']} probes; {s['opened']} newly allowed, {s['closed']} newly blocked, "
           f"{s['changed']} other change, {s['undetermined']} undetermined, {s['same']} unchanged"]
    for n in res["notes"]:
        out.append("note: " + n)
    word = {"opened": "NEWLY ALLOWED", "closed": "NEWLY BLOCKED", "changed": "CHANGED", "undetermined": "UNDETERMINED"}
    for g in res["groups"]:
        where = []
        for fld, label in (("src", "from"), ("dst", "to"), ("iif", "in"), ("oif", "out")):
            if g[fld]:
                where.append(f"{label} {', '.join(g[fld][:6])}" + (f" (+{len(g[fld]) - 6} more)" if len(g[fld]) > 6 else ""))
        out.append(f"{word[g['kind']]:<13} {g['proto']}{_ports(g['dports'])}  {g['old']} -> {g['new']}  " + "; ".join(where))
    if not res["groups"]:
        out.append("No difference for any probe.")
    return "\n".join(out) + "\n"
