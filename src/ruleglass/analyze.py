"""Static checks on a parsed ruleset."""
from __future__ import annotations

from .parse import BUILTIN, TERMINAL

SENSITIVE = {22: "SSH", 23: "Telnet", 445: "SMB", 139: "NetBIOS", 3389: "RDP", 5900: "VNC", 3306: "MySQL", 5432: "PostgreSQL",
             6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API (unencrypted)"}
SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _cond(rule, kind):
    return [c for c in rule["conds"] if c[0] == kind]


def _simple(rule):
    """True when every condition is understood and un-negated, so set comparison is sound."""
    return all(k != "unknown" and not neg for k, _, neg in rule["conds"]) and rule["target"] in TERMINAL | {"RETURN"}


def _net_subset(b, a):
    return all(any(x.version == y.version and x.subnet_of(y) for y in a) for x in b)


def _range_subset(b, a):
    return all(any(alo <= blo and bhi <= ahi for alo, ahi in a) for blo, bhi in b)


def _iface_subset(b, a):
    if a.endswith("+"):
        return b.startswith(a[:-1])
    return a == b


def covers(a, b):
    """True if every packet matching rule b also matches rule a (a is simple)."""
    if not _simple(a):
        return False
    for kind, aval, _ in a["conds"]:
        bs = _cond(b, kind)
        if not bs or any(neg for _, _, neg in bs):
            return False
        bval = bs[0][1]
        if kind in ("src", "dst"):
            ok = _net_subset(bval, aval)
        elif kind in ("sport", "dport"):
            ok = _range_subset(bval, aval)
        elif kind in ("iif", "oif"):
            ok = _iface_subset(bval, aval)
        elif kind == "state":
            ok = bval <= aval
        elif kind == "proto":
            ok = aval == "all" or bval == aval
        else:
            ok = False
        if not ok:
            return False
    return True


def _f(rule_id, sev, chain, rule, title, detail):
    return {"id": rule_id, "severity": sev, "chain": chain, "line": rule["line"] if rule else None, "rule": rule["raw"] if rule else None, "title": title, "detail": detail}


def analyze(parsed):
    out = []
    for e in parsed["errors"]:
        out.append({"id": "RG000", "severity": "info", "chain": None, "line": None, "rule": None, "title": "Line not understood", "detail": e})
    tables = parsed["tables"]
    for tname in tables:
        if tname != "filter" and any(c["rules"] for c in tables[tname]["chains"].values()):
            out.append({"id": "RG010", "severity": "info", "chain": None, "line": None, "rule": None,
                        "title": f"Table {tname} has rules that are not simulated",
                        "detail": "NAT, mangle and raw rules can change a packet's address, port or mark before the filter table sees it. Traces cover the filter table only."})
    flt = tables.get("filter")
    if not flt:
        return out
    chains = flt["chains"]
    for name in ("INPUT", "FORWARD"):
        c = chains.get(name)
        if c and (c["policy"] or "ACCEPT") == "ACCEPT":
            out.append({"id": "RG001", "severity": "medium", "chain": name, "line": None, "rule": None, "title": f"{name} policy is ACCEPT",
                        "detail": "Anything not matched by a rule is allowed. Prefer a DROP policy with explicit allows, or a final explicit DROP rule."})
    jumped = set()
    for name, c in chains.items():
        for r in c["rules"]:
            if r["target"] in chains and r["target"] not in BUILTIN:
                jumped.add(r["target"])
            elif r["target"] and r["target"] not in TERMINAL | {"RETURN", "LOG", "ULOG", "NFLOG"} and r["target"] not in chains:
                if r["target"] not in ("MARK", "NFQUEUE", "CONNMARK", "TRACE", "TCPMSS", "SECMARK", "CT", "NOTRACK", "TEE", "SET", "CLASSIFY", "DSCP", "TOS", "TTL", "HL", "REDIRECT", "DNAT", "SNAT", "MASQUERADE", "NETMAP", "CHECKSUM", "SYNPROXY", "AUDIT", "HMARK", "IDLETIMER", "LED", "RATEEST", "CLUSTERIP", "ECN"):
                    out.append(_f("RG004", "high", name, r, f"Jump to undefined chain {r['target']}", "iptables would refuse to load this ruleset."))
        for i, r in enumerate(c["rules"]):
            for prev in c["rules"][:i]:
                if covers(prev, r):
                    out.append(_f("RG002", "medium", name, r, "Rule can never match (shadowed)",
                                  f"Line {prev['line']} ({prev['target']}) already handles every packet this rule would match."))
                    break
            if name in ("INPUT", "FORWARD") and r["target"] == "ACCEPT" and not _cond(r, "src") and not _cond(r, "iif"):
                for lo, hi in sum((c_[1] for c_ in _cond(r, "dport")), []):
                    for port, label in SENSITIVE.items():
                        if lo <= port <= hi and not any(neg for _, _, neg in _cond(r, "dport")):
                            out.append(_f("RG003", "high" if port in (22, 23, 3389, 5900, 2375, 445, 139) else "medium", name, r,
                                          f"{label} (port {port}) is open to any source",
                                          "No source address or interface restriction. Restrict with -s, or place it behind a VPN or jump host."))
    for name in chains:
        if name not in BUILTIN and name not in jumped:
            out.append({"id": "RG005", "severity": "low", "chain": name, "line": None, "rule": None, "title": f"Chain {name} is never jumped to", "detail": "Its rules never run."})
    out.sort(key=lambda f: (SEV[f["severity"]], f["id"], f["line"] or 0))
    return out
