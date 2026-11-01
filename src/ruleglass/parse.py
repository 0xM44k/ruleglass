"""Parse `iptables-save` / `ip6tables-save` text into tables, chains and rules.

Only reads text you give it. Never runs iptables.
Conditions are tuples (kind, value, negated). Anything not understood becomes
("unknown", description, False), which later evaluates to "cannot tell".
"""
from __future__ import annotations

import ipaddress
import shlex

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "ipv6-icmp": 58, "gre": 47, "esp": 50, "ah": 51, "sctp": 132}
BUILTIN = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}
TERMINAL = {"ACCEPT", "DROP", "REJECT"}
NONTERMINAL = {"LOG", "ULOG", "NFLOG"}
COMMENT_ONLY_MODULES = {"comment", "tcp", "udp", "icmp", "icmp6", "multiport", "state", "conntrack"}


class ParseError(Exception):
    pass


def norm_proto(p):
    p = p.lower()
    if p in ("all", "0"):
        return "all"
    if p.isdigit():
        n = int(p)
        for k, v in PROTO_NUM.items():
            if v == n:
                return k
        return str(n)
    return {"ipv6-icmp": "icmpv6"}.get(p, p)


def parse_ports(spec):
    out = []
    for part in spec.split(","):
        a, _, b = part.partition(":")
        lo = int(a) if a else 0
        hi = int(b) if b else (65535 if ":" in part else lo)
        if not (0 <= lo <= hi <= 65535):
            raise ValueError(f"bad port range {part!r}")
        out.append((lo, hi))
    return out


def parse_nets(spec):
    return [ipaddress.ip_network(s, strict=False) for s in spec.split(",")]


def parse_rule(line, lineno):
    try:
        toks = shlex.split(line)
    except ValueError as e:
        raise ParseError(f"line {lineno}: {e}") from e
    if len(toks) < 2 or toks[0] not in ("-A", "-I"):
        raise ParseError(f"line {lineno}: unsupported rule syntax: {line[:60]}")
    rule = {"chain": toks[1], "line": lineno, "raw": line.strip(), "conds": [], "target": None, "goto": False}
    i, neg, module = 2, False, None
    if toks[0] == "-I" and len(toks) > 2 and toks[2].isdigit():
        i = 3

    def val():
        nonlocal i, neg
        i += 1
        if i < len(toks) and toks[i] == "!":
            neg, i = True, i + 1
        if i >= len(toks):
            raise ParseError(f"line {lineno}: option {toks[i - 1]!r} needs a value")
        return toks[i]

    while i < len(toks):
        t = toks[i]
        try:
            if t == "!":
                neg = True
            elif t in ("-s", "--source", "--src"):
                rule["conds"].append(("src", parse_nets(val()), neg)); neg = False
            elif t in ("-d", "--destination", "--dst"):
                rule["conds"].append(("dst", parse_nets(val()), neg)); neg = False
            elif t in ("-p", "--protocol"):
                rule["conds"].append(("proto", norm_proto(val()), neg)); neg = False
            elif t in ("-i", "--in-interface"):
                rule["conds"].append(("iif", val(), neg)); neg = False
            elif t in ("-o", "--out-interface"):
                rule["conds"].append(("oif", val(), neg)); neg = False
            elif t in ("-m", "--match"):
                module = val(); neg = False
                if module not in COMMENT_ONLY_MODULES:
                    rule["conds"].append(("unknown", f"-m {module}", False))
            elif t in ("--dport", "--destination-port", "--dports", "--destination-ports"):
                rule["conds"].append(("dport", parse_ports(val()), neg)); neg = False
            elif t in ("--sport", "--source-port", "--sports", "--source-ports"):
                rule["conds"].append(("sport", parse_ports(val()), neg)); neg = False
            elif t in ("--state", "--ctstate"):
                rule["conds"].append(("state", set(val().upper().split(",")), neg)); neg = False
            elif t == "--comment":
                val(); neg = False
            elif t in ("-j", "--jump", "-g", "--goto"):
                rule["target"] = val()
                rule["goto"] = t in ("-g", "--goto")
                break                                       # everything after is target options
            elif t in ("-f", "--fragment", "--syn", "--tcp-flags", "--tcp-option", "--icmp-type", "--icmpv6-type", "--limit", "--limit-burst", "--mac-source", "--uid-owner", "--gid-owner", "--match-set", "--src-type", "--dst-type", "--set", "--update", "--rcheck", "--seconds", "--hitcount", "--string", "--algo", "--length", "--mark", "--connlimit-above", "--connmark", "--ttl-eq", "--dscp", "--ctproto", "--ctorigsrc", "--ctorigdst", "--ctstatus", "--physdev-in", "--physdev-out", "--physdev-is-bridged"):
                rule["conds"].append(("unknown", t, False)); neg = False
                if not t.startswith("-f") and t not in ("--syn", "-f", "--fragment") and i + 1 < len(toks) and not toks[i + 1].startswith("-"):
                    i += 1
            elif t.startswith("-"):
                rule["conds"].append(("unknown", t, False))
                if i + 1 < len(toks) and not toks[i + 1].startswith("-"):
                    i += 1
        except ValueError as e:
            raise ParseError(f"line {lineno}: {e}") from e
        i += 1
    if rule["target"] is None:
        rule["target"] = ""               # counting-only rule: no -j
    return rule


def parse(text):
    """Returns {"tables": {name: {"chains": {chain: {"policy": str|None, "rules": [...]}}}}, "errors": [...]}"""
    tables, cur, errors = {}, None, []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("*"):
            cur = tables.setdefault(s[1:], {"chains": {}})
        elif s == "COMMIT":
            cur = None
        elif s.startswith(":"):
            if cur is None:
                errors.append(f"line {n}: chain declaration outside a table")
                continue
            parts = s[1:].split()
            cur["chains"][parts[0]] = {"policy": parts[1] if len(parts) > 1 and parts[1] != "-" else None, "rules": []}
        elif s.startswith(("-A", "-I")):
            if cur is None:
                errors.append(f"line {n}: rule outside a table")
                continue
            try:
                r = parse_rule(s, n)
            except ParseError as e:
                errors.append(str(e))
                continue
            ch = cur["chains"].setdefault(r["chain"], {"policy": None, "rules": []})
            ch["rules"].append(r)
        else:
            errors.append(f"line {n}: not recognised: {s[:50]}")
    if not tables:
        raise ParseError("no tables found: is this iptables-save output (lines like *filter, :INPUT DROP [0:0], -A INPUT ...)?")
    return {"tables": tables, "errors": errors}
