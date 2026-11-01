import json, os, subprocess, sys, unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
from ruleglass.analyze import analyze, covers
from ruleglass.parse import ParseError, parse, parse_rule
from ruleglass.trace import Packet, trace


def rs(body, policy="DROP", extra_chains=""):
    return f"*filter\n:INPUT {policy} [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n{extra_chains}{body}\nCOMMIT\n"


def v(text, chain="INPUT", **kw):
    return trace(parse(text), chain, Packet(**kw))["verdict"]


FULL = dict(proto="tcp", src="203.0.113.9", dst="10.0.0.2", sport=40000, iif="eth0")


class Parse(unittest.TestCase):
    def test_options(self):
        r = parse_rule('-A INPUT ! -s 10.0.0.0/8 -p tcp -m tcp --dport 22:25 -m comment --comment "a b; c" -j ACCEPT', 1)
        kinds = [(c[0], c[2]) for c in r["conds"]]
        self.assertEqual(kinds, [("src", True), ("proto", False), ("dport", False)])
        self.assertEqual(r["conds"][2][1], [(22, 25)])
        self.assertEqual(r["target"], "ACCEPT")

    def test_old_style_negation_and_multiport_and_state(self):
        r = parse_rule("-A INPUT -s ! 10.0.0.1 -m multiport --dports 80,443,8000:8100 -m state --state NEW,ESTABLISHED -j DROP", 1)
        self.assertTrue(r["conds"][0][2])
        self.assertEqual(r["conds"][1][1], [(80, 80), (443, 443), (8000, 8100)])
        self.assertEqual(r["conds"][2][1], {"NEW", "ESTABLISHED"})

    def test_unsupported_modules_become_unknown(self):
        r = parse_rule("-A INPUT -m recent --rcheck --seconds 60 -j DROP", 1)
        self.assertTrue(all(c[0] == "unknown" for c in r["conds"]))

    def test_target_options_ignored(self):
        r = parse_rule('-A INPUT -p tcp -j REJECT --reject-with tcp-reset', 1)
        self.assertEqual(r["target"], "REJECT")

    def test_errors_do_not_abort(self):
        p = parse(rs("-A INPUT -p tcp --dport 99999 -j ACCEPT\n-A INPUT -j DROP\ngarbage"))
        self.assertEqual(len(p["errors"]), 2)
        self.assertEqual(len(p["tables"]["filter"]["chains"]["INPUT"]["rules"]), 1)

    def test_not_iptables_output(self):
        with self.assertRaises(ParseError):
            parse("hello world")


class Trace(unittest.TestCase):
    def test_policy_and_accept(self):
        t = rs("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT")
        self.assertEqual(v(t, **FULL, dport=22), "ACCEPT")
        self.assertEqual(v(t, **FULL, dport=23), "DROP")
        self.assertEqual(v(rs("", policy="ACCEPT"), **FULL, dport=23), "ACCEPT")

    def test_first_match_wins(self):
        t = rs("-A INPUT -s 203.0.113.0/24 -j DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT")
        self.assertEqual(v(t, **FULL, dport=22), "DROP")

    def test_negation(self):
        t = rs("-A INPUT ! -s 10.0.0.0/8 -j DROP", policy="ACCEPT")
        self.assertEqual(v(t, **FULL, dport=22), "DROP")
        self.assertEqual(v(t, **dict(FULL, src="10.1.1.1"), dport=22), "ACCEPT")

    def test_user_chain_return_and_fallthrough(self):
        t = rs("-A INPUT -j U\n-A INPUT -p tcp --dport 80 -j ACCEPT\n-A U -s 10.0.0.0/8 -j DROP\n-A U -j RETURN", extra_chains=":U - [0:0]\n")
        self.assertEqual(v(t, **FULL, dport=80), "ACCEPT")
        self.assertEqual(v(t, **dict(FULL, src="10.1.1.1"), dport=80), "DROP")

    def test_user_chain_end_returns_to_caller(self):
        t = rs("-A INPUT -j U\n-A INPUT -j ACCEPT\n-A U -s 10.0.0.0/8 -j DROP", extra_chains=":U - [0:0]\n")
        self.assertEqual(v(t, **FULL, dport=1), "ACCEPT")

    def test_goto_does_not_return_to_caller_rules(self):
        t = rs("-A INPUT -g U\n-A INPUT -j ACCEPT\n-A U -s 10.0.0.0/8 -j DROP", extra_chains=":U - [0:0]\n")
        self.assertEqual(v(t, **FULL, dport=1), "DROP")      # falls off U, ends INPUT, policy DROP

    def test_loop_is_uncertain_not_a_hang(self):
        t = rs("-A INPUT -j A\n-A A -j B\n-A B -j A", extra_chains=":A - [0:0]\n:B - [0:0]\n")
        self.assertEqual(v(t, **FULL), "UNCERTAIN")

    def test_unsupported_match_gives_uncertain_with_both_outcomes(self):
        t = rs("-A INPUT -p tcp --dport 80 -m limit --limit 5/s -j ACCEPT")
        r = trace(parse(t), "INPUT", Packet(**FULL, dport=80))
        self.assertEqual((r["verdict"], r["possible"]), ("UNCERTAIN", ["ACCEPT", "DROP"]))

    def test_uncertain_that_does_not_change_outcome_is_definite(self):
        t = rs("-A INPUT -m recent --rcheck -j LOG\n-A INPUT -j ACCEPT")
        self.assertEqual(v(t, **FULL), "ACCEPT")

    def test_missing_packet_field_is_uncertain(self):
        t = rs("-A INPUT -i lo -j ACCEPT")
        self.assertEqual(v(t, proto="tcp", src="1.2.3.4", dport=22), "UNCERTAIN")
        self.assertEqual(v(t, proto="tcp", src="1.2.3.4", dport=22, iif="lo"), "ACCEPT")
        self.assertEqual(v(t, proto="tcp", src="1.2.3.4", dport=22, iif="eth0"), "DROP")

    def test_interface_wildcard_and_state(self):
        t = rs("-A INPUT -i eth+ -m conntrack --ctstate ESTABLISHED -j ACCEPT")
        self.assertEqual(v(t, **FULL, dport=1, state="ESTABLISHED"), "ACCEPT")
        self.assertEqual(v(t, **FULL, dport=1, state="NEW"), "DROP")
        self.assertEqual(v(t, **dict(FULL, iif="wlan0"), dport=1, state="ESTABLISHED"), "DROP")

    def test_ports_do_not_apply_to_icmp(self):
        t = rs("-A INPUT -p tcp --dport 22 -j ACCEPT")
        self.assertEqual(v(t, proto="icmp", src="1.2.3.4", iif="eth0"), "DROP")

    def test_ipv6_and_family_mismatch(self):
        t = rs("-A INPUT -s 2001:db8::/32 -j ACCEPT")
        self.assertEqual(v(t, proto="tcp", src="2001:db8::1", iif="eth0", dport=1), "ACCEPT")
        self.assertEqual(v(t, proto="tcp", src="192.0.2.1", iif="eth0", dport=1), "DROP")

    def test_reject_and_unknown_target(self):
        self.assertEqual(v(rs("-A INPUT -j REJECT --reject-with icmp-port-unreachable"), **FULL), "REJECT")
        self.assertEqual(v(rs("-A INPUT -j NFQUEUE --queue-num 1"), **FULL), "UNCERTAIN")

    def test_branch_explosion_is_bounded(self):
        body = "\n".join(f"-A INPUT -m recent --rcheck --name n{i} -j DROP" for i in range(40))
        self.assertIn(v(rs(body, policy="ACCEPT"), **FULL), ("UNCERTAIN", "DROP", "ACCEPT"))   # must return, not hang


class Analyze(unittest.TestCase):
    def ids(self, text):
        return [f["id"] for f in analyze(parse(text))]

    def test_shadow_detection_positive_and_negative(self):
        base = "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        self.assertIn("RG002", self.ids(rs(base + "-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT")))
        self.assertNotIn("RG002", self.ids(rs(base + "-A INPUT -p tcp --dport 23 -j ACCEPT")))
        self.assertNotIn("RG002", self.ids(rs("-A INPUT -s 10.0.0.0/8 -j DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT")))   # B is broader on src
        self.assertNotIn("RG002", self.ids(rs("-A INPUT ! -s 10.0.0.0/8 -j DROP\n-A INPUT -s 192.0.2.1 -j ACCEPT")))     # negation: no claim
        self.assertNotIn("RG002", self.ids(rs("-A INPUT -m limit --limit 1/s -j DROP\n-A INPUT -p tcp -j ACCEPT")))      # unknown match: no claim
        self.assertNotIn("RG002", self.ids(rs("-A INPUT -j LOG\n-A INPUT -p tcp -j ACCEPT")))                           # LOG is not terminal

    def test_covers_ranges_and_ifaces(self):
        a = parse_rule("-A INPUT -p tcp --dport 1:1024 -i eth+ -j DROP", 1)
        self.assertTrue(covers(a, parse_rule("-A INPUT -p tcp --dport 22 -i eth0 -j ACCEPT", 2)))
        self.assertFalse(covers(a, parse_rule("-A INPUT -p tcp --dport 22 -i wlan0 -j ACCEPT", 2)))
        self.assertFalse(covers(a, parse_rule("-A INPUT -p tcp --dport 22:2000 -i eth0 -j ACCEPT", 2)))

    def test_sensitive_ports(self):
        self.assertIn("RG003", self.ids(rs("-A INPUT -p tcp -m multiport --dports 80,3306 -j ACCEPT")))
        self.assertNotIn("RG003", self.ids(rs("-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT")))
        self.assertNotIn("RG003", self.ids(rs("-A INPUT -i lo -p tcp --dport 22 -j ACCEPT")))

    def test_policy_undefined_unused_and_nat(self):
        ids = self.ids(rs("-A INPUT -j NOPE", policy="ACCEPT", extra_chains=":UNUSED - [0:0]\n") + "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.5\nCOMMIT\n")
        self.assertTrue({"RG001", "RG004", "RG005", "RG010"} <= set(ids))

    def test_realistic_docker_style_ruleset_parses(self):
        text = """*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER-USER -j RETURN
COMMIT
"""
        p = parse(text)
        self.assertEqual(p["errors"], [])
        r = trace(p, "FORWARD", Packet(proto="tcp", src="203.0.113.5", dst="172.17.0.2", dport=80, iif="eth0", oif="docker0"))
        self.assertEqual(r["verdict"], "ACCEPT")


class Cli(unittest.TestCase):
    def run_cli(self, *a, stdin=None):
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        return subprocess.run([sys.executable, "-m", "ruleglass", *a], capture_output=True, text=True, env=env, input=stdin)

    def test_example_and_exit_codes(self):
        ex = os.path.join(ROOT, "examples", "web-host.rules")
        self.assertEqual(self.run_cli("analyze", ex).returncode, 0)
        self.assertEqual(self.run_cli("analyze", ex, "--fail-on", "high").returncode, 1)
        self.assertEqual(self.run_cli("analyze", "/nonexistent").returncode, 2)
        self.assertEqual(self.run_cli("analyze", "-", stdin="nope").returncode, 2)
        p = self.run_cli("trace", ex, "--proto", "tcp", "--src", "203.0.113.9", "--dport", "22", "--in", "eth0")
        self.assertTrue(p.stdout.startswith("ACCEPT"))
        j = json.loads(self.run_cli("trace", ex, "--proto", "tcp", "--src", "203.0.113.9", "--dport", "25", "--in", "eth0", "--format", "json").stdout)
        self.assertEqual(j["verdict"], "DROP")
        self.assertEqual(self.run_cli("trace", ex, "--src", "not-an-ip").returncode, 2)

    def test_sarif_output(self):
        ex = os.path.join(ROOT, "examples", "web-host.rules")
        out = self.run_cli("analyze", ex, "--format", "sarif").stdout
        s = json.loads(out)
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ruleglass")
        if run["results"]:
            r0 = run["results"][0]
            self.assertIn(r0["level"], {"error", "warning", "note"})
            self.assertEqual(r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], ex)
            rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
            self.assertTrue({r["ruleId"] for r in run["results"]} <= rule_ids)


import ipaddress
import random
from ruleglass import diffrules


def rules_text(body, policy="DROP"):
    return rs(body, policy)


class Diff(unittest.TestCase):
    OLD = rules_text("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT")

    def d(self, old, new, **kw):
        return diffrules.diff_rulesets(parse(old), parse(new), **kw)

    def test_identical_rulesets_have_no_changes(self):
        r = self.d(self.OLD, self.OLD)
        self.assertEqual((r["summary"]["opened"], r["summary"]["closed"], r["changes"]), (0, 0, []))
        self.assertGreater(r["probes"], 0)

    def test_new_allow_is_opened_and_removal_is_closed(self):
        new = rules_text("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m multiport --dports 80,443,8443 -j ACCEPT")
        up = self.d(self.OLD, new)
        self.assertEqual([(g["kind"], g["proto"], g["dports"]) for g in up["groups"]], [("opened", "tcp", [8443])])
        down = self.d(new, self.OLD)
        self.assertEqual([(g["kind"], g["dports"]) for g in down["groups"]], [("closed", [8443])])

    def test_source_narrowing_is_reported_by_source(self):
        new = rules_text("-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT")
        r = self.d(self.OLD, new)
        closed = [c for c in r["changes"] if c["kind"] == "closed"]
        self.assertTrue(closed)
        self.assertTrue(all(c["dport"] == 22 and not c["src"].startswith("10.") for c in closed))
        self.assertEqual(r["summary"]["opened"], 0)

    def test_policy_flip_opens_everything_not_matched(self):
        r = self.d(self.OLD, rules_text("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", policy="ACCEPT"))
        self.assertGreater(r["summary"]["opened"], 0)

    def test_unevaluable_match_is_undetermined_not_a_guess(self):
        lim = rules_text("-A INPUT -p tcp -m tcp --dport 8080 -m limit --limit 10/second -j ACCEPT")
        r = self.d(self.OLD, lim)
        self.assertGreater(r["summary"]["undetermined"], 0)
        self.assertTrue(any(c["kind"] == "undetermined" and c["new"] == "UNCERTAIN" for c in r["changes"]))

    def test_interface_pattern_probe_and_other_interface(self):
        new = rules_text("-A INPUT -i br+ -j ACCEPT")
        r = self.d(rules_text(""), new)
        ifs = {c["iif"] for c in r["changes"]}
        self.assertEqual(ifs, {"br0"})

    def test_ipv6_nets_get_an_ipv6_outsider(self):
        new = rules_text("-A INPUT -s 2001:db8:1::/48 -j ACCEPT")
        r = self.d(rules_text(""), new)
        self.assertTrue(any(":" in c["src"] for c in r["changes"]))

    def test_missing_chain_is_reported_not_crashed(self):
        r = self.d("*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n", self.OLD)
        self.assertTrue(r["notes"])

    def test_probe_cap_is_disclosed(self):
        old, cap = diffrules.MAX_PROBES, 5
        diffrules.MAX_PROBES = cap
        try:
            r = self.d(self.OLD, self.OLD)
        finally:
            diffrules.MAX_PROBES = old
        self.assertEqual(r["probes"], cap)
        self.assertTrue(any("incomplete" in n for n in r["notes"]))

    def test_probe_cells_represent_every_point_of_the_domain(self):
        """For random rulesets, every packet in a small domain must get the same old/new verdicts as the
        probe that stands for its cell (the greatest probe port and address at or below it). If the probe
        set misses a boundary, some point falls into the wrong cell and this fails."""
        rng = random.Random(20261101)
        ADDRS = [f"10.0.0.{i}" for i in range(0, 32)] + ["192.0.2.1", "192.0.2.200", "203.0.113.77"]
        IFS = ["eth0", "eth1", "br0", "wlan9"]
        NETS = ["10.0.0.0/27", "10.0.0.0/29", "10.0.0.8/30", "10.0.0.16/28", "10.0.0.5", "10.0.0.31/32", "10.0.0.0/8", "192.0.2.0/24"]

        def gen():
            lines = []
            for _ in range(rng.randint(0, 6)):
                parts = ["-A INPUT"]
                if rng.random() < 0.5:
                    parts.append(("! " if rng.random() < 0.25 else "") + "-s " + rng.choice(NETS))
                if rng.random() < 0.4:
                    parts.append(("! " if rng.random() < 0.15 else "") + "-i " + rng.choice(["eth0", "eth1", "br+", "wlan9"]))
                if rng.random() < 0.8:
                    parts.append("-p tcp")
                    r = rng.random()
                    if r < 0.4:
                        lo = rng.randint(1, 55)
                        parts.append(f"-m tcp --dport {lo}:{lo + rng.randint(0, 6)}")
                    elif r < 0.6:
                        parts.append("-m multiport --dports " + ",".join(str(rng.randint(1, 60)) for _ in range(rng.randint(1, 3))))
                parts.append("-j " + rng.choice(["ACCEPT", "ACCEPT", "DROP", "REJECT"]))
                lines.append(" ".join(parts))
            return rs("\n".join(lines), policy=rng.choice(["DROP", "ACCEPT"]))

        def rep(sorted_pts, value, fallback):
            below = [p for p in sorted_pts if p <= value]
            return below[-1] if below else fallback

        points_checked = 0
        for _ in range(30):
            a_txt, b_txt = gen(), gen()
            a, b = parse(a_txt), parse(b_txt)
            probes, capped = diffrules.build_probes([a, b])
            self.assertFalse(capped)
            tcp = [p for p in probes if p["proto"] == "tcp"]
            ports = sorted({p["dport"] for p in tcp if p["dport"] is not None})
            addrs = sorted({ipaddress.ip_address(p["src"]) for p in tcp if p["src"] is not None and ":" not in p["src"]})
            ifs = {p["iif"] for p in tcp if p["iif"] is not None}
            keys = {(p["src"], p["dport"], p["iif"]) for p in tcp}
            for ip in ADDRS:
                for ifc in IFS:
                    rep_if = ifc if ifc in ifs else ("br0" if ifc.startswith("br") and "br0" in ifs else diffrules.OTHER_IF)
                    for port in range(1, 71):
                        point = dict(proto="tcp", src=ip, dport=port, iif=ifc)
                        want = (trace(a, "INPUT", Packet(**point))["verdict"], trace(b, "INPUT", Packet(**point))["verdict"])
                        rp = rep(ports, port, None)
                        ra = rep(addrs, ipaddress.ip_address(ip), ipaddress.ip_address(diffrules.OUTSIDER_V4)) if addrs else None
                        stand_in = dict(proto="tcp", src=str(ra) if ra is not None else None, dport=rp if ports else None, iif=rep_if if ifs else None)
                        self.assertIn((stand_in["src"], stand_in["dport"], stand_in["iif"]), keys, "stand-in packet is not in the probe set")
                        got = (trace(a, "INPUT", Packet(**stand_in))["verdict"], trace(b, "INPUT", Packet(**stand_in))["verdict"])
                        self.assertEqual(got, want, (a_txt, b_txt, point, stand_in))
                        points_checked += 1
        self.assertGreater(points_checked, 100000)

    def test_cli_text_json_and_exit_codes(self):
        import tempfile
        d = tempfile.mkdtemp()
        o, n = os.path.join(d, "o"), os.path.join(d, "n")
        open(o, "w").write(self.OLD)
        open(n, "w").write(rules_text("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m multiport --dports 80,443,8443 -j ACCEPT"))
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        run = lambda *a: subprocess.run([sys.executable, "-m", "ruleglass", "diff", *a], capture_output=True, text=True, env=env)
        self.assertEqual(run(o, n).returncode, 0)
        gate = run(o, n, "--fail-on", "opened")
        self.assertEqual(gate.returncode, 1)
        self.assertIn("NEWLY ALLOWED", gate.stdout)
        self.assertEqual(run(n, o, "--fail-on", "opened").returncode, 0)       # only closing: gate stays green
        self.assertEqual(run(n, o, "--fail-on", "any").returncode, 1)
        self.assertGreater(json.loads(run(o, n, "--format", "json").stdout)["summary"]["opened"], 0)
        self.assertEqual(run(o, "/nonexistent").returncode, 2)


if __name__ == "__main__":
    unittest.main()
