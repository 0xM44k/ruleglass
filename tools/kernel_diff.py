"""Differential test of ruleglass against the real Linux kernel (netfilter).

Needs: Linux, root (CAP_NET_ADMIN), iptables, iptables-restore, unshare.
It creates a throw-away network namespace, loads random rulesets into it, makes real
TCP connections over the loopback interface and compares the outcome (connect
succeeds / times out / refused) with ruleglass's trace. Nothing outside the
namespace is touched.

    python3 tools/kernel_diff.py [--rulesets 60] [--seed 1]
"""
import argparse, fcntl, os, random, socket, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

SRCS = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
DSTS = ["127.0.0.5", "127.0.0.6"]
PORTS = [8001, 8002, 8003, 8004]
NETS = ["127.0.0.1", "127.0.0.2/32", "127.0.0.0/30", "127.0.0.0/8", "127.0.0.2", "127.0.0.4/30"]


def lo_up():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack("16sH", b"lo", 0)
    flags = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, ifr))[1]          # SIOCGIFFLAGS
    fcntl.ioctl(s, 0x8914, struct.pack("16sH", b"lo", flags | 1))           # SIOCSIFFLAGS IFF_UP


def gen_rule(rng, chain, in_user):
    parts = [f"-A {chain}"]
    if rng.random() < 0.5:
        parts.append(("! " if rng.random() < 0.2 else "") + "-s " + rng.choice(NETS))
    if rng.random() < 0.3:
        parts.append(("! " if rng.random() < 0.2 else "") + "-d " + rng.choice(["127.0.0.5", "127.0.0.4/30", "127.0.0.0/24"]))
    if rng.random() < 0.7:
        parts.append("-p tcp")
        r = rng.random()
        if r < 0.3:
            parts.append(f"-m tcp --dport {rng.choice(PORTS)}")
        elif r < 0.45:
            parts.append("-m tcp --dport 8001:8002")
        elif r < 0.6:
            parts.append("-m multiport --dports 8001,8003")
        elif r < 0.65:
            parts.append(f"-m tcp ! --dport {rng.choice(PORTS)}")
    if rng.random() < 0.15:
        parts.append(rng.choice(["-i lo", "! -i lo", "-i l+"]))
    if rng.random() < 0.05:
        parts.append("-m limit --limit 100000/sec --limit-burst 100000")
    targets = ["ACCEPT", "DROP", "REJECT", "LOG --log-prefix x", "-j U"] if not in_user else ["ACCEPT", "DROP", "REJECT", "RETURN", "LOG --log-prefix x"]
    t = rng.choice(targets)
    parts.append(t if t.startswith("-j") else f"-j {t}")
    if not in_user and rng.random() < 0.08:
        parts[-1] = "-g U"
    return " ".join(parts)


def gen_ruleset(rng):
    pol = rng.choice(["ACCEPT", "DROP"])
    lines = ["*filter", f":INPUT {pol} [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", ":U - [0:0]",
             "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]
    lines += [gen_rule(rng, "INPUT", False) for _ in range(rng.randint(1, 6))]
    lines += [gen_rule(rng, "U", True) for _ in range(rng.randint(0, 3))]
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def probe(src, dst, dport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.15)
    try:
        s.bind((src, 0))
        s.connect((dst, dport))
        return "ACCEPT"
    except socket.timeout:
        return "DROP"
    except ConnectionRefusedError:
        return "REJECT"
    finally:
        s.close()


def run_inner(n, seed):
    from ruleglass.parse import parse
    from ruleglass.trace import Packet, trace
    lo_up()
    listeners = []
    for p in PORTS:
        l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind(("0.0.0.0", p)); l.listen(64); listeners.append(l)
    rng = random.Random(seed)
    stats = dict(definite_agree=0, definite_disagree=0, uncertain_contains=0, uncertain_misses=0)
    bad = []
    for k in range(n):
        text = gen_ruleset(rng)
        r = subprocess.run(["iptables-restore"], input=text, text=True, capture_output=True)
        if r.returncode != 0:
            continue
        saved = subprocess.run(["iptables-save", "-t", "filter"], capture_output=True, text=True).stdout   # parse the kernel's own formatting
        parsed = parse(saved)
        for _ in range(8):
            src, dst, dport = rng.choice(SRCS), rng.choice(DSTS), rng.choice(PORTS)
            real = probe(src, dst, dport)
            res = trace(parsed, "INPUT", Packet(proto="tcp", src=src, dst=dst, dport=dport, iif="lo", state="NEW"))
            if res["verdict"] == "UNCERTAIN":
                ok = real in res["possible"]
                stats["uncertain_contains" if ok else "uncertain_misses"] += 1
            else:
                ok = real == res["verdict"]
                stats["definite_agree" if ok else "definite_disagree"] += 1
            if not ok:
                bad.append((saved, src, dst, dport, real, res["verdict"], res["possible"]))
        subprocess.run(["iptables", "-F"], capture_output=True); subprocess.run(["iptables", "-X"], capture_output=True)
        subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], capture_output=True)
    print(stats)
    for b in bad[:3]:
        print("MISMATCH", b[1:], "\n" + b[0])
    return 1 if bad else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--rulesets", type=int, default=60); ap.add_argument("--seed", type=int, default=1); ap.add_argument("--inner", action="store_true")
    a = ap.parse_args()
    if a.inner:
        sys.exit(run_inner(a.rulesets, a.seed))
    sys.exit(subprocess.call(["unshare", "-n", sys.executable, os.path.abspath(__file__), "--inner", "--rulesets", str(a.rulesets), "--seed", str(a.seed)]))
