"""Check ruleglass against the real Linux kernel on the shipped example ruleset.

Needs: Linux, root (CAP_NET_ADMIN), iptables-restore, nsenter and `pip install pyroute2`.
It builds two throw-away network namespaces joined by a veth pair, loads
examples/web-host.rules into the "host" namespace, and opens real TCP connections to it
from several source addresses. A connection that completes means the kernel accepted
the SYN; a timeout means it was dropped. Each result is printed next to the verdict of
`ruleglass trace`. Nothing outside the two namespaces is touched; both are removed at
the end.

    python3 tools/kernel_example.py [rules-file]

The check is meant to catch a *wrong* verdict (ruleglass says ACCEPT, kernel dropped,
or the reverse). A verdict of UNCERTAIN is not a mismatch: ruleglass is saying it cannot
decide, for example because of `-m limit`, and the kernel's answer for one packet is one
of the outcomes it allowed.
"""
import os
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from pyroute2 import NetNS, netns as nsmod  # noqa: E402

RULES = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "examples", "web-host.rules")
HOST_IP, CLIENT_NET = "198.51.100.1", "198.51.100.2"
SOURCES = ["203.0.113.9", "10.1.2.3", "192.0.2.5"]
PORTS = [22, 80, 443, 8080, 3306, 9000, 25]
IFACE = "veth-h"


def in_ns(name):
    fd = os.open(f"/var/run/netns/{name}", os.O_RDONLY)
    os.setns(fd, os.CLONE_NEWNET)
    os.close(fd)


def setup():
    for n in ("rg_h", "rg_c"):
        try:
            nsmod.remove(n)
        except Exception:
            pass
    h, c = NetNS("rg_h"), NetNS("rg_c")
    me = NetNS  # keep linter quiet
    root = __import__("pyroute2").IPRoute()
    root.link("add", ifname=IFACE, kind="veth", peer={"ifname": "veth-c", "net_ns_fd": "rg_c"})
    idx = root.link_lookup(ifname=IFACE)[0]
    root.link("set", index=idx, net_ns_fd="rg_h")
    root.close()
    hi = h.link_lookup(ifname=IFACE)[0]
    h.addr("add", index=hi, address=HOST_IP, prefixlen=24)
    h.link("set", index=hi, state="up")
    h.link("set", index=h.link_lookup(ifname="lo")[0], state="up")
    ci = c.link_lookup(ifname="veth-c")[0]
    c.addr("add", index=ci, address=CLIENT_NET, prefixlen=24)
    for s in SOURCES:
        c.addr("add", index=ci, address=s, prefixlen=32)
        h.route("add", dst=s, prefixlen=32, oif=hi)            # reply path
    c.link("set", index=ci, state="up")
    c.route("add", dst=HOST_IP, prefixlen=32, oif=ci)
    return h, c


def load_rules():
    with open(RULES) as f:
        text = f.read()
    p = subprocess.run(["nsenter", "--net=/var/run/netns/rg_h", "iptables-restore"], input=text,
                       text=True, capture_output=True)
    if p.returncode:
        sys.exit("iptables-restore failed: " + p.stderr)


def serve():
    in_ns("rg_h")
    socks = []
    for p in PORTS:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.listen(16)
        socks.append(s)
    while True:
        time.sleep(1)


def kernel_verdict(src, port):
    in_ns("rg_c")
    s = socket.socket()
    s.settimeout(1.5)
    s.bind((src, 0))
    try:
        s.connect((HOST_IP, port))
        return "ACCEPT"
    except socket.timeout:
        return "DROP"
    except ConnectionRefusedError:
        return "REJECT"
    finally:
        s.close()


def ruleglass_verdict(src, port):
    env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"), PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run([sys.executable, "-m", "ruleglass", "trace", RULES, "--proto", "tcp", "--src", src,
                        "--dst", HOST_IP, "--dport", str(port), "--in", IFACE, "--state", "NEW", "--format", "json"],
                       capture_output=True, text=True, env=env)
    import json
    return json.loads(p.stdout)["verdict"] if p.stdout.strip().startswith("{") else p.stdout.strip() or p.stderr


def main():
    h, c = setup()
    try:
        load_rules()
        # the server thread must switch namespace, so run it in a forked process
        pid = os.fork()
        if pid == 0:
            try:
                serve()
            finally:
                os._exit(0)
        time.sleep(0.5)
        bad = 0
        print(f"{'source':<13}{'dport':>6}  {'kernel':<8}{'ruleglass':<10}result")
        for src in SOURCES:
            for port in PORTS:
                k = kernel_verdict(src, port)
                r = ruleglass_verdict(src, port)
                ok = (r == k) or r == "UNCERTAIN"
                bad += not ok
                print(f"{src:<13}{port:>6}  {k:<8}{r:<10}{'ok' if ok and r == k else ('ok (uncertain, kernel allowed)' if ok else 'MISMATCH')}")
        os.kill(pid, 9)
        print("\nmismatches:", bad)
        return 1 if bad else 0
    finally:
        h.close(); c.close()
        for n in ("rg_h", "rg_c"):
            try:
                nsmod.remove(n)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
