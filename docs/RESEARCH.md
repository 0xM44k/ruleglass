# Research record (2026-10-26)

Method: web search plus fetches. Search result pages gave titles only.

## Observed

- [kinkie/iptsim](https://github.com/kinkie/iptsim) (fetched): a Python tool that ingests `iptables-save` output and traces which rules a packet would traverse; GPL-3.0; the page gave no feature list, usage or stated limitations, so I cannot compare features. It says it was inspired by iptables-simulate from INQNET GmbH (I did not read that).
- Search also surfaced a web "firewall rule logic simulator" page; I did not open it.
- Because I read so little of the existing tools, ruleglass makes **no claim to be better or first**. Its design choices are the things I could reason about independently.

## Design choices

- **Three-valued matching.** Real rulesets contain matches an offline tool cannot evaluate (`-m limit`, `-m recent`, `-m set`, `-m owner`, ...) and traces often omit fields (such as the input interface). Rather than guess, a rule whose result depends on something unknown is "maybe", both branches are explored, and the answer is `UNCERTAIN: could be ACCEPT or DROP` with the exact rules and missing fields it depends on. A definite verdict means every branch agreed.
- **Static findings only where sound.** Shadowed-rule detection (a later rule that can never match) fires only when the earlier rule is terminal, has no negations or unknown matches, and set containment on addresses, port ranges, interface and state is provable. It makes no claim otherwise.
- **Filter table only.** NAT, mangle and raw can change a packet before filtering; ruleglass says so whenever those tables contain rules.

## Validated against the real kernel (limited)

`tools/kernel_diff.py` loads random rulesets into a throw-away network namespace (iptables v1.8.10, nf_tables backend, run as root in a cloud container), makes real TCP connections over loopback, and compares connect success / timeout / refusal with ruleglass's trace. It parses the kernel's **own** `iptables-save` output, so it also tests the parser against real formatting. Result on 2026-10-26: **1,184 probes across seeds 1–4, 0 disagreements** (all verdicts definite; no uncertain cases occurred).

What that covers: INPUT chain, new TCP connections over `lo`, source/destination addresses and networks (including negation), destination ports (single, range, multiport, negated), `-i lo`/`l+`/`! -i lo`, protocol, user chains, `RETURN`, `-g`, `LOG`, ACCEPT/DROP/REJECT, ACCEPT and DROP policies. What it does **not** cover: FORWARD/OUTPUT, IPv6, other interfaces, source ports, connection states other than NEW, `-m limit` or any other unsupported match, UDP/ICMP, NAT interplay.

## Not verified

- Not tested against large real-world dumps beyond one hand-written Docker-style example.
- `nft` rulesets (nftables native syntax) are not supported; `iptables-save` output from iptables-nft is.
- The sensitive-port list and severities are my judgement.
