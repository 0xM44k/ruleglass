# Changelog

## 0.3.0 — 2026-11
- New `ruleglass diff OLD NEW`: reports what a ruleset change newly allows, newly blocks, changes, or leaves undetermined, using probes placed at every range, network and interface boundary the rulesets mention. `--fail-on opened|any` gates CI; text and JSON output.
- 11 new tests (39 total), including a brute-force check that the probe set represents every packet of a small domain, validated by mutation.
- Reported tool version now matches the package (it previously said 0.1.0).

## 0.2.0 — 2026-10
Added `analyze --format sarif`, so findings can go straight into GitHub code scanning or another SARIF viewer.

## 0.1.0 — 2026-10
Initial release. See the README for features and limits.
