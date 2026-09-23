> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# MO5 — iOS Security Assessment

**iOS app security assessment toolkit** by **5h4d0wn1k** for **mobile
penetration testing** of an app's `Info.plist`: App Transport Security (ATS)
exceptions, keychain access groups, data-protection flags, deprecated
`UIWebView` usage, export-compliance (`ITSAppUsesNonExemptEncryption`) states
and jailbreak-detection hints — with severity-tagged JSON findings and offline
fixtures. Standard-library only.

## Why assess Info.plist

An iOS app's `Info.plist` reveals high-impact security posture before a single
binary is touched: disabled ATS, wildcard keychain groups, deprecated
`UIWebView` and missing export-compliance declarations routinely ship in real
apps. This tool automates the plist triage step of a mobile assessment so
reviewers can flag CRITICAL keychain over-privileges and weak TLS policy in
seconds, then verify the rest of the binary. It works offline against bundled
vulnerable and hardened fixtures, making it an ideal lab exercise for
[assessment education](ETHICS.md). Only run it against apps you own or hold
written authorization to audit — see [SCOPE.md](SCOPE.md).

## Features

- **Plists without plistlib** — walks XML `<dict>/<array>/<string>/<integer>`
  key trees via `ElementTree` (`parse_plist` in `firmware/ios_assess.py`).
- **ATS analysis** — flags `NSAllowsArbitraryLoads`,
  `NSAllowsArbitraryLoadsInWebContent`, per-domain
  `NSExceptionMinimumTLSVersion` and `NSExceptionRequiresForwardSecrecy`.
- **Data protection** — checks `UIFileSharingEnabled` and
  `LSSupportsOpeningDocumentsInPlace`.
- **Keychain scope** — CRITICAL for wildcard `*` access group; MEDIUM for
  shared app-group / iCloud identifiers.
- **Deprecated components** — `UIWebView` detection.
- **Export compliance (EAR)** — validates `ITSAppUsesNonExemptEncryption`
  states against App Store review expectations.
- **Hardening hints** — jailbreak-detection indicator inventory
  (`jailbreak`, `cydia`, `frida`, `substrate`, …).
- **Findings report** — severity-tagged JSON summary with severity counts.
- **Offline fixtures** — `vulnerable_Info.plist` and `hardened_Info.plist` for
  deterministic demos and differential testing.

## Quickstart

```bash
# Offline demo (assesses the vulnerable + hardened fixtures, writes reports/)
python3 firmware/ios_assess.py

# Assess a real Info.plist from a permitted IPA
unzip -p app.ipa Payload/App.app/Info.plist > Info.plist
python3 firmware/ios_assess.py -p Info.plist --json

# Rebuild fixtures
python3 firmware/ios_assess.py --make-fixture

# Run the test suite (18 deterministic offline tests)
python3 -m unittest discover -s tests
```

## CLI

```
python3 firmware/ios_assess.py [-h] [-p PLIST] [--json] [--report-dir REPORT_DIR]
                               [--make-fixture]
```

- `-p, --plist` — path to an `Info.plist`; omitted → offline demo.
- `--json` — write a JSON findings summary to `reports/`.
- `--report-dir` — report directory (default `reports`).
- `--make-fixture` — regenerate fixtures and exit.

Exit codes: `0` on success (including the demo), `2` on input error.

## Project structure

```
firmware/ios_assess.py   # plist parser, check modules, findings, CLI
fixtures/                # vulnerable_ and hardened_Info.plist demo targets
tests/                   # unittest coverage: ATS, keychain, EAR, demo
ETHICS.md                # educational-use policy (read first)
SCOPE.md                 # scope and target authorization rules
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized target scope.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

New plist checks, fixture variants and differential test cases are welcome.
Open an issue or PR against the default branch; keep contributions scoped to
educational and authorized-use tooling.

## License

MIT — full legal shield in [LICENSE](LICENSE). Educational, authorization-
required software for assessing iOS apps you own or are explicitly permitted
to audit.