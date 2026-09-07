# MO5 — iOS Security Assessment

Evaluates an iOS app's `Info.plist` for security misconfigurations — ATS
exceptions, data protection, keychain access groups, deprecated components,
encryption-compliance flags, and privacy descriptions. Runs offline against
fixtures. Standard-library only.

## What the engine genuinely does

- **Hand-rolled XML plist parser** — no `plistlib`; decodes `<dict>/<array>/
  <string>/<integer>/<true/<false>` key trees from raw XML.
- **ATS analysis** — `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsInWebContent`,
  per-domain `NSExceptionMinimumTLSVersion` and `NSExceptionRequiresForwardSecrecy`.
- **Data protection** — `UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace`.
- **Keychain scope** — wildcard `*` access group (CRITICAL), shared
  app-group / iCloud identifiers (MEDIUM).
- **Deprecated components** — `UIWebView` detection.
- **Encryption (EAR) compliance** — `ITSAppUsesNonExemptEncryption` states.
- **Vulnerability detection** — hashing/hardcoded-secret, jailbreak-detection
  hints, privacy-description inventory.
- **Findings** — severity-tagged JSON summary.

## Quick start

```bash
# Offline demo (assesses vulnerable+hardened fixture plists, writes reports/, exit 0)
python3 firmware/ios_assess.py

# Assess a real Info.plist
python3 firmware/ios_assess.py --plist Info.plist --json

# Rebuild fixtures
python3 firmware/ios_assess.py --make-fixture

# Tests
python3 -m unittest discover -s tests
```

## CLI

```
python3 firmware/ios_assess.py [-h] [-p PLIST] [--json] [--report-dir REPORT_DIR]
                               [--make-fixture]
```

- `--plist/-p` — path to an `Info.plist`; omitted → offline demo.
- `--json` — write JSON summary to `reports/`.
- `--report-dir` — report directory (default `reports`).
- `--make-fixture` — regenerate fixtures and exit.

Exit codes: `0` success (incl. demo), `2` input error.

## Live Lab Test Plan

Prerequisites: an IPA (or just an Info.plist) you own or are authorized to
audit — the fixture `com.example.vulnerableapp` stands in offline.

1. **Baseline**: `python3 firmware/ios_assess.py` — confirm vulnerable fixture
   yields ATS+keychain+deprecated findings while `hardened_Info.plist` yields
   < 5 low-severity findings.
2. **Real target**: pull the `Info.plist` from a permitted IPA
   (`unzip -p app.ipa Payload/App.app/Info.plist`) and run the assessor; verify
   every ATS exception against `plutil -p`.
3. **Differential**: remove `NSAllowsArbitraryLoads` and the wildcard keychain
   group from the vulnerable fixture and confirm the corresponding hints
   disappear (regression guard).
4. **JSON output**: confirm `reports/mo5_report.json` has `severity_counts` and
   the full findings array.
5. **Regression**: re-run `python3 -m unittest discover -s tests`.

## Metrics

| Metric                     | Value |
|----------------------------|-------|
| Standard-library only      | Yes   |
| Third-party deps           | none  |
| Deterministic offline tests| 18    |
| Fixtures                   | vulnerable + hardened Info.plist |
| Offline demo exit          | 0     |
| Report output              | `reports/*.json` (gitignored) |
| Inputs                     | Info.plist (XML) |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. See `LICENSE` for the full shield —
Authorization, CFAA / computer-crime statutes, Acceptable Use, Prohibited Use,
No Warranty, and Responsible Disclosure. Only assess apps you own or are
explicitly authorized to audit.

## License

MIT — full legal shield in `LICENSE`.