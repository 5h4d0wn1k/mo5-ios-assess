# MO5 — iOS Security Assessment

Info.plist security assessment for iOS app transport security, data protection, and compliance.

## Overview

This project implements an iOS app security assessor that:
- Parses Info.plist XML and extracts all configuration values
- Checks App Transport Security (ATS) exceptions and TLS enforcement
- Detects missing data protection flags (NSFileProtectionNone, UIFileSharingEnabled)
- Flags keychain access-group over-privilege including wildcard groups
- Identifies deprecated UIWebView usage
- Checks encryption compliance flags (ITSAppUsesNonExemptEncryption)
- Detects jailbreak-detection presence hints
- Reviews privacy usage description completeness

## Features

- **ATS Analysis**: NSAllowsArbitraryLoads, exception domains, TLS version, forward secrecy
- **Data Protection**: UIFileSharingEnabled, LSSupportsOpeningDocumentsInPlace
- **Keychain Audit**: Access group enumeration, wildcard detection, shared groups
- **Deprecated Components**: UIWebView detection with migration guidance
- **Encryption Compliance**: EAR/EE exemption flag verification
- **Jailbreak Detection**: Plist-level indicator scanning
- **Privacy Descriptions**: Coverage check for required usage descriptions

## Dependencies

**None** — uses only Python standard library (`xml.etree.ElementTree`, `re`, `argparse`, `collections`).

## Installation

```bash
# No external dependencies required
python3 ios_assess.py
```

## Usage

```bash
# Run demo with embedded sample plist
python3 ios_assess.py

# Assess a specific Info.plist
python3 ios_assess.py --plist Info.plist
```

## Example Output

```
============================================================
  MO5 — iOS Security Assessment
============================================================
  Info.plist Security Analysis

============================================================
  APP TRANSPORT SECURITY (ATS)
============================================================
  [!!] CRITICAL: NSAllowsArbitraryLoads=true — ATS fully disabled
  [!!] HIGH: example.com allows TLSv1.0 (should be TLSv1.2+)
  [!!] MEDIUM: example.com — forward secrecy not required

============================================================
  KEYCHAIN ACCESS GROUPS
============================================================
  [!!] CRITICAL: Wildcard keychain access group (*) — shares keychain with all apps

============================================================
  DEPRECATED COMPONENTS
============================================================
  [!!] HIGH: UIWebView present — deprecated, use WKWebView

  iOS SECURITY ASSESSMENT SUMMARY
  CRITICAL  : 2
  HIGH      : 2
  MEDIUM    : 2
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the app owner before using this tool
- Unauthorized reverse engineering of iOS apps may violate applicable laws
- This tool should ONLY be used on apps you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **DMCA (17 U.S.C. § 1201)**: Circumventing software protection measures may violate copyright law
- **Apple Developer Agreement**: Reverse engineering restrictions apply to App Store apps
- **State Laws**: Many states have additional computer crime and reverse engineering statutes

### Acceptable Use
- Security assessment of your own iOS applications
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Scanning or reverse engineering apps you do not own
- Distributing exploits or vulnerability details publicly
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the app developer privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
