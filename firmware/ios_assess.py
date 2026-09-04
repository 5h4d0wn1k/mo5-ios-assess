#!/usr/bin/env python3
"""
MO5 — iOS Security Assessment
Evaluates iOS app Info.plist for security misconfigurations

Features:
- Parse Info.plist XML and check ATS exceptions
- Detect missing data protection (NSFileProtectionNone)
- Flag keychain access-group over-privilege
- Identify deprecated UIWebView usage
- Check encryption compliance flags
- Detect jailbreak-detection presence hints

Usage:
    python3 ios_assess.py
    python3 ios_assess.py --plist Info.plist

WARNING: Educational use only. Only assess apps you own or are authorized to audit.
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

SAMPLE_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>VulnerableApp</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.vulnerableapp</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>

    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
        <key>NSExceptionDomains</key>
        <dict>
            <key>example.com</key>
            <dict>
                <key>NSExceptionRequiresForwardSecrecy</key>
                <false/>
                <key>NSExceptionMinimumTLSVersion</key>
                <string>TLSv1.0</string>
            </dict>
        </dict>
    </dict>

    <key>UIFileSharingEnabled</key>
    <true/>
    <key>LSSupportsOpeningDocumentsInPlace</key>
    <true/>

    <key>UIWebView</key>
    <string>YES</string>

    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.example.vulnerableapp</string>
        <string>$(AppIdentifierPrefix)com.apple.security.application-groups</string>
        <string>com.apple.developer.icloud-container-identifiers</string>
        <string>*</string>
    </array>

    <key>UIRequiredDeviceCapabilities</key>
    <array>
        <string>armv7</string>
    </array>

    <key>ITSAppUsesNonExemptEncryption</key>
    <false/>

    <key>NSFaceIDUsageDescription</key>
    <string>Use Face ID for login</string>

    <key>NSCameraUsageDescription</key>
    <string>Scan documents</string>

    <key>NSMicrophoneUsageDescription</key>
    <string>Record audio</string>

    <key>NSLocationWhenInUseUsageDescription</key>
    <string>Find nearby stores</string>

    <key>NSLocationAlwaysUsageDescription</key>
    <string>Track your location</string>

    <key>NSContactsUsageDescription</key>
    <string>Import contacts</string>

    <key>NSPhotoLibraryUsageDescription</key>
    <string>Select photos</string>

    <key>NSHealthShareUsageDescription</key>
    <string>Read health data</string>

    <key>NSHealthUpdateUsageDescription</key>
    <string>Write health data</string>

    <key>NSBluetoothAlwaysUsageDescription</key>
    <string>Connect to devices</string>

    <key>UISupportsDocumentBrowser</key>
    <true/>

    <key>NSNetworkActivityIndicatorVisible</key>
    <true/>

    <key>UILaunchStoryboardName</key>
    <string>LaunchScreen</string>
</dict>
</plist>
"""

ATS_EXCEPTIONS = [
    "NSAllowsArbitraryLoads",
    "NSAllowsLocalNetworking",
    "NSExceptionRequiresForwardSecrecy",
    "NSExceptionMinimumTLSVersion",
    "NSAllowsArbitraryLoadsInWebContent",
]

PRIVACY_KEYS = [
    "NSCameraUsageDescription", "NSMicrophoneUsageDescription",
    "NSLocationWhenInUseUsageDescription", "NSLocationAlwaysUsageDescription",
    "NSContactsUsageDescription", "NSPhotoLibraryUsageDescription",
    "NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription",
    "NSBluetoothAlwaysUsageDescription", "NSFaceIDUsageDescription",
    "NSHomeKitUsageDescription", "NSSpeechRecognitionUsageDescription",
    "NSAppleMusicUsageDescription", "NSMotionUsageDescription",
]


class IOSAppAssessor:
    def __init__(self, plist_text=None):
        self.plist_text = plist_text or SAMPLE_PLIST
        self.findings = []
        self.plist_data = {}

    def parse_plist(self):
        print("\n" + "=" * 60)
        print("  PARSING INFO.PLIST")
        print("=" * 60)

        try:
            self.plist_data = self._parse_plist_xml(self.plist_text)
            bundle_id = self.plist_data.get("CFBundleIdentifier", "unknown")
            version = self.plist_data.get("CFBundleShortVersionString", "unknown")
            print(f"  Bundle ID: {bundle_id}")
            print(f"  Version: {version}")
            return True
        except Exception as e:
            print(f"  ERROR: Failed to parse plist: {e}")
            self.findings.append({"severity": "CRITICAL", "category": "parse_error", "detail": str(e)})
            return False

    def _parse_plist_xml(self, text):
        result = {}
        try:
            root = ET.fromstring(text)
            dict_elem = root if root.tag == "dict" else root.find("dict")
            if dict_elem is None:
                return result
            children = list(dict_elem)
            i = 0
            while i < len(children) - 1:
                if children[i].tag == "key":
                    key = children[i].text or ""
                    value_elem = children[i + 1]
                    result[key] = self._extract_value(value_elem)
                i += 2
        except ET.ParseError:
            pass
        return result

    def _extract_value(self, elem):
        tag = elem.tag
        if tag == "string":
            return elem.text or ""
        elif tag == "true":
            return True
        elif tag == "false":
            return False
        elif tag == "integer":
            return int(elem.text or "0")
        elif tag == "real":
            return float(elem.text or "0")
        elif tag == "array":
            return [self._extract_value(child) for child in elem]
        elif tag == "dict":
            return self._parse_plist_xml(ET.tostring(elem, encoding="unicode"))
        return None

    def check_ats(self):
        print("\n" + "=" * 60)
        print("  APP TRANSPORT SECURITY (ATS)")
        print("=" * 60)

        ats = self.plist_data.get("NSAppTransportSecurity", {})
        if not ats:
            print("  [OK] No ATS configuration found (default: secure)")
            return

        allows_arbitrary = ats.get("NSAllowsArbitraryLoads", False)
        if allows_arbitrary:
            self.findings.append({"severity": "CRITICAL", "category": "ats",
                                  "detail": "NSAllowsArbitraryLoads=true — disables ATS entirely"})
            print("  [!!] CRITICAL: NSAllowsArbitraryLoads=true — ATS fully disabled")

        allows_local = ats.get("NSAllowsLocalNetworking", False)
        if allows_local:
            print("  [OK] NSAllowsLocalNetworking=true (local only)")

        allows_web = ats.get("NSAllowsArbitraryLoadsInWebContent", False)
        if allows_web:
            self.findings.append({"severity": "HIGH", "category": "ats",
                                  "detail": "NSAllowsArbitraryLoadsInWebContent=true — weakens web content security"})
            print("  [!!] HIGH: NSAllowsArbitraryLoadsInWebContent=true")

        exception_domains = ats.get("NSExceptionDomains", {})
        if isinstance(exception_domains, dict):
            for domain, config in exception_domains.items():
                if isinstance(config, dict):
                    tls_version = config.get("NSExceptionMinimumTLSVersion", "")
                    fwd_secrecy = config.get("NSExceptionRequiresForwardSecrecy", True)
                    if tls_version and tls_version < "TLSv1.2":
                        self.findings.append({"severity": "HIGH", "category": "ats",
                                              "detail": f"Domain {domain}: minimum TLS {tls_version}"})
                        print(f"  [!!] HIGH: {domain} allows {tls_version} (should be TLSv1.2+)")
                    if fwd_secrecy is False:
                        self.findings.append({"severity": "MEDIUM", "category": "ats",
                                              "detail": f"Domain {domain}: forward secrecy not required"})
                        print(f"  [!!] MEDIUM: {domain} — forward secrecy not required")

        if not any(f["severity"] in ("CRITICAL", "HIGH") for f in self.findings if f["category"] == "ats"):
            print("  [OK] ATS configuration appears reasonable")

    def check_data_protection(self):
        print("\n" + "=" * 60)
        print("  DATA PROTECTION")
        print("=" * 60)

        file_sharing = self.plist_data.get("UIFileSharingEnabled", False)
        if file_sharing:
            self.findings.append({"severity": "HIGH", "category": "data_protection",
                                  "detail": "UIFileSharingEnabled=true — exposes Documents/ to iTunes"})
            print("  [!!] HIGH: UIFileSharingEnabled=true — Documents/ exposed via iTunes File Sharing")
        else:
            print("  [OK] UIFileSharingEnabled not set or false")

        docs_in_place = self.plist_data.get("LSSupportsOpeningDocumentsInPlace", False)
        if docs_in_place:
            self.findings.append({"severity": "MEDIUM", "category": "data_protection",
                                  "detail": "LSSupportsOpeningDocumentsInPlace=true — document access enabled"})
            print("  [!!] MEDIUM: LSSupportsOpeningDocumentsInPlace=true")

        doc_browser = self.plist_data.get("UISupportsDocumentBrowser", False)
        if doc_browser:
            print("  [INFO] UISupportsDocumentBrowser=true")

        if not file_sharing and not docs_in_place:
            print("  [OK] No file sharing or document access flags enabled")

    def check_keychain(self):
        print("\n" + "=" * 60)
        print("  KEYCHAIN ACCESS GROUPS")
        print("=" * 60)

        groups = self.plist_data.get("keychain-access-groups", [])
        if not groups:
            print("  [OK] No keychain access groups declared")
            return

        print(f"  Declared groups: {len(groups)}")
        for g in groups:
            print(f"    - {g}")

        if "*" in groups:
            self.findings.append({"severity": "CRITICAL", "category": "keychain",
                                  "detail": "Wildcard keychain access group (*) — shares keychain with all apps"})
            print("  [!!] CRITICAL: Wildcard (*) keychain group — all apps can share keychain items")

        shared_groups = [g for g in groups if "com.apple.security.application-groups" in g or "icloud" in g.lower()]
        if shared_groups:
            self.findings.append({"severity": "MEDIUM", "category": "keychain",
                                  "detail": f"Shared keychain groups present: {len(shared_groups)}"})
            print(f"  [!!] MEDIUM: {len(shared_groups)} shared keychain group(s) present")

        if not any(f["category"] == "keychain" for f in self.findings):
            print("  [OK] Keychain access groups appear scoped")

    def check_deprecated_components(self):
        print("\n" + "=" * 60)
        print("  DEPRECATED COMPONENTS")
        print("=" * 60)

        ui_webview = self.plist_data.get("UIWebView")
        if ui_webview:
            self.findings.append({"severity": "HIGH", "category": "deprecated",
                                  "detail": "UIWebView declared — deprecated since iOS 12, use WKWebView"})
            print("  [!!] HIGH: UIWebView present — deprecated, use WKWebView")
        else:
            print("  [OK] No UIWebView declaration found")

        network_activity = self.plist_data.get("NSNetworkActivityIndicatorVisible", False)
        if network_activity:
            print("  [INFO] NSNetworkActivityIndicatorVisible=true (cosmetic, removed in iOS 13+)")

    def check_encryption_compliance(self):
        print("\n" + "=" * 60)
        print("  ENCRYPTION COMPLIANCE (EAR/EE)")
        print("=" * 60)

        exempt = self.plist_data.get("ITSAppUsesNonExemptEncryption", None)
        if exempt is True:
            print("  [OK] ITSAppUsesNonExemptEncryption=true — exempt from export compliance")
        elif exempt is False:
            print("  [INFO] ITSAppUsesNonExemptEncryption=false — claims no exempt encryption")
            self.findings.append({"severity": "LOW", "category": "encryption",
                                  "detail": "ITSAppUsesNonExemptEncryption=false — verify crypto usage is correct"})
        else:
            self.findings.append({"severity": "MEDIUM", "category": "encryption",
                                  "detail": "ITSAppUsesNonExemptEncryption not set — may trigger App Store review"})
            print("  [!!] MEDIUM: ITSAppUsesNonExemptEncryption not set — App Store may require compliance docs")

    def check_jailbreak_detection_hints(self):
        print("\n" + "=" * 60)
        print("  JAILBREAK DETECTION HINTS")
        print("=" * 60)
        plist_str = self.plist_text.lower()

        indicators = ["skipbackup", "jailbreak", "cydia", "sileo", "frida", "substrate"]
        found = [ind for ind in indicators if ind in plist_str]

        if found:
            print(f"  [INFO] Jailbreak-related strings in plist: {', '.join(found)}")
        else:
            print("  [INFO] No jailbreak-detection hints found in plist")
            self.findings.append({"severity": "INFO", "category": "jailbreak",
                                  "detail": "No jailbreak detection indicators in Info.plist (check code separately)"})

    def check_privacy_descriptions(self):
        print("\n" + "=" * 60)
        print("  PRIVACY USAGE DESCRIPTIONS")
        print("=" * 60)

        present = []
        missing_recommended = []
        for key in PRIVACY_KEYS:
            val = self.plist_data.get(key)
            if val:
                present.append(key)
            else:
                missing_recommended.append(key)

        print(f"  Privacy keys present: {len(present)}")
        for k in present:
            print(f"    [OK] {k}")

        if missing_recommended:
            print(f"\n  Privacy keys not declared: {len(missing_recommended)}")
            for k in missing_recommended[:5]:
                print(f"    -- {k}")

    def generate_report(self):
        print("\n" + "=" * 60)
        print("  iOS SECURITY ASSESSMENT SUMMARY")
        print("=" * 60)
        sev_counts = defaultdict(int)
        for f in self.findings:
            sev_counts[f["severity"]] += 1

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev_counts[sev] > 0:
                print(f"  {sev:10s}: {sev_counts[sev]}")

        print(f"\n  Total findings: {len(self.findings)}")
        if self.findings:
            print("\n  Detailed findings:")
            for i, f in enumerate(self.findings, 1):
                print(f"    {i}. [{f['severity']}] {f['category']}: {f['detail']}")

        print("\n" + "=" * 60)

    def run(self):
        print("\n" + "=" * 60)
        print("  MO5 — iOS Security Assessment")
        print("=" * 60)
        print("  Info.plist Security Analysis")

        if not self.parse_plist():
            return self.findings

        self.check_ats()
        self.check_data_protection()
        self.check_keychain()
        self.check_deprecated_components()
        self.check_encryption_compliance()
        self.check_jailbreak_detection_hints()
        self.check_privacy_descriptions()
        self.generate_report()

        return self.findings


def main():
    parser = argparse.ArgumentParser(description="MO5 — iOS Security Assessment")
    parser.add_argument("--plist", "-p", help="Path to Info.plist (uses demo if omitted)")
    args = parser.parse_args()

    plist_text = None
    if args.plist:
        try:
            with open(args.plist) as f:
                plist_text = f.read()
            print(f"Loaded plist from: {args.plist}")
        except Exception as e:
            print(f"ERROR: Could not read plist: {e}")
            sys.exit(1)
    else:
        print("No plist provided — using embedded demo data")

    assessor = IOSAppAssessor(plist_text)
    findings = assessor.run()

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
