#!/usr/bin/env python3
"""Deterministic offline tests for MO5 — iOS plist security assessment."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import firmware.ios_assess as mo5
from firmware.ios_assess import IOSAppAssessor, create_fixtures, FIXTURE_HARDENED_PLIST


class TestPlistParsing(unittest.TestCase):
    def test_parses_scalar_types(self):
        a = IOSAppAssessor(mo5.SAMPLE_PLIST)
        self.assertTrue(a.parse_plist())
        self.assertEqual(a.plist_data["CFBundleIdentifier"], "com.example.vulnerableapp")
        self.assertIs(a.plist_data["UIFileSharingEnabled"], True)
        self.assertEqual(a.plist_data["CFBundleVersion"], "1.0")

    def test_parses_nested_dict_and_array(self):
        a = IOSAppAssessor(mo5.SAMPLE_PLIST)
        a.parse_plist()
        ats = a.plist_data["NSAppTransportSecurity"]
        self.assertIs(ats["NSAllowsArbitraryLoads"], True)
        self.assertIs(ats["NSExceptionDomains"]["example.com"]["NSExceptionRequiresForwardSecrecy"], False)
        groups = a.plist_data["keychain-access-groups"]
        self.assertIn("*", groups)

    def test_invalid_plist_records_critical(self):
        a = IOSAppAssessor("<dict><key>k</dict")
        self.assertFalse(a.parse_plist())
        cats = {f["category"] for f in a.findings}
        self.assertIn("parse_error", cats)

    def test_empty_dict_default(self):
        a = IOSAppAssessor("<plist><dict/></plist>")
        self.assertTrue(a.parse_plist())
        self.assertEqual(a.plist_data, {})


class TestVulnerableFindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = IOSAppAssessor(mo5.SAMPLE_PLIST)
        cls.a.run()

    def test_ats_arbitrary_loads_critical(self):
        ats = [f for f in self.a.findings if f["category"] == "ats"]
        self.assertGreater(len(ats), 0)

    def test_ats_findings(self):
        ats = [f for f in self.a.findings if f["category"] == "ats"]
        self.assertTrue(any("ArbitraryLoads" in f["detail"] for f in ats))
        self.assertTrue(any("TLSv1.0" in f["detail"] for f in ats))

    def test_keychain_wildcard(self):
        kc = [f for f in self.a.findings if f["category"] == "keychain"]
        self.assertTrue(any("Wildcard" in f["detail"] for f in kc))

    def test_deprecated_uiwebview(self):
        dep = [f for f in self.a.findings if f["category"] == "deprecated"]
        self.assertTrue(any("UIWebView" in f["detail"] for f in dep))

    def test_data_protection_file_sharing(self):
        dp = [f for f in self.a.findings if f["category"] == "data_protection"]
        self.assertTrue(any("FileSharing" in f["detail"] for f in dp))

    def test_exemption_flag(self):
        enc = [f for f in self.a.findings if f["category"] == "encryption"]
        self.assertTrue(any("ITSAppUsesNonExemptEncryption" in f["detail"] for f in enc))

    def test_summary_jsonable(self):
        s = self.a.summary()
        json.dumps(s)
        self.assertEqual(s["bundle_id"], "com.example.vulnerableapp")


class TestHardenedPlist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = IOSAppAssessor(FIXTURE_HARDENED_PLIST)
        cls.a.run()

    def test_no_ats_critical(self):
        for f in self.a.findings:
            self.assertNotEqual(f["category"], "ats")

    def test_no_wildcard_keychain(self):
        for f in self.a.findings:
            self.assertNotEqual(f["category"], "keychain")

    def test_no_uiwebview(self):
        for f in self.a.findings:
            self.assertNotEqual(f["category"], "deprecated")

    def test_few_findings(self):
        self.assertLess(len(self.a.findings), 5)


class TestVisitSecurityBypass(unittest.TestCase):
    def test_ats_webcontent_high(self):
        text = mo5.SAMPLE_PLIST.replace(
            "<key>NSExceptionDomains</key>",
            "<key>NSAllowsArbitraryLoadsInWebContent</key><true/><key>NSExceptionDomains</key>")
        a = IOSAppAssessor(text)
        a.run()
        ats = [f for f in a.findings if f["category"] == "ats"]
        self.assertTrue(any("WebContent" in f["detail"] for f in ats))


class TestFixturesAndDemo(unittest.TestCase):
    def test_fixture_factory(self):
        with tempfile.TemporaryDirectory() as tmp:
            created = create_fixtures(tmp)
            self.assertEqual(len(created), 2)
            self.assertTrue(os.path.exists(os.path.join(tmp, "vulnerable_Info.plist")))

    def test_demo_exits_zero_with_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = mo5.run_demo(os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            report = os.path.join(tmp, "reports", "mo5_demo_report.json")
            self.assertTrue(os.path.exists(report))
            with open(report) as f:
                data = json.load(f)
            self.assertIn("vulnerable_Info.plist", data)
            self.assertIn("hardened_Info.plist", data)
            self.assertGreater(len(data["vulnerable_Info.plist"]["findings"]),
                               len(data["hardened_Info.plist"]["findings"]))


if __name__ == "__main__":
    unittest.main()