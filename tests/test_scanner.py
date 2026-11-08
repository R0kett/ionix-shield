#!/usr/bin/env python3
"""
Unit tests for R0cket-1 Cyber-Sentinel Scanner
"""
import unittest
from sentinel_scanner import analyze, audit_url, audit_text, detect_homoglyphs, calculate_entropy


class TestR0cket1(unittest.TestCase):
    def test_clean_url(self):
        res = analyze("https://github.com/milcham")
        self.assertEqual(res["verdict"], "SAIN")
        self.assertLess(res["score"], 2.0)

    def test_homoglyph_detection(self):
        # Using Cyrillic 'а' (U+0430)
        homos = detect_homoglyphs("pаypal.com")
        self.assertTrue(len(homos) > 0)
        res = analyze("http://pаypal.com-verify.xyz/auth")
        self.assertEqual(res["verdict"], "DANGER_CRITIQUE")
        self.assertGreaterEqual(res["score"], 5.0)

    def test_double_extension_trap(self):
        res = analyze("https://safe-documents.club/download/facture.pdf.dmg")
        self.assertEqual(res["verdict"], "DANGER_CRITIQUE")
        self.assertTrue(any("double extension" in s.lower() for s in res["signals"]))

    def test_social_engineering_urgency(self):
        text = "URGENT: Votre compte bancaire est suspendu sous 24h. Veuillez vérifier votre carte bancaire ici: http://bourso-securite.top"
        res = analyze(text)
        self.assertEqual(res["verdict"], "DANGER_CRITIQUE")
        self.assertTrue(any("blocage imminent" in s.lower() for s in res["signals"]))

    def test_shannon_entropy(self):
        normal_entropy = calculate_entropy("google")
        dga_entropy = calculate_entropy("xk89az1109qjklmz")
        self.assertGreater(dga_entropy, normal_entropy)


if __name__ == "__main__":
    unittest.main()
