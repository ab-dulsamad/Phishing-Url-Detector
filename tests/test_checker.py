"""
Automated Unit Tests for Phishing URL Awareness Checker
======================================================
Tests all 6 detection rules, the 5 required benchmark sample URLs,
edge cases, and risk scoring logic.
"""

import unittest
from phishing_checker import PhishingURLChecker, analyze_url


class TestPhishingDetectionRules(unittest.TestCase):
    def setUp(self):
        self.checker = PhishingURLChecker(length_threshold=100, subdomain_threshold=5)

    # -------------------------------------------------------------------------
    # 1. @ Symbol Detection Tests
    # -------------------------------------------------------------------------
    def test_at_symbol_present(self):
        res = self.checker.check_at_symbol("http://paypal.com@malicious.invalid/login")
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], "at_symbol")
        self.assertEqual(res["severity"], "High")

    def test_at_symbol_absent(self):
        res = self.checker.check_at_symbol("https://paypal.com/login")
        self.assertIsNone(res)

    # -------------------------------------------------------------------------
    # 2. Long URL Detection Tests (> 100 characters)
    # -------------------------------------------------------------------------
    def test_long_url_exceeds_threshold(self):
        # 105 characters
        long_url = "https://example.com/" + "a" * 85
        self.assertGreater(len(long_url), 100)
        res = self.checker.check_url_length(long_url)
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], "long_url")

    def test_long_url_under_threshold(self):
        # Under 100 characters
        short_url = "https://example.com/login"
        res = self.checker.check_url_length(short_url)
        self.assertIsNone(res)

    def test_long_url_exact_boundary(self):
        # Exactly 100 characters should not trigger (threshold is > 100)
        exact_100_url = "https://" + "x" * 92
        self.assertEqual(len(exact_100_url), 100)
        res = self.checker.check_url_length(exact_100_url)
        self.assertIsNone(res)

    # -------------------------------------------------------------------------
    # 3. IP Address Detection Tests (IPv4 / IPv6)
    # -------------------------------------------------------------------------
    def test_ipv4_address_as_hostname(self):
        res = self.checker.check_ip_address("192.0.2.10")
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], "ip_address")
        self.assertIn("IPv4", res["technical_detail"])

    def test_ipv6_address_as_hostname(self):
        # IPv6 format stripped of brackets
        res = self.checker.check_ip_address("2001:db8::1")
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], "ip_address")
        self.assertIn("IPv6", res["technical_detail"])

    def test_domain_is_not_ip_address(self):
        res = self.checker.check_ip_address("example.com")
        self.assertIsNone(res)

    # -------------------------------------------------------------------------
    # 4. Subdomain Detection Tests (>= 5 segments)
    # -------------------------------------------------------------------------
    def test_subdomains_five_or_more(self):
        # 7 segments: a, b, c, d, e, example, invalid
        res = self.checker.check_subdomains("a.b.c.d.e.example.invalid", is_ip=False)
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], "subdomain_chain")
        self.assertIn("7 dot-separated segments", res["technical_detail"])

    def test_subdomains_exactly_five(self):
        # 5 segments: one, two, three, example, com
        res = self.checker.check_subdomains("one.two.three.example.com", is_ip=False)
        self.assertIsNotNone(res)

    def test_subdomains_four_or_fewer(self):
        # 3 segments: www.example.com
        res = self.checker.check_subdomains("www.example.com", is_ip=False)
        self.assertIsNone(res)

    def test_ip_address_not_flagged_as_subdomain(self):
        # An IPv4 like 192.0.2.10 has 4 octets, but is an IP, not subdomains
        res = self.checker.check_subdomains("192.0.2.10", is_ip=True)
        self.assertIsNone(res)

    # -------------------------------------------------------------------------
    # 5. Punycode Detection Tests (xn--)
    # -------------------------------------------------------------------------
    def test_punycode_detected(self):
        res = self.checker.check_punycode("xn--example.invalid", "https://xn--example.invalid/")
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], "punycode")

    def test_punycode_absent(self):
        res = self.checker.check_punycode("example.com", "https://example.com")
        self.assertIsNone(res)

    # -------------------------------------------------------------------------
    # 6. HTTP Detection Tests
    # -------------------------------------------------------------------------
    def test_http_protocol_flagged(self):
        parsed = self.checker.parse_url_components("http://example.com")
        res = self.checker.check_http_protocol(parsed)
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], "http_protocol")

    def test_https_protocol_passes(self):
        parsed = self.checker.parse_url_components("https://example.com")
        res = self.checker.check_http_protocol(parsed)
        self.assertIsNone(res)


class TestRequiredBenchmarkSamples(unittest.TestCase):
    """Verifies all five required benchmark URLs from Requirement 7."""

    def setUp(self):
        self.checker = PhishingURLChecker()

    def test_sample_1_legitimate(self):
        """1. https://www.example.com/login -> LOW INDICATOR COUNT (0 warnings)"""
        url = "https://www.example.com/login"
        res = self.checker.analyze(url)
        self.assertEqual(res["risk_level"], "LOW INDICATOR COUNT")
        self.assertEqual(res["warning_count"], 0)
        self.assertIn("No warning signs detected does NOT guarantee", res["disclaimer"])

    def test_sample_2_ip_address_and_http(self):
        """2. http://192.0.2.10/account -> MEDIUM RISK (2 warnings: IP + HTTP)"""
        url = "http://192.0.2.10/account"
        res = self.checker.analyze(url)
        self.assertEqual(res["risk_level"], "MEDIUM RISK")
        self.assertEqual(res["warning_count"], 2)
        warning_ids = [w["id"] for w in res["warnings"]]
        self.assertIn("ip_address", warning_ids)
        self.assertIn("http_protocol", warning_ids)

    def test_sample_3_at_symbol_and_http(self):
        """3. http://example.com@sample.invalid/login -> MEDIUM RISK (2 warnings: @ + HTTP)"""
        url = "http://example.com@sample.invalid/login"
        res = self.checker.analyze(url)
        self.assertEqual(res["risk_level"], "MEDIUM RISK")
        self.assertEqual(res["warning_count"], 2)
        warning_ids = [w["id"] for w in res["warnings"]]
        self.assertIn("at_symbol", warning_ids)
        self.assertIn("http_protocol", warning_ids)

    def test_sample_4_excessive_subdomains(self):
        """4. https://a.b.c.d.e.example.invalid/path -> MEDIUM RISK (1 warning: Subdomains)"""
        url = "https://a.b.c.d.e.example.invalid/path"
        res = self.checker.analyze(url)
        self.assertEqual(res["risk_level"], "MEDIUM RISK")
        self.assertEqual(res["warning_count"], 1)
        warning_ids = [w["id"] for w in res["warnings"]]
        self.assertIn("subdomain_chain", warning_ids)

    def test_sample_5_punycode(self):
        """5. https://xn--example.invalid/ -> MEDIUM RISK (1 warning: Punycode)"""
        url = "https://xn--example.invalid/"
        res = self.checker.analyze(url)
        self.assertEqual(res["risk_level"], "MEDIUM RISK")
        self.assertEqual(res["warning_count"], 1)
        warning_ids = [w["id"] for w in res["warnings"]]
        self.assertIn("punycode", warning_ids)

    def test_high_risk_multi_indicator(self):
        """Extra: Test multi-indicator URL triggering HIGH RISK (>= 3 warnings)"""
        url = (
            "http://admin@192.0.2.10/security-portal/verify-credentials?"
            "redirect=http://attacker.com/session/token/long-string-padding-out-url-over-one-hundred-characters"
        )
        res = self.checker.analyze(url)
        self.assertEqual(res["risk_level"], "HIGH RISK")
        self.assertGreaterEqual(res["warning_count"], 3)


class TestEdgeCasesAndSafety(unittest.TestCase):
    """Verifies robustness with blank inputs, whitespace, and safety disclaimers."""

    def test_empty_string(self):
        res = analyze_url("")
        self.assertFalse(res["valid"])
        self.assertEqual(res["warning_count"], 0)
        self.assertIn("disclaimer", res)

    def test_whitespace_string(self):
        res = analyze_url("   \n\t  ")
        self.assertFalse(res["valid"])

    def test_disclaimer_always_present(self):
        res = analyze_url("https://www.google.com")
        self.assertIn("No warning signs detected does NOT guarantee that this URL is safe.", res["disclaimer"])


if __name__ == "__main__":
    unittest.main()

