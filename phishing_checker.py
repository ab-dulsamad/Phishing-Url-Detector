"""
Phishing URL Awareness Checker - Core Detection Engine
======================================================
Author: Cybersecurity & Software Engineering Project Team
Purpose: Educational URL text inspection tool to identify suspicious patterns
         commonly found in phishing attacks.

SECURITY NOTICE:
This tool performs pure static lexical/textual inspection of the supplied URL string.
It NEVER connects to external networks, NEVER visits websites, and NEVER sends user data.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit


class PhishingURLChecker:
    """Core static analysis engine for detecting suspicious patterns in URLs.

    Implements six standard phishing detection checks:
    1. @ Symbol Detection
    2. Long URL Detection (> 100 characters)
    3. IP Address as Hostname Detection (IPv4 / IPv6)
    4. Excessive Subdomain Detection (5 or more segments)
    5. Punycode Detection (xn--)
    6. Insecure HTTP Protocol Detection
    """

    # Educational risk assessment thresholds
    # LOW INDICATOR COUNT: 0 warning signs
    # MEDIUM RISK: 1 or 2 warning signs
    # HIGH RISK: 3 or more warning signs (multiple compounded indicators)
    RISK_LEVEL_LOW = "LOW INDICATOR COUNT"
    RISK_LEVEL_MEDIUM = "MEDIUM RISK"
    RISK_LEVEL_HIGH = "HIGH RISK"

    MANDATORY_DISCLAIMER = (
        "No warning signs detected does NOT guarantee that this URL is safe. "
        "Risk levels are educational indicators, not verified threat classifications."
    )

    def __init__(self, length_threshold: int = 100, subdomain_threshold: int = 5):
        """Initialize checker with standard thresholds.

        :param length_threshold: Character length cutoff for flagging long URLs.
        :param subdomain_threshold: Minimum number of dot-separated hostname segments to flag.
        """
        self.length_threshold = length_threshold
        self.subdomain_threshold = subdomain_threshold

    def parse_url_components(self, raw_url: str) -> Dict[str, Any]:
        """Safely extract scheme, authority, hostname, and path from a URL string.

        Handles missing schemes (e.g. 'example.com/login') gracefully for text inspection.
        """
        cleaned_url = raw_url.strip()

        # Check if URL starts with a valid URI scheme (e.g., http://, https://)
        scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(?://)?", cleaned_url)
        has_explicit_scheme = bool(scheme_match)

        # Prepend http:// for parsing if scheme is missing so urlsplit parses netloc correctly
        parse_target = cleaned_url if has_explicit_scheme else f"http://{cleaned_url}"
        split_result = urlsplit(parse_target)

        # Extract hostname and clean IPv6 bracket formatting
        hostname = split_result.hostname or ""
        hostname_clean = hostname.strip("[]").lower()

        return {
            "raw_url": cleaned_url,
            "has_explicit_scheme": has_explicit_scheme,
            "scheme": split_result.scheme.lower() if has_explicit_scheme else "",
            "netloc": split_result.netloc,
            "hostname": hostname_clean,
            "port": split_result.port,
            "path": split_result.path,
            "query": split_result.query,
            "fragment": split_result.fragment,
        }

    # -------------------------------------------------------------------------
    # Detection Check 1: @ Symbol Detection
    # -------------------------------------------------------------------------
    def check_at_symbol(self, url: str) -> Optional[Dict[str, Any]]:
        """Identify URLs containing an '@' symbol.

        Attack Vector:
        In URI specifications (RFC 3986), the '@' character separates user credentials
        from the destination host (e.g., http://trusted.com@evil.com). Attackers place
        trusted brand names before the '@' so victims assume they are on a legitimate site,
        while the browser actually routes the connection to the host after the '@'.
        """
        if "@" in url:
            # Extract context around the '@' symbol
            parts = url.split("@", 1)
            before_at = parts[0]
            after_at = parts[1] if len(parts) > 1 else ""
            return {
                "id": "at_symbol",
                "name": "@ Symbol Deception",
                "severity": "High",
                "technical_detail": f"Found '@' symbol at character index {url.find('@')}.",
                "description": (
                    "The URL contains an '@' character. In web URLs, characters before '@' "
                    "are treated as user authentication data, causing your browser to connect to "
                    "the host listed AFTER the '@' symbol instead."
                ),
                "risk_explanation": (
                    "Phishers often craft URLs like 'http://paypal.com@attacker-site.com' to deceive "
                    "users who skim the beginning of a URL and mistakenly believe they are visiting "
                    "a legitimate company."
                ),
                "educational_recommendation": (
                    "Never enter login credentials if a URL contains an '@' symbol in the address bar. "
                    "Verify the actual domain located after the '@' symbol."
                ),
            }
        return None

    # -------------------------------------------------------------------------
    # Detection Check 2: Long URL Detection
    # -------------------------------------------------------------------------
    def check_url_length(self, url: str) -> Optional[Dict[str, Any]]:
        """Flag URLs longer than 100 characters.

        Attack Vector:
        Attackers create excessively long URLs to hide suspicious domain names or parameters
        from the visible portion of mobile and desktop address bars, or to pass obfuscated
        redirection payloads.
        """
        length = len(url)
        if length > self.length_threshold:
            return {
                "id": "long_url",
                "name": "Excessive URL Length",
                "severity": "Medium",
                "technical_detail": f"URL length is {length} characters (threshold is {self.length_threshold}).",
                "description": (
                    f"The URL contains {length} characters, exceeding the 100-character awareness threshold. "
                    "Unusually long URLs are frequently used in phishing campaigns."
                ),
                "risk_explanation": (
                    "Cybercriminals craft long URLs to push the true destination domain out of view "
                    "on mobile screens and narrow address bars. They also embed long hex tokens or "
                    "nested redirect parameters to evade automated filters."
                ),
                "educational_recommendation": (
                    "Examine the actual base domain carefully. Use caution if a link from an email or "
                    "message is unusually long and crowded with obscure parameters."
                ),
            }
        return None

    # -------------------------------------------------------------------------
    # Detection Check 3: IP Address Detection
    # -------------------------------------------------------------------------
    def check_ip_address(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Identify IP addresses used as hostnames instead of registered domain names.

        Attack Vector:
        Reputable organizations use registered domain names (e.g., example.com) with
        managed SSL certificates. Phishers frequently host disposable attack pages
        directly on raw IP addresses to bypass domain registration costs, registrar takedowns,
        and domain reputation blacklists.
        """
        if not hostname:
            return None

        # Test if hostname parses as an IPv4 or IPv6 address
        try:
            ip_obj = ipaddress.ip_address(hostname)
            ip_version = f"IPv{ip_obj.version}"
            return {
                "id": "ip_address",
                "name": "Direct IP Address as Hostname",
                "severity": "High",
                "technical_detail": f"Detected raw {ip_version} address: '{hostname}'.",
                "description": (
                    f"The URL points directly to an {ip_version} address ({hostname}) rather than a "
                    "registered domain name."
                ),
                "risk_explanation": (
                    "Legitimate businesses almost never ask users to access portals via raw IP addresses. "
                    "Phishers use direct IPs to avoid domain registration records, bypass WHOIS verification, "
                    "and evade domain-level reputation blocklists."
                ),
                "educational_recommendation": (
                    "Do not enter personal information or passwords on any website identified only by a "
                    "numeric IP address. Legitimate organizations always use registered domain names."
                ),
            }
        except ValueError:
            # Not a valid IP address; normal domain hostname
            return None

    # -------------------------------------------------------------------------
    # Detection Check 4: Subdomain Detection
    # -------------------------------------------------------------------------
    def check_subdomains(self, hostname: str, is_ip: bool = False) -> Optional[Dict[str, Any]]:
        """Flag hostnames containing five or more segments (e.g., a.b.c.d.e.example.invalid).

        Attack Vector:
        Attackers chain multiple subdomains together (e.g., paypal.com.account.verify.evil.com)
        so that naive users focus on the trusted brand name embedded in the subdomain prefix
        rather than the actual top-level domain at the end.
        """
        # IP addresses naturally contain 4 dot-separated octets, not subdomains
        if is_ip or not hostname:
            return None

        segments = [seg for seg in hostname.split(".") if seg]
        segment_count = len(segments)

        if segment_count >= self.subdomain_threshold:
            return {
                "id": "subdomain_chain",
                "name": "Excessive Subdomain Segments",
                "severity": "Medium",
                "technical_detail": (
                    f"Hostname contains {segment_count} dot-separated segments "
                    f"(threshold is {self.subdomain_threshold}): [{', '.join(segments)}]."
                ),
                "description": (
                    f"The hostname consists of {segment_count} segments. Legitimate web hosts rarely "
                    "use 5 or more levels of subdomains for user-facing links."
                ),
                "risk_explanation": (
                    "Attackers prepend authentic brand names as subdomains "
                    "(e.g., 'chase.com.security.verify.phishingsite.com') to trick mobile users who only see "
                    "the first few characters in their screen's truncated address bar."
                ),
                "educational_recommendation": (
                    "Read the domain name from right to left (starting just before the first slash) to determine "
                    "the genuine root domain, ignoring deceptive subdomains placed at the front."
                ),
            }
        return None

    # -------------------------------------------------------------------------
    # Detection Check 5: Punycode Detection
    # -------------------------------------------------------------------------
    def check_punycode(self, hostname: str, raw_url: str) -> Optional[Dict[str, Any]]:
        """Detect hostnames containing 'xn--' (Punycode encoding).

        Attack Vector:
        Punycode represents Internationalized Domain Names (IDNs) in ASCII. Attackers exploit
        IDN homograph attacks by substituting Latin letters with visually indistinguishable
        Cyrillic or Greek glyphs (e.g., Cyrillic 'а' U+0430 for Latin 'a' U+0061).
        When translated by the browser, the domain begins with 'xn--' (e.g., xn--pple-43d.com).
        """
        lower_host = hostname.lower()
        lower_url = raw_url.lower()

        if "xn--" in lower_host or "xn--" in lower_url:
            # Find the punycode label if possible
            labels = [lbl for lbl in lower_host.split(".") if "xn--" in lbl]
            detail_label = ", ".join(labels) if labels else "xn-- detected in URL string"

            return {
                "id": "punycode",
                "name": "Punycode (IDN Homograph) Indicator",
                "severity": "High",
                "technical_detail": f"Punycode prefix 'xn--' found in domain: {detail_label}.",
                "description": (
                    "The hostname contains 'xn--', which indicates Punycode encoding for non-ASCII "
                    "international characters."
                ),
                "risk_explanation": (
                    "Phishers exploit Internationalized Domain Names (IDNs) in 'homograph attacks' by "
                    "swapping Latin letters with lookalike Cyrillic or Greek characters (e.g., replacing 'o' with "
                    "Cyrillic '\u043e'). In the background, the actual registered domain uses the 'xn--' prefix."
                ),
                "educational_recommendation": (
                    "Be extremely wary of links containing 'xn--' unless you specifically expect an "
                    "internationalized domain in a local non-Latin script. Attackers use this to mimic trusted brands."
                ),
            }
        return None

    # -------------------------------------------------------------------------
    # Detection Check 6: HTTP Detection
    # -------------------------------------------------------------------------
    def check_http_protocol(self, parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Identify URLs using unencrypted HTTP instead of secure HTTPS.

        Attack Vector:
        HTTP transmits data in plaintext without cryptographic integrity or identity verification.
        Any intermediary can intercept or modify data in transit. Modern trusted sites enforce HTTPS.
        """
        scheme = parsed.get("scheme", "")
        raw_url = parsed.get("raw_url", "")

        # Flag if scheme is explicitly http, or URL begins with http:// (not https://)
        is_http = scheme == "http" or (
            raw_url.lower().startswith("http://") and not raw_url.lower().startswith("https://")
        )

        if is_http:
            return {
                "id": "http_protocol",
                "name": "Insecure HTTP Protocol",
                "severity": "Medium",
                "technical_detail": "URL protocol is 'http://' (unencrypted plaintext).",
                "description": (
                    "The URL uses the unencrypted HTTP protocol instead of modern, encrypted HTTPS."
                ),
                "risk_explanation": (
                    "HTTP connections do not encrypt communications or authenticate the web server. "
                    "Traffic can be intercepted or manipulated via Man-in-the-Middle (MitM) attacks. "
                    "Reputable login and banking services invariably mandate HTTPS."
                ),
                "educational_recommendation": (
                    "Never enter passwords, banking details, or sensitive personal information on any website "
                    "using HTTP. Look for 'https://' and a valid security certificate."
                ),
            }
        return None

    # -------------------------------------------------------------------------
    # Full Analysis Pipeline
    # -------------------------------------------------------------------------
    def analyze(self, url: str) -> Dict[str, Any]:
        """Perform all 6 detection checks on a URL string and return risk evaluation."""
        if not url or not url.strip():
            return {
                "url": "",
                "valid": False,
                "error": "URL cannot be empty. Please provide a URL string to inspect.",
                "risk_level": "INVALID INPUT",
                "warning_count": 0,
                "warnings": [],
                "passed_checks": [],
                "recommendations": [],
                "disclaimer": self.MANDATORY_DISCLAIMER,
            }

        cleaned_url = url.strip()
        parsed = self.parse_url_components(cleaned_url)
        hostname = parsed["hostname"]

        # Run Check 3 (IP check) first so subdomain check knows if host is an IP
        ip_warning = self.check_ip_address(hostname)
        is_ip = ip_warning is not None

        # Execute all 6 detection checks
        raw_checks = [
            ("check_at_symbol", self.check_at_symbol(cleaned_url), "@ Symbol Deception"),
            ("check_url_length", self.check_url_length(cleaned_url), "URL Length Limit (100 chars)"),
            ("check_ip_address", ip_warning, "Domain Name vs. Raw IP Hostname"),
            ("check_subdomains", self.check_subdomains(hostname, is_ip=is_ip), "Subdomain Segment Count (<5)"),
            ("check_punycode", self.check_punycode(hostname, cleaned_url), "Punycode (xn--) Homograph Detection"),
            ("check_http_protocol", self.check_http_protocol(parsed), "Transport Security (HTTPS vs. HTTP)"),
        ]

        warnings: List[Dict[str, Any]] = []
        passed_checks: List[Dict[str, str]] = []

        for check_key, result, check_label in raw_checks:
            if result:
                warnings.append(result)
            else:
                passed_checks.append({
                    "id": check_key,
                    "name": check_label,
                    "status": "Passed (No anomaly detected)",
                })

        warning_count = len(warnings)

        # Risk Assessment Classification based on prompt requirements:
        # - LOW INDICATOR COUNT: No listed warning signs detected (0 warnings)
        # - MEDIUM RISK: One or two warning signs detected (1 or 2 warnings)
        # - HIGH RISK: Multiple warning signs detected (3 or more warnings)
        if warning_count == 0:
            risk_level = self.RISK_LEVEL_LOW
            risk_class = "low"
            risk_summary = "No listed suspicious characteristics detected in this URL's static structure."
        elif 1 <= warning_count <= 2:
            risk_level = self.RISK_LEVEL_MEDIUM
            risk_class = "medium"
            risk_summary = f"{warning_count} suspicious indicator(s) identified. Exercise heightened caution."
        else:
            risk_level = self.RISK_LEVEL_HIGH
            risk_class = "high"
            risk_summary = f"{warning_count} suspicious indicators compounded. Highly characteristic of deceptive links."

        # Educational recommendations
        recommendations = self._generate_recommendations(warnings, warning_count)

        return {
            "url": cleaned_url,
            "valid": True,
            "parsed_components": {
                "scheme": parsed["scheme"] or "(not specified)",
                "hostname": parsed["hostname"] or "(not specified)",
                "length": len(cleaned_url),
                "is_ip": is_ip,
            },
            "risk_level": risk_level,
            "risk_class": risk_class,
            "risk_summary": risk_summary,
            "warning_count": warning_count,
            "total_checks": 6,
            "warnings": warnings,
            "passed_checks": passed_checks,
            "recommendations": recommendations,
            "disclaimer": self.MANDATORY_DISCLAIMER,
        }

    def _generate_recommendations(
        self, warnings: List[Dict[str, Any]], count: int
    ) -> List[str]:
        """Compile actionable cyber hygiene recommendations for the user."""
        recs: List[str] = []

        warning_ids = {w["id"] for w in warnings}

        if "http_protocol" in warning_ids:
            recs.append("Verify the website uses HTTPS before entering any login or payment information.")

        if "at_symbol" in warning_ids:
            recs.append("Carefully verify the domain name after the '@' symbol; do not trust brand names placed before it.")

        if "ip_address" in warning_ids:
            recs.append("Avoid accessing critical services via raw numeric IP addresses. Look for the official domain name.")

        if "subdomain_chain" in warning_ids:
            recs.append("Inspect the root domain directly adjacent to the first single slash (/), ignoring preceding subdomain labels.")

        if "punycode" in warning_ids:
            recs.append("Check for IDN homograph spoofing: ensure character sets match your expected language and company domain.")

        if "long_url" in warning_ids:
            recs.append("Examine long URLs in a plain-text editor before clicking, to view the complete destination without clipping.")

        # Baseline cyber defense recommendations
        if count == 0:
            recs.append("Remember that legitimate-looking URLs can still point to compromised sites or newly registered phishing domains.")
            recs.append("Always navigate directly to official websites by typing known URLs or using trusted bookmarks.")
        else:
            recs.append("If this link was received in an unsolicited email or SMS, do NOT click it; verify with the sender independently.")
            recs.append("Utilize a password manager, which automatically refuses to auto-fill credentials on spoofed domains.")

        return recs


def analyze_url(url: str) -> Dict[str, Any]:
    """Convenience function to analyze a URL with default checker configuration."""
    checker = PhishingURLChecker()
    return checker.analyze(url)


# -----------------------------------------------------------------------------
# Terminal CLI Demonstration Mode
# -----------------------------------------------------------------------------
def run_cli():
    """Command-line interface for testing and interactive terminal demonstrations."""
    import sys

    checker = PhishingURLChecker()

    print("=" * 72)
    print("      CYBERSECURITY TOOL: PHISHING URL AWARENESS CHECKER")
    print("          Educational URL Static Text Inspection Engine")
    print("=" * 72)
    print("NOTE: Performs local static text inspection only (0 network requests).\n")

    # If URL provided as argument: python phishing_checker.py <URL>
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        _print_cli_result(checker.analyze(target_url))
        return

    # Interactive mode
    benchmark_samples = [
        ("1", "https://www.example.com/login", "Sample 1: Standard HTTPS Domain"),
        ("2", "http://192.0.2.10/account", "Sample 2: Raw IP Hostname + HTTP"),
        ("3", "http://example.com@sample.invalid/login", "Sample 3: @ Symbol Credential Trick"),
        ("4", "https://a.b.c.d.e.example.invalid/path", "Sample 4: Excessive Subdomains (5+)"),
        ("5", "https://xn--example.invalid/", "Sample 5: Punycode (IDN Homograph)"),
    ]

    while True:
        print("-" * 72)
        print("Choose an option:")
        for key, sample_url, desc in benchmark_samples:
            print(f"  [{key}] Test {desc} -> {sample_url}")
        print("  [C] Custom URL (type any URL)")
        print("  [Q] Quit")
        choice = input("\nEnter choice [1-5, C, Q]: ").strip().lower()

        if choice == "q":
            print("\nExiting Phishing URL Awareness Checker. Stay safe online!")
            break
        elif choice in {"1", "2", "3", "4", "5"}:
            selected_url = benchmark_samples[int(choice) - 1][1]
            print(f"\nAnalyzing benchmark URL: {selected_url}")
            _print_cli_result(checker.analyze(selected_url))
        elif choice == "c":
            custom_url = input("\nEnter custom URL to inspect: ").strip()
            if custom_url:
                _print_cli_result(checker.analyze(custom_url))
            else:
                print("Empty URL entered.")
        else:
            print("Invalid selection. Please choose 1-5, C, or Q.")


def _print_cli_result(res: Dict[str, Any]):
    """Format and print analysis result to terminal."""
    if not res.get("valid"):
        print(f"\n[!] Error: {res.get('error')}\n")
        return

    risk = res["risk_level"]
    count = res["warning_count"]

    color_prefix = ""
    if risk == "HIGH RISK":
        badge = f"[!!! {risk} !!!]"
    elif risk == "MEDIUM RISK":
        badge = f"[** {risk} **]"
    else:
        badge = f"[OK: {risk}]"

    print("\n" + "=" * 72)
    print(f"TARGET URL: {res['url']}")
    print(f"LENGTH    : {res['parsed_components']['length']} characters")
    print(f"STATUS    : {badge} ({count} warning indicators detected)")
    print(f"SUMMARY   : {res['risk_summary']}")
    print("-" * 72)

    if count > 0:
        print("\n--- DETECTED WARNING SIGNS ---")
        for idx, w in enumerate(res["warnings"], 1):
            print(f"\n[{idx}] {w['name']} (Severity: {w['severity']})")
            print(f"    - Detail : {w['technical_detail']}")
            print(f"    - What   : {w['description']}")
            print(f"    - Threat : {w['risk_explanation']}")
    else:
        print("\n--- PASSED INSPECTION CHECKS ---")
        for p in res["passed_checks"]:
            print(f"  [+] {p['name']}: {p['status']}")

    print("\n--- SECURITY RECOMMENDATIONS ---")
    for r in res["recommendations"]:
        print(f"  * {r}")

    print("\n--- MANDATORY DISCLAIMER ---")
    print(f"  {res['disclaimer']}")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    run_cli()

