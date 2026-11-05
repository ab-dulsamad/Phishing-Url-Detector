# Phishing URL Awareness Checker - Test Samples & Benchmark Results

This document records the official benchmark test suite for the **Phishing URL Awareness Checker**. All test cases are executed without sending network packets or contacting remote servers.

---

## Benchmark Test Summary Table

| Test Case | Sample URL | Detected Warning Signs | Count | Risk Assessment Result |
| :--- | :--- | :--- | :---: | :--- |
| **Sample 1** | `https://www.example.com/login` | None (All checks passed) | 0 | `LOW INDICATOR COUNT` |
| **Sample 2** | `http://192.0.2.10/account` | 1. Direct IP Address as Host<br>2. Insecure HTTP Protocol | 2 | `MEDIUM RISK` |
| **Sample 3** | `http://example.com@sample.invalid/login` | 1. @ Symbol Deception<br>2. Insecure HTTP Protocol | 2 | `MEDIUM RISK` |
| **Sample 4** | `https://a.b.c.d.e.example.invalid/path` | 1. Excessive Subdomain Segments (7 $\ge$ 5) | 1 | `MEDIUM RISK` |
| **Sample 5** | `https://xn--example.invalid/` | 1. Punycode (IDN Homograph) Indicator | 1 | `MEDIUM RISK` |
| **Sample 6 (Bonus)** | `http://admin@192.0.2.10/verify?redirect=http://attacker.com/session/token/long-string-padding-out-url-over-one-hundred-characters` | 1. @ Symbol Deception<br>2. Excessive URL Length (137 chars)<br>3. Direct IP Address as Host<br>4. Insecure HTTP Protocol | 4 | `HIGH RISK` |

---

## Detailed Benchmark Walkthrough

### 1. Sample 1: Baseline Legitimate Structure
- **URL**: `https://www.example.com/login`
- **Scheme**: `https` (secure)
- **Hostname**: `www.example.com` (3 segments: `www`, `example`, `com`)
- **Length**: 29 characters (< 100)
- **Detected Flags**: None
- **Risk Level**: `LOW INDICATOR COUNT`
- **Technical Explanation**:
  The URL uses encrypted HTTPS, has a registered domain name with normal subdomain depth, does not use the `@` symbol or Punycode encoding, and falls well within normal length limits.
- **Mandatory Educational Notice**:
  > *"No warning signs detected does NOT guarantee that this URL is safe. Risk levels are educational indicators, not verified threat classifications."*

---

### 2. Sample 2: Direct IP Address as Hostname + Plaintext HTTP
- **URL**: `http://192.0.2.10/account`
- **Scheme**: `http`
- **Hostname**: `192.0.2.10`
- **Length**: 25 characters
- **Detected Warnings**:
  1. `Direct IP Address as Hostname` (Severity: High)
     - *Detail*: Hostname parses as an IPv4 address `192.0.2.10` using Python's `ipaddress` library.
     - *Attack Vector*: Cybercriminals host phishing templates on compromised servers or cloud droplets directly by IP to bypass domain registration costs, registrar identity checks, and domain blocklists.
  2. `Insecure HTTP Protocol` (Severity: Medium)
     - *Detail*: Connection uses `http://` instead of `https://`.
     - *Attack Vector*: Traffic is unencrypted, exposing user credentials to eavesdropping and Man-in-the-Middle (MitM) attacks.
- **Risk Level**: `MEDIUM RISK` (2 warning indicators detected)

---

### 3. Sample 3: @ Symbol Credential Obfuscation + HTTP
- **URL**: `http://example.com@sample.invalid/login`
- **Scheme**: `http`
- **Authority / Netloc**: `example.com@sample.invalid`
- **Actual Hostname**: `sample.invalid`
- **Length**: 39 characters
- **Detected Warnings**:
  1. `@ Symbol Deception` (Severity: High)
     - *Detail*: The `@` symbol is located at index 18.
     - *Attack Vector*: Under RFC 3986 URI syntax, `userinfo@hostname` treats `example.com` as user authentication information, while routing the victim's browser to `sample.invalid`. Phishers use this to trick users into believing they are visiting the brand name before the `@`.
  2. `Insecure HTTP Protocol` (Severity: Medium)
     - *Detail*: Unencrypted HTTP protocol in use.
- **Risk Level**: `MEDIUM RISK` (2 warning indicators detected)

---

### 4. Sample 4: Excessive Subdomain Chaining
- **URL**: `https://a.b.c.d.e.example.invalid/path`
- **Scheme**: `https`
- **Hostname**: `a.b.c.d.e.example.invalid`
- **Subdomain Segments**: `['a', 'b', 'c', 'd', 'e', 'example', 'invalid']` (7 segments $\ge$ threshold of 5)
- **Length**: 38 characters
- **Detected Warnings**:
  1. `Excessive Subdomain Segments` (Severity: Medium)
     - *Detail*: Hostname contains 7 dot-separated labels.
     - *Attack Vector*: Attackers chain reputable-sounding brand names into subdomain prefixes (e.g. `paypal.com.account.verify.attacker.com`). Because narrow mobile screens truncate the end of long hostnames, users often only see the brand name at the beginning.
- **Risk Level**: `MEDIUM RISK` (1 warning indicator detected)

---

### 5. Sample 5: Punycode (IDN Homograph) Detection
- **URL**: `https://xn--example.invalid/`
- **Scheme**: `https`
- **Hostname**: `xn--example.invalid`
- **Length**: 28 characters
- **Detected Warnings**:
  1. `Punycode (IDN Homograph) Indicator` (Severity: High)
     - *Detail*: Hostname contains the `xn--` prefix.
     - *Attack Vector*: Internationalized Domain Names (IDNs) allow non-ASCII characters, which are encoded in ASCII starting with `xn--`. Attackers use Cyrillic or Greek lookalikes (homoglyphs) to create visually identical replicas of trusted brand domains (e.g., `xn--pple-43d.com` displaying visually as `аpple.com`).
- **Risk Level**: `MEDIUM RISK` (1 warning indicator detected)

---

### 6. Sample 6 (Bonus High Risk): Multi-Vector Compound Threat
- **URL**: `http://admin@192.0.2.10/verify?redirect=http://attacker.com/session/token/long-string-padding-out-url-over-one-hundred-characters`
- **Length**: 137 characters (> 100)
- **Detected Warnings**:
  1. `@ Symbol Deception`
  2. `Excessive URL Length` (137 characters)
  3. `Direct IP Address as Hostname` (`192.0.2.10`)
  4. `Insecure HTTP Protocol` (`http://`)
- **Risk Level**: `HIGH RISK` (4 warning indicators compounded)
- **Technical Explanation**:
  Multiple concurrent evasion and deception techniques are present. Demonstrates how compounded indicators escalate the evaluation to `HIGH RISK`.

---

## How to Run Automated Verification

Execute the Python test suite from the project root:

```bash
python -m unittest tests/test_checker.py -v
```

All 25 automated tests will execute and verify each rule and benchmark sample.

