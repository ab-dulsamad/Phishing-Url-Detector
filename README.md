# Phishing URL Awareness Checker

> **An Educational Cybersecurity Static Analysis Tool for URL Phishing Detection**

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask_3.x-lightgrey.svg)](https://palletsprojects.com/p/flask/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)
[![Zero Network Calls](https://img.shields.io/badge/Mode-100%25_Offline_Safe-success.svg)](#)
[![Tests Passing](https://img.shields.io/badge/Unit_Tests-25%2F25_Passed-brightgreen.svg)](#)

---

## 1. Project Introduction

The **Phishing URL Awareness Checker** is a Python-based cybersecurity mini-project developed to identify suspicious textual patterns in URLs. It assists users, students, and non-technical individuals in recognizing potential phishing indicators before interacting with dangerous links.

The application operates strictly through **offline static lexical inspection**. It deconstructs and evaluates the raw text of a URL using RFC standards without opening websites, establishing network connections, or contacting external servers.

---

## 2. Problem Statement

Phishing remains the predominant initial attack vector for data breaches, ransomware distribution, and identity theft. Attackers exploit subtle visual and syntactic manipulation of URLs—such as credential obfuscation, character homoglyphs, and excessive subdomain hierarchies—to mislead unsuspecting users.

Many users cannot discern between a genuine corporate domain and a cleverly spoofed address. Furthermore, existing automated security scanners often perform live DNS queries and web requests that can alert attackers or risk user privacy. There is a need for a safe, transparent, educational tool that analyzes suspicious URL traits locally and explains the security implications behind each warning sign.

---

## 3. Project Objectives

1. **Heuristic Identification:** Detect six classic URL-based phishing indicators without making network requests.
2. **Educational Risk Scoring:** Provide clear risk categorizations (`LOW INDICATOR COUNT`, `MEDIUM RISK`, `HIGH RISK`) with detailed explanations of attacker techniques.
3. **Safety & Privacy:** Ensure 100% offline text inspection—never opening links, collecting credentials, or transmitting telemetry data.
4. **Dual Interface:** Deliver both an interactive terminal CLI engine and a modern cybersecurity web dashboard.
5. **Academic Clarity:** Maintain clean, beginner-friendly Python code suitable for undergraduate computer science reviews and viva presentations.

---

## 4. Technologies Used

- **Programming Language:** Python 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.13)
- **Standard Library Modules (Core Engine):**
  - `re`: Regular expressions for pattern detection and scheme identification.
  - `urllib.parse`: RFC 3986 URL parsing (`urlsplit`) for token decomposition.
  - `ipaddress`: Accurate IPv4 and IPv6 network address validation.
  - `unittest`: Automated test framework.
- **Web Interface:**
  - **Backend:** Flask 3.x (lightweight Python microframework).
  - **Frontend:** Semantic HTML5, Custom Cyber Dark CSS3, Vanilla JavaScript (ES6+).
  - **Storage:** Client-side HTML5 `localStorage` (no server database or tracking).

---

## 5. Main Features & Detection Checks

The core engine implements six distinct phishing heuristic checks:

| # | Detection Check | Description | Why Attackers Use It |
| :---: | :--- | :--- | :--- |
| **1** | **`@` Symbol Detection** | Identifies the presence of the `@` character in the URL. | Under RFC 3986, characters before `@` are treated as user credentials. Attackers write `http://paypal.com@evil.com` to trick users who look at the first domain. |
| **2** | **Long URL Detection** | Flags URLs exceeding 100 characters in length. | Long URLs push the malicious domain off-screen on smartphones and conceal encoded payloads or redirect parameters. |
| **3** | **IP Address Detection** | Identifies direct IPv4 or IPv6 addresses used as hostnames. | Legitimate businesses use registered domains. Cybercriminals deploy raw IPs to bypass domain registration costs, registrar takedowns, and reputation filters. |
| **4** | **Subdomain Chaining** | Flags hostnames with five or more dot-separated segments. | Attackers chain authentic brand names (e.g. `bank.com.login.verify.attacker.com`) so users see only the trusted prefix on narrow screens. |
| **5** | **Punycode Detection** | Detects domains containing the `xn--` prefix. | Internationalized Domain Names (IDNs) allow lookalike characters (e.g., Cyrillic 'а' for Latin 'a') to spoof legitimate brands in homograph attacks. |
| **6** | **HTTP Protocol Detection** | Flags URLs using insecure `http://` instead of `https://`. | HTTP lacks TLS encryption and certificate identity proof, exposing users to plaintext credential sniffing and MitM tampering. |

---

## 6. Risk Assessment Framework

Results are categorized into three educational levels based on the number of flagged indicators:

- **`LOW INDICATOR COUNT`**: 0 warning signs detected in the URL structure.
- **`MEDIUM RISK`**: 1 or 2 warning signs detected.
- **`HIGH RISK`**: 3 or more warning signs detected (multiple compounded indicators).

### Mandatory Security Disclaimer
> **"No warning signs detected does NOT guarantee that this URL is safe. Risk levels are educational indicators, not verified threat classifications."**

---

## 7. System Requirements

- **Operating System:** Windows 10/11, macOS 11+, or Linux (Ubuntu, Debian, Fedora, etc.)
- **Python:** Version 3.10 or higher (`python --version`)
- **Web Browser:** Any modern browser (Chrome, Edge, Firefox, Brave, Safari)
- **Disk Space:** Less than 20 MB

---

## 8. Installation Instructions

### Step 1: Open Terminal / Command Prompt
Open your terminal or VS Code terminal in the project directory:
```bash
cd "Phishing Url Detector"
```

### Step 2: (Optional but Recommended) Create a Virtual Environment
```bash
# On Windows (PowerShell / Command Prompt)
python -m venv venv
.\venv\Scripts\activate

# On macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Requirements
```bash
pip install -r requirements.txt
```
*(Note: If you only want to use the CLI tool `phishing_checker.py`, zero pip packages are needed—it runs purely on the Python standard library!)*

---

## 9. How to Run the Project

### Option A: Web Dashboard (Recommended for Demonstrations)

1. Start the Flask application:
   ```bash
   python app.py
   ```
2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```
3. **Dashboard Capabilities:**
   - Click any of the **Quick Test Benchmark Chips** to load and analyze sample URLs instantly.
   - Paste any custom URL and click **Analyze URL**.
   - Watch the animated scanner examine the URL across all six heuristic checks.
   - Review the detailed breakdown, technical details, attacker rationale, and defense recommendations.
   - Inspect your persistent local analysis history stored safely in your browser.

---

### Option B: Command-Line Interface (CLI Mode)

#### 1. Interactive Menu Mode:
```bash
python phishing_checker.py
```
This launches an interactive terminal menu where you can select any of the benchmark test cases or input your own URL string:
```text
========================================================================
      CYBERSECURITY TOOL: PHISHING URL AWARENESS CHECKER
          Educational URL Static Text Inspection Engine
========================================================================
NOTE: Performs local static text inspection only (0 network requests).

------------------------------------------------------------------------
Choose an option:
  [1] Test Sample 1: Standard HTTPS Domain -> https://www.example.com/login
  [2] Test Sample 2: Raw IP Hostname + HTTP -> http://192.0.2.10/account
  [3] Test Sample 3: @ Symbol Credential Trick -> http://example.com@sample.invalid/login
  [4] Test Sample 4: Excessive Subdomains (5+) -> https://a.b.c.d.e.example.invalid/path
  [5] Test Sample 5: Punycode (IDN Homograph) -> https://xn--example.invalid/
  [C] Custom URL (type any URL)
  [Q] Quit
```

#### 2. Single-Command Mode:
Pass the target URL directly as a command-line argument:
```bash
python phishing_checker.py "http://192.0.2.10/account"
```

---

## 10. Sample Inputs and Expected Outputs

The project has been benchmarked against the five required evaluation URLs and a multi-indicator high-risk URL:

### Test Case 1: Standard Legitimate Structure
- **Input URL:** `https://www.example.com/login`
- **Output:**
  - **Risk Assessment:** `LOW INDICATOR COUNT`
  - **Flags Triggered:** `0`
  - **Summary:** No listed suspicious characteristics detected in this URL's static structure.
  - **Disclaimer:** *"No warning signs detected does NOT guarantee that this URL is safe."*

### Test Case 2: Direct IP Address + Insecure HTTP
- **Input URL:** `http://192.0.2.10/account`
- **Output:**
  - **Risk Assessment:** `MEDIUM RISK`
  - **Flags Triggered:** `2`
    1. `Direct IP Address as Hostname` (Raw IPv4 detected: `192.0.2.10`)
    2. `Insecure HTTP Protocol` (Unencrypted plaintext transport)

### Test Case 3: `@` Symbol Credential Obfuscation
- **Input URL:** `http://example.com@sample.invalid/login`
- **Output:**
  - **Risk Assessment:** `MEDIUM RISK`
  - **Flags Triggered:** `2`
    1. `@ Symbol Deception` (Deceptive credential trick routing to `sample.invalid`)
    2. `Insecure HTTP Protocol`

### Test Case 4: Excessive Subdomain Chaining
- **Input URL:** `https://a.b.c.d.e.example.invalid/path`
- **Output:**
  - **Risk Assessment:** `MEDIUM RISK`
  - **Flags Triggered:** `1`
    1. `Excessive Subdomain Segments` (7 dot-separated labels $\ge$ 5)

### Test Case 5: Punycode (IDN Homograph) Indicator
- **Input URL:** `https://xn--example.invalid/`
- **Output:**
  - **Risk Assessment:** `MEDIUM RISK`
  - **Flags Triggered:** `1`
    1. `Punycode (IDN Homograph) Indicator` (`xn--` prefix detected)

### Test Case 6: Multi-Vector Compound High Risk
- **Input URL:** `http://admin@192.0.2.10/verify?redirect=http://attacker.com/session/token/long-string-padding-out-url-over-one-hundred-characters`
- **Output:**
  - **Risk Assessment:** `HIGH RISK`
  - **Flags Triggered:** `4` (`@` Symbol, URL Length > 100, Direct IP Hostname, Insecure HTTP)

---

## 11. Automated Testing Details

Automated unit tests are implemented using Python's built-in `unittest` framework located in [`tests/test_checker.py`](file:///C:/Users/samad/OneDrive/Desktop/Phishing%20Url%20Detector/tests/test_checker.py).

To execute the test suite:
```bash
python -m unittest tests/test_checker.py -v
```

### Test Coverage Highlights:
- **Rule Verification:** Independent tests for all six heuristic checks (boundary conditions, uppercase/lowercase handling, and IPv4/IPv6).
- **Benchmark Tests:** Verifies all 5 required test cases and their exact warning counts.
- **Edge Cases:** Validates handling of empty inputs, whitespace strings, and missing scheme prefixes.
- **Safety Guarantee:** Verifies that the mandatory educational disclaimer is present in every result.

---

## 12. How to Run the Project in VS Code (Beginner Guide)

If you are presenting this project in Visual Studio Code:

1. **Open the Folder:**
   - Launch VS Code.
   - Go to **File** $\rightarrow$ **Open Folder...** and select `Phishing Url Detector`.
2. **Open the Integrated Terminal:**
   - Press <kbd>Ctrl</kbd> + <kbd>`</kbd> (backtick) or select **Terminal** $\rightarrow$ **New Terminal** from the top menu.
3. **Verify Python Interpreter:**
   - Look at the bottom-right status bar to ensure Python 3.10+ is selected. If not, press <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>P</kbd>, type `Python: Select Interpreter`, and choose your Python installation.
4. **Run the Automated Tests:**
   ```bash
   python -m unittest tests/test_checker.py -v
   ```
5. **Launch the Web Dashboard:**
   ```bash
   python app.py
   ```
   Hold <kbd>Ctrl</kbd> and click the `http://127.0.0.1:5000` link in the terminal to view the dashboard in your browser.
6. **Or Run the CLI Demonstration:**
   - Open a second terminal split and run:
     ```bash
     python phishing_checker.py
     ```

---

## 13. Project Structure

```text
Phishing Url Detector/
│
├── phishing_checker.py      # Core detection engine (zero external dependencies)
├── app.py                   # Flask web server & REST API
├── requirements.txt         # Project dependencies (Flask)
├── README.md                # Comprehensive project documentation
│
├── templates/
│   └── index.html           # Modern cybersecurity dashboard template
│
├── static/
│   ├── style.css            # Cyber navy theme, responsive CSS layout & glowing UI
│   └── script.js            # UI controller, scanner animations & localStorage history
│
├── tests/
│   ├── test_checker.py      # Automated Python unit test suite (25 tests)
│   └── test_samples.md      # Detailed test benchmark documentation & walkthrough
│
└── screenshots/
    └── README.md            # Guidelines for project presentation screenshots
```

---

## 14. Project Limitations

While static lexical analysis is exceptionally fast, private, and safe, it possesses inherent architectural boundaries:

1. **No Real-Time Content Analysis:** Does not inspect the HTML, JavaScript, forms, or login fields of the destination page.
2. **Shortener Services:** URL shorteners (e.g., `bit.ly`, `tinyurl.com`) can obscure a long malicious URL into a short, benign-looking path.
3. **Legitimate Subdomain Depth:** Some large cloud CDNs and legitimate enterprise platforms legitimately use five or more subdomain tiers.
4. **New Phishing Domains:** Cybercriminals who register brand-new domains with valid HTTPS certificates will pass lexical checks.
5. **No Domain Age / WHOIS:** Pure static text inspection does not query domain registry creation dates or reputation blocklists.

---

## 15. Future Enhancements

For future expansion or a major CSE project phase, the following enhancements could be incorporated:

1. **Machine Learning Classifier:** Train a Random Forest or XGBoost model on large-scale phishing datasets (e.g., PhishTank, Alexa Top 1M) using lexical feature vectors.
2. **Domain Age & WHOIS Lookup:** Integrate WHOIS lookup to flag domains registered within the last 14 to 30 days.
3. **SSL/TLS Certificate Inspection:** Query Certificate Transparency (CT) logs to check issuer authenticity.
4. **Headless Browser Sandbox:** Safely render links in an isolated Docker container to inspect login form actions and brand logos.
5. **Browser Extension:** Package the detection engine into a lightweight Chrome/Firefox browser extension for real-time browsing protection.

---

## 16. Ethical & Educational Compliance

- **Zero Exploitation:** This tool is strictly diagnostic and educational.
- **Zero Ingestion:** No user passwords, telemetry, or personal browsing histories are stored on servers or sent across networks.
- **Safe Testing:** All benchmark samples use synthetic or RFC 2606 reserved domains (`.invalid`, `.example`) and documentation IP addresses (`192.0.2.0/24`) to guarantee zero accidental exposure to live threats.

---

**Developed for CSE Cybersecurity Mini-Project & Technical Viva Defense.**

