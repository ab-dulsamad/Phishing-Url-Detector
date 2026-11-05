# Screenshots Directory

This directory is intended to store screenshots of the application during demonstration and review.

### Recommended Demonstration Screenshots:
1. `01_dashboard_home.png` - Initial view of the Cybersecurity Dashboard with the six detection heuristics guide.
2. `02_sample1_legitimate.png` - Analysis of Sample 1 (`https://www.example.com/login`) showing `LOW INDICATOR COUNT` and the safety disclaimer.
3. `03_sample2_ip_address.png` - Analysis of Sample 2 (`http://192.0.2.10/account`) showing `MEDIUM RISK` with direct IP and HTTP warning flags.
4. `04_sample3_at_symbol.png` - Analysis of Sample 3 (`http://example.com@sample.invalid/login`) showing `@` symbol deception warning.
5. `05_sample4_subdomains.png` - Analysis of Sample 4 (`https://a.b.c.d.e.example.invalid/path`) highlighting the 7 subdomain segments.
6. `06_sample5_punycode.png` - Analysis of Sample 5 (`https://xn--example.invalid/`) showing Punycode homograph attack flag.
7. `07_sample6_high_risk.png` - Analysis of a multi-vector sample showing `HIGH RISK` with 4 compounded indicators.
8. `08_terminal_cli_mode.png` - Running `python phishing_checker.py` in the VS Code terminal.
