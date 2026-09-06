# ALU Regex Data Extraction & Secure Validation Tool

## Overview
This tool extracts, validates, and categorizes structured data—including official ALU emails, PCI-DSS compliant credit cards, Rwandan phone numbers, and web URLs—from raw API logs and text files. It implements strict validation logic and masking to handle untrusted input safely.

---

## Folder Structure

```text
alu-regex-data-extraction_aanyar1-tech/
├── input/
│   └── raw-text.txt          # Source raw text file
├── output/
│   └── sample-output.json    # Generated JSON output and audit logs
├── src/
│   └── main.py               # Main Python script
└── README.md                 # Project documentation
```

---

## Features & Validation

1. **ALU Emails:** Strictly validates and categorizes:
   - Official: `@alueducation.com`
   - Alumni: `@alumni.alueducation.com`
   - SI (Student Interns): `@si.alueducation.com`
   - General / External: Non-ALU valid email addresses
   - *Security:* Masks local email parts for PII privacy and rejects domain spoofing / malformed double-dot emails into an audit log.

2. **Credit Cards:** Validates card structures (Visa, Mastercard, Amex) using the Luhn Modulo 10 algorithm and masks output (`4532-XXXX-XXXX-3456`) for PCI-DSS compliance.

3. **Rwandan Phone Numbers:** Validates Rwandan formats (`+250`, `00250`, or `07...`) for MTN/Airtel networks, filters dummy numbers, and normalizes them cleanly as `+250 7XX XXX XXX`.

4. **URLs:** Validates HTTP/HTTPS web links while filtering out XSS scripts and malicious payloads.

---

## How to Run

1. **Prerequisites:** Make sure Python 3.8 or higher is installed.
2. **Execution:** Run the core extraction script from the repository root directory:
   ```bash
   python3 src/main.py
   ```
3. **Output:** Check the terminal for the execution summary report, and open `output/sample-output.json` to view the full extracted data and validation audit log.
