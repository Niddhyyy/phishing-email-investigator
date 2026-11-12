# Phishing Email Investigator

A Python project I built to learn more about phishing email analysis and basic cybersecurity investigation.

The idea is to take a suspicious email (`.eml` file), examine its contents, look for potentially suspicious indicators, and generate a report with the findings.

## What does it do?

- Reads `.eml` files and extracts email details such as sender, recipient, subject and date.
- Checks URLs for suspicious characteristics like IP addresses, URL shorteners, punycode and unusual domains.
- Extracts IOCs (Indicators of Compromise), including URLs, domains, IP addresses and file hashes.
- Checks email headers for available SPF, DKIM and DMARC information.
- Compares sender and Reply-To addresses.
- Inspects email attachments by checking their file extensions, sizes and SHA-256 hashes.
- Assigns a risk score based on the indicators found.
- Generates a Markdown report containing the investigation results.

## Tech used

- Python
- Regular Expressions
- Email parsing
- URL parsing
- Hashlib
- JSON and CSV
- Unittest

## Project structure

```text
phishing-investigator/
├── samples/
├── reports/
├── output/
├── src/
│   ├── analyze_email.py
│   ├── analyze_url.py
│   ├── extract_iocs.py
│   ├── risk_scoring.py
│   └── generate_report.py
├── tests/
├── .gitignore
└── README.md
```

## Running the project

Clone the repository:

```bash
git clone https://github.com/Niddhyyy/phishing-email-investigator.git
cd phishing-email-investigator
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Analyze a sample email:

```bash
python src/analyze_email.py samples/sample_email.eml
```

Extract IOCs:

```bash
python src/extract_iocs.py samples/sample_email.eml
```

Generate the investigation report:

```bash
python src/generate_report.py
```

The generated report is saved in `reports/`, while the extracted IOCs are saved in `output/` as JSON and CSV files.

## Running tests

```bash
python -m unittest discover -s tests -v
```

Currently, the project has 14 automated tests, covering URL analysis, email security checks and attachment inspection.

## A few things to keep in mind

This is a learning project, not a complete enterprise phishing detection system.

The risk score is based on predefined rules, so it can produce false positives or miss suspicious emails. SPF, DKIM and DMARC information is read from existing email headers; the project does not independently verify these authentication mechanisms. Attachment inspection is limited to metadata and file extension checks, not actual malware scanning.

## Why I built this

I wanted to get practical experience with Python and understand how a basic phishing investigation works, from parsing an email to extracting indicators and producing a final report.

More improvements may be added as I learn more about cybersecurity.
