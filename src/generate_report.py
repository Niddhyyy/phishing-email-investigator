
import re
from datetime import datetime
from pathlib import Path
from email import policy
from email.parser import BytesParser

from analyze_url import analyze_url
from analyze_email import analyze_attachments
from extract_iocs import extract_iocs
from risk_scoring import (
    calculate_risk,
    check_reply_to_mismatch,
    check_sender_impersonation,
    check_return_path_mismatch,
    check_email_authentication,
    analyze_email_content
)


BASE_DIR = Path(__file__).resolve().parents[1]
INPUT_FILE = BASE_DIR / "samples" / "sample_email.eml"
OUTPUT_FILE = BASE_DIR / "reports" / "investigation_report.md"


def generate_report():

    # 1. Read the email
    with open(INPUT_FILE, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    sender = str(msg.get("From", "Unknown"))
    recipient = str(msg.get("To", "Unknown"))
    subject = str(msg.get("Subject", "No subject"))
    date = str(msg.get("Date", "Unknown"))

    body = msg.get_body(preferencelist=("plain",))
    email_text = body.get_content() if body else ""

    # 2. Analyze attachments
    attachments = analyze_attachments(msg)

    # 3. Extract URLs
    urls = re.findall(
        r'https?://[^\s<>"\']+',
        email_text
    )

    url_findings = []

    for url in urls:
        result = analyze_url(url)
        url_findings.extend(result["findings"])

    # 4. Analyze email content
    content_findings = analyze_email_content(
        subject + " " + email_text
    )

    # 5. Check sender information
    reply_mismatch = check_reply_to_mismatch(msg)

    sender_findings = check_sender_impersonation(msg)

    return_path_mismatch = check_return_path_mismatch(msg)

    auth_findings = check_email_authentication(msg)

    # 6. Combine all findings
    all_findings = (
        url_findings
        + content_findings
        + sender_findings
        + auth_findings
    )

    if return_path_mismatch:
        all_findings.append(
            "From and Return-Path domains do not match (+15)"
        )

    # 7. Calculate risk
    risk = calculate_risk(
        all_findings,
        reply_to_mismatch=reply_mismatch
    )

    # 8. Extract IOCs
    iocs = extract_iocs(
        sender + " "
        + recipient + " "
        + subject + " "
        + email_text
    )

    # 9. Build the Markdown report
    report = "# Phishing Email Investigation Report\n\n"

    report += "## 1. Investigation Details\n\n"
    report += f"- **Generated:** {datetime.now()}\n"
    report += f"- **Sender:** {sender}\n"
    report += f"- **Recipient:** {recipient}\n"
    report += f"- **Subject:** {subject}\n"
    report += f"- **Date:** {date}\n\n"

    report += "## 2. Extracted URLs\n\n"

    if urls:
        for url in urls:
            report += f"- {url}\n"
    else:
        report += "No URLs found.\n"

    report += "\n## 3. URL Analysis Findings\n\n"

    if url_findings:
        for finding in url_findings:
            report += f"- {finding}\n"
    else:
        report += "No suspicious URL characteristics detected.\n"

    report += "\n## 4. Attachment Analysis\n\n"

    if attachments:
        for attachment in attachments:
            report += f"### {attachment['filename']}\n\n"
            report += f"- Extension: {attachment['extension']}\n"
            report += f"- Size: {attachment['size']} bytes\n"
            report += f"- SHA-256: `{attachment['sha256']}`\n"
            report += (
                "- Suspicious extension: "
                + ("YES" if attachment["suspicious"] else "NO")
                + "\n\n"
            )
    else:
        report += "No attachments found in this email.\n\n"

    report += "## 5. Extracted Indicators of Compromise (IOCs)\n\n"

    if iocs:
        for ioc in iocs:
            report += (
                f"- **{ioc['type']}**: `{ioc['value']}`\n"
            )
    else:
        report += "No IOCs extracted.\n"

    report += "\n## 6. Email Content Findings\n\n"

    if content_findings:
        for finding in content_findings:
            report += f"- {finding}\n"
    else:
        report += "No suspicious phrases detected.\n"

    report += "\n## 7. Email Security Findings\n\n"

    security_findings = []

    if reply_mismatch:
        security_findings.append(
            "Sender and Reply-To addresses differ."
        )

    security_findings.extend(sender_findings)

    if return_path_mismatch:
        security_findings.append(
            "From and Return-Path domains do not match."
        )

    security_findings.extend(auth_findings)

    if security_findings:
        for finding in security_findings:
            report += f"- {finding}\n"
    else:
        report += "No email security warnings detected.\n"

    report += "\n## 8. Risk Assessment\n\n"
    report += f"- **Risk Score:** {risk['score']}/100\n"
    report += f"- **Risk Level:** {risk['risk_level']}\n\n"

    report += "### Reasons\n\n"

    if risk["reasons"]:
        for reason in risk["reasons"]:
            report += f"- {reason}\n"
    else:
        report += "No risk indicators identified.\n"

    report += "\n## 9. Investigation Conclusion\n\n"

    if risk["risk_level"] == "HIGH":
        report += (
            "The email contains multiple suspicious indicators. "
            "It should be treated as potentially malicious "
            "and investigated further.\n"
        )
    elif risk["risk_level"] == "MEDIUM":
        report += (
            "The email contains some suspicious indicators. "
            "Further investigation is recommended.\n"
        )
    else:
        report += (
            "The email has a low heuristic risk score. "
            "This does not guarantee that the email is safe.\n"
        )

    report += (
        "\n**Note:** This tool uses rule-based detection. "
        "Its findings are indicators for investigation, "
        "not definitive proof of malicious activity.\n"
    )

    # 10. Save the report
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(report, encoding="utf-8")

    print("\n=== REPORT GENERATED ===")
    print(f"Report saved to: {OUTPUT_FILE}")
    print("Risk Score:", risk["score"])
    print("Risk Level:", risk["risk_level"])


if __name__ == "__main__":
    generate_report()
