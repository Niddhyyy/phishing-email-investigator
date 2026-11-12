
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from analyze_url import analyze_url


def check_reply_to_mismatch(msg):
    sender = parseaddr(msg.get("From", ""))[1]
    reply_to = parseaddr(msg.get("Reply-To", ""))[1]

    if sender and reply_to:
        return sender.lower() != reply_to.lower()

    return False

def check_sender_impersonation(msg):
    trusted_brands = {
        "paypal": ["paypal.com"],
        "google": ["google.com"],
        "microsoft": ["microsoft.com"],
        "amazon": ["amazon.com"]
    }

    sender_name, sender_email = parseaddr(msg.get("From", ""))
    sender_domain = sender_email.split("@")[-1].lower()

    findings = []

    for brand, trusted_domains in trusted_brands.items():
        if brand in sender_name.lower():
            if sender_domain not in trusted_domains:
                findings.append(
                    f"Possible {brand} display-name impersonation"
                )

    return findings

def check_return_path_mismatch(msg):
    from email.utils import parseaddr

    sender_email = parseaddr(msg.get("From", ""))[1]
    return_email = parseaddr(msg.get("Return-Path", ""))[1]

    if not sender_email or not return_email:
        return False

    sender_domain = sender_email.split("@")[-1].lower()
    return_domain = return_email.split("@")[-1].lower()

    return sender_domain != return_domain

def analyze_email_content(email_text):
    suspicious_phrases = {
        "urgent": 5,
        "verify your account": 15,
        "account restricted": 15,
        "password expired": 10,
        "immediate action required": 15,
        "click here": 5
    }

    findings = []
    text = email_text.lower()

    for phrase, points in suspicious_phrases.items():
        if phrase in text:
            findings.append(
                f"Suspicious email phrase: '{phrase}' (+{points})"
            )

    return findings

def check_email_authentication(msg):
    findings = []

    auth_results = str(
        msg.get("Authentication-Results", "")
    ).lower()

    received_spf = str(
        msg.get("Received-SPF", "")
    ).lower()

    if "spf=fail" in auth_results or received_spf.startswith("fail"):
        findings.append("SPF authentication failed (+20)")

    elif "spf=softfail" in auth_results or received_spf.startswith("softfail"):
        findings.append("SPF authentication softfailed (+10)")

    if "dkim=fail" in auth_results:
        findings.append("DKIM authentication failed (+20)")

    if "dmarc=fail" in auth_results:
        findings.append("DMARC authentication failed (+25)")

    return findings


def calculate_risk(url_findings, reply_to_mismatch=False):
    score = 0
    reasons = []

    weights = {
        "Host is an IP address, not a domain name": 15,
        "URL uses a known shortening service": 10,
        "Hostname contains punycode": 20,
        "Hostname has many subdomains": 10,
        "URL contains an @ symbol": 15,
        "Hostname uses a suspicious TLD": 10,
        "Possible paypal brand impersonation": 20
    }

    for finding in url_findings:
        if finding.startswith("Suspicious email phrase:"):
            points = int(finding.split("(+")[-1].replace(")", ""))
        else:
            points = weights.get(finding, 10)

        score += points
        reasons.append(finding)

    if reply_to_mismatch:
        score += 20
        reasons.append("Sender and Reply-To addresses differ (+20)")

    score = min(score, 100)

    if score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }


def main():

    # Step 1: Read email
    with open("samples/sample_email.eml", "rb") as file:
        email_msg = BytesParser(policy=policy.default).parse(file)

    # Step 2: Extract email body
    body = email_msg.get_body(preferencelist=("plain",))
    email_text = body.get_content() if body else ""

    # Step 3: Analyze subject and body
    subject = str(email_msg.get("Subject", ""))
    content_findings = analyze_email_content(subject + " " + email_text)

    # Step 4: Extract URLs
    urls = re.findall(r'https?://[^\s<>"\']+', email_text)

    # Step 5: Analyze URLs
    all_findings = []

    for url in urls:
        url_result = analyze_url(url)
        all_findings.extend(url_result["findings"])

    # Step 6: Add email-content findings
    all_findings.extend(content_findings)

    # Step 7: Check Reply-To mismatch
    reply_mismatch = check_reply_to_mismatch(email_msg)

    sender_findings = check_sender_impersonation(email_msg)
    all_findings.extend(sender_findings)

    return_path_mismatch = check_return_path_mismatch(email_msg)

    if return_path_mismatch:
        all_findings.append(
        "From and Return-Path domains do not match (+15)"
    )
        auth_findings = check_email_authentication(email_msg)
    all_findings.extend(auth_findings)

    # Step 8: Calculate risk
    result = calculate_risk(
        all_findings,
        reply_to_mismatch=reply_mismatch
    )

    # Step 9: Display results
    print("\n=== RISK ASSESSMENT ===")
    print("Analyzed URLs:", urls)
    print("Risk Score:", result["score"])
    print("Risk Level:", result["risk_level"])

    print("\nReasons:")
    for reason in result["reasons"]:
        print("-", reason)


if __name__ == "__main__":
    main()
