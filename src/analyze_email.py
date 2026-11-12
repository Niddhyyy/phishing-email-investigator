import hashlib
import os
import re
from email import policy
from email.parser import BytesParser
import argparse


def analyze_attachments(msg):
    suspicious_extensions = {
        ".exe", ".scr", ".bat", ".cmd",
        ".js", ".vbs", ".ps1", ".hta",
        ".jar", ".msi", ".com"
    }

    attachments = []

    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue

        filename = part.get_filename() or "unknown"
        extension = os.path.splitext(filename)[1].lower()

        file_data = part.get_payload(decode=True) or b""
        file_hash = hashlib.sha256(file_data).hexdigest()

        attachment_info = {
            "filename": filename,
            "extension": extension,
            "size": len(file_data),
            "sha256": file_hash,
            "suspicious": extension in suspicious_extensions
        }

        attachments.append(attachment_info)

    return attachments


def analyze_email(file_path):
    with open(file_path, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    print("\n=== EMAIL INVESTIGATION REPORT ===")

    print("From:", msg.get("From", "Not available"))
    print("To:", msg.get("To", "Not available"))
    print("Subject:", msg.get("Subject", "Not available"))
    print("Date:", msg.get("Date", "Not available"))
    print("\n=== RECEIVED CHAIN ===")

    received_headers = msg.get_all("Received", [])

    if received_headers:
        for header in received_headers:
            print(header)
    else:
        print("No Received headers available.")
    print("Reply-To:", msg.get("Reply-To", "Not available"))
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")

    if reply_to and from_addr:
        if reply_to.lower() not in from_addr.lower():
            print("\nWARNING: Reply-To address differs from sender!")
        else:
            print("\nReply-To matches sender.")
    print("\n=== EMAIL AUTHENTICATION ===")

    print("SPF:", msg.get("Received-SPF", "Not available"))
    print("DKIM:", msg.get("DKIM-Signature", "Not available"))
    print("DMARC:", msg.get("Authentication-Results", "Not available"))

    print("\n=== EMAIL BODY ===")

    body = msg.get_body(preferencelist=("plain",))

    if body:
        email_text = body.get_content()
        print(email_text)

        print("\n=== EXTRACTED URLs ===")

        url_pattern = r'https?://[^\s<>"\']+'
        urls = re.findall(url_pattern, email_text)

        if urls:
            for url in urls:
                url = url.rstrip(".,;:!?)")
                print(url)
        else:
            print("No URLs found.")

    else:
        print("No plain-text email body found.")


    attachments = analyze_attachments(msg)

    print("\n=== ATTACHMENT ANALYSIS ===")

    if not attachments:
        print("No attachments found.")

    for attachment in attachments:
        print("Filename:", attachment["filename"])
        print("Extension:", attachment["extension"])
        print("Size:", attachment["size"], "bytes")
        print("SHA-256:", attachment["sha256"])

        if attachment["suspicious"]:
            print("WARNING: Potentially dangerous file extension!")
        else:
            print("No suspicious extension detected.")

        print("-" * 40)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze an email file"
    )

    parser.add_argument("file", help="Path to the .eml file")
    args = parser.parse_args()

    analyze_email(args.file)


if __name__ == "__main__":
    main()
