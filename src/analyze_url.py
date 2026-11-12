
"""
Phishing Investigator - Session 2

Purpose:
    Analyze suspicious URLs using defensive detection rules.

Safety:
    - Does not open URLs.
    - Does not make network requests.
    - Only examines the supplied URL string.
"""

import argparse
import ipaddress
import json
from urllib.parse import urlsplit


# Known URL shortening services.
# This is a small demonstration list, not an exhaustive database.
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
}

# TLDs we want to flag for additional investigation.
# These are examples, not a list of inherently malicious TLDs.
SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "work",
    "zip",
}

# Brands to monitor for possible impersonation.
# This simple detector is intentionally conservative.
MONITORED_BRANDS = {
    "google",
    "microsoft",
    "paypal",
    "amazon",
}


def analyze_url(raw_url):
    """Analyze URL structure and return findings."""

    raw_url = raw_url.strip()

    # Add // when a scheme is missing so urlsplit
    # can still identify the hostname.
    candidate = raw_url

    if "://" not in candidate:
        candidate = "//" + candidate

    parsed = urlsplit(candidate)

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    findings = []

    # Rule 1: Check for an @ symbol.
    if "@" in parsed.netloc:
        findings.append("Contains an @ symbol in the network location")

    # Rule 2: Check whether the hostname is an IP address.
    is_ip = False

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        findings.append("Host is an IP address, not a domain name")
    except ValueError:
        pass

    # Rule 3: Check for punycode.
    if any(label.startswith("xn--") for label in hostname.split(".")):
        findings.append("Hostname contains a punycode label")

    # Rule 4: Count hostname labels.
    labels = hostname.split(".") if hostname else []

    if len(labels) >= 5:
        findings.append("Hostname has five or more labels")

    # Rule 5: Check against known URL shorteners.
    if hostname in SHORTENERS:
        findings.append("Uses a known URL shortening service")

    # Rule 6: Check the final hostname label (TLD).
    if not is_ip and "." in hostname:
        tld = hostname.rsplit(".", 1)[-1]

        if tld in SUSPICIOUS_TLDS:
            findings.append(f"Uses a monitored TLD: .{tld}")

    # Rule 7: Look for possible brand impersonation.
    # This is a basic heuristic, not proper domain similarity analysis.
    if not is_ip:
        registered_domain_candidate = (
            hostname.split(".")[-2]
            if len(labels) >= 2
            else hostname
        )

        for brand in MONITORED_BRANDS:
            if brand in hostname and registered_domain_candidate != brand:
                findings.append(
                    f"Possible {brand} brand impersonation"
                )

    # Rule 8: Check URL length.
    if len(raw_url) > 100:
        findings.append("URL is unusually long")

    # Return structured information instead of only printing it.
    return {
        "url": raw_url,
        "hostname": hostname or None,
        "path": parsed.path or "/",
        "is_ip": is_ip,
        "findings": findings,
        "finding_count": len(findings),
    }


def main():
    """Accept a URL and display the analysis."""

    parser = argparse.ArgumentParser(
        description="Defensive URL investigation tool"
    )

    parser.add_argument("url", help="URL string to analyze")

    args = parser.parse_args()

    result = analyze_url(args.url)

    print("\n=== URL Investigation ===")
    print(f"URL: {result['url']}")
    print(f"Hostname: {result['hostname']}")
    print(f"Path: {result['path']}")

    print("\nFindings:")

    if result["findings"]:
        for finding in result["findings"]:
            print(f"- {finding}")
    else:
        print("- No current detection rules triggered")

    print(f"\nTotal findings: {result['finding_count']}")

    # Save the investigation result as JSON.
    with open("output/url_analysis.json", "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print("\nSaved results to output/url_analysis.json")


if __name__ == "__main__":
    main()
