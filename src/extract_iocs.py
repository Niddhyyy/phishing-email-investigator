import re
import ipaddress
import json
import csv
import argparse


def extract_iocs(text):

    # Store all extracted indicators here.
    iocs = []

    # 1. Extract URLs.
    url_pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(url_pattern, text)

    for url in urls:
        url = url.rstrip(".,;:!?)")

        iocs.append({
            "type": "URL",
            "value": url
        })

    # 2. Extract possible IPv4 addresses.
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    possible_ips = re.findall(ip_pattern, text)

    for ip in possible_ips:
        try:
            ipaddress.ip_address(ip)

            iocs.append({
                "type": "IP",
                "value": ip
            })

        except ValueError:
            continue

    # 3. Extract domain names.
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b'
    domains = re.findall(domain_pattern, text)

    for domain in domains:
        iocs.append({
            "type": "DOMAIN",
            "value": domain.lower()
        })

    # 4. Extract MD5 hashes.
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    md5_hashes = re.findall(md5_pattern, text)

    for value in md5_hashes:
        iocs.append({
            "type": "MD5",
            "value": value.lower()
        })

    # 5. Extract SHA256 hashes.
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    sha256_hashes = re.findall(sha256_pattern, text)

    for value in sha256_hashes:
        iocs.append({
            "type": "SHA256",
            "value": value.lower()
        })

    # 6. Remove duplicate indicators.
    unique_iocs = []
    seen = set()

    for ioc in iocs:
        key = (ioc["type"], ioc["value"])

        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    return unique_iocs


def main():

    # Accept the input filename from the terminal.
    parser = argparse.ArgumentParser()

    parser.add_argument("file", help="Input text file")

    args = parser.parse_args()

    # Read the sample text file.
    with open(args.file, "r", encoding="utf-8") as file:
        text = file.read()
    # Extract indicators.
    iocs = extract_iocs(text)

    # Save results as JSON.
    with open("output/iocs.json", "w", encoding="utf-8") as file:
        json.dump(iocs, file, indent=4)

    # Save results as CSV.
    with open("output/iocs.csv", "w", newline="", encoding="utf-8") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=["type", "value"]
        )

        writer.writeheader()
        writer.writerows(iocs)

    # Display results.
    print("\n=== IOC Extraction Results ===")

    for ioc in iocs:
        print(f"{ioc['type']}: {ioc['value']}")

    print(f"\nTotal unique IOCs: {len(iocs)}")
    print("Saved to output/iocs.json")
    print("Saved to output/iocs.csv")


if __name__ == "__main__":
    main()
