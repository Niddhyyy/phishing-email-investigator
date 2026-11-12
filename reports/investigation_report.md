# Phishing Email Investigation Report

## 1. Investigation Details

- **Generated:** 2026-11-12 23:09:08.223588
- **Sender:** IT Support <support@example.com>
- **Recipient:** employee@example.com
- **Subject:** Urgent: Account Verification Required
- **Date:** Thu, 12 Nov 2026 10:30:00 +0530

## 2. Extracted URLs

- https://login.example.net/verify

## 3. URL Analysis Findings

No suspicious URL characteristics detected.

## 4. Attachment Analysis

No attachments found in this email.

## 5. Extracted Indicators of Compromise (IOCs)

- **URL**: `https://login.example.net/verify`
- **DOMAIN**: `example.com`
- **DOMAIN**: `login.example.net`

## 6. Email Content Findings

- Suspicious email phrase: 'urgent' (+5)
- Suspicious email phrase: 'verify your account' (+15)

## 7. Email Security Findings

- Sender and Reply-To addresses differ.

## 8. Risk Assessment

- **Risk Score:** 40/100
- **Risk Level:** MEDIUM

### Reasons

- Suspicious email phrase: 'urgent' (+5)
- Suspicious email phrase: 'verify your account' (+15)
- Sender and Reply-To addresses differ (+20)

## 9. Investigation Conclusion

The email contains some suspicious indicators. Further investigation is recommended.

**Note:** This tool uses rule-based detection. Its findings are indicators for investigation, not definitive proof of malicious activity.
