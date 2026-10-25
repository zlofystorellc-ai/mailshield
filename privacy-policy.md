# MailShield Privacy Policy

_Last updated: 25 October 2026_

MailShield is a browser extension that warns you about phishing, scam and malicious emails in Gmail. This policy explains exactly what data MailShield handles, why, and how you control it.

## 1. Summary

- MailShield **does not** read your mailbox in the background, access your Google account, or send email on your behalf. It only looks at an email **when you open it** in Gmail.
- Basic protection runs **entirely inside your browser**. Nothing is sent anywhere until you turn on **cloud protection** on the welcome page or in the popup.
- MailShield **never stores the body of the emails you read**.
- Scam reports are sent **only when you click "Report as scam" and tick the consent box**, and personal details are removed on your computer first.
- MailShield does not sell data, use it for advertising, or share it except with the security services listed below.
- You can delete your data at any time from the popup (**Delete my data**).

## 2. Data processed locally (never leaves your device)

When you open an email, MailShield reads the sender name and address, reply-to address, subject, visible text, links and attachment file names, and checks them in your browser. MailShield also keeps in your browser's extension storage your settings, your allowlist and blocklist, simple counters (emails scanned, warnings, threats blocked, reports made), a 24-hour cache of verdicts, and the list of known scam signatures.

## 3. Data sent when cloud protection is ON

For each email you open, MailShield sends to its server over HTTPS:

| Data | Why | What is stored |
|---|---|---|
| Sender address and display name | sender reputation, look-alike detection | the sender **domain** only |
| Subject | matching | a one-way **hash** only |
| Links (URLs) and attachment **file names** (never the files) | link reputation checks | each link's domain and a **hash** of the URL |
| A short excerpt of the text, **normalized** so that amounts, dates, numbers, names, phone numbers, email addresses, UPI IDs and account numbers are replaced by placeholders such as `<amount>` | comparing against reported scam patterns | a **SimHash fingerprint** only (it can't be turned back into text) |
| The local risk score and reasons | combining results | the score, level, reason codes and threat type |

These scan records are **deleted automatically after 90 days**. MailShield identifies your installation with a **random install ID** (not your name, email or Google account) and a token derived from it.

### Third-party security services

To check links, MailShield's **server** (never your browser) may send the **URL** of a link, or its domain, to:

- **Google Safe Browsing** (Google LLC): lists known phishing and malware sites
- **VirusTotal** (Google/Chronicle): URL reputation from many security vendors
- **URLhaus** (abuse.ch): known malware distribution sites
- **RDAP registries** (via rdap.org): the domain's registration date

URL reputation results are cached for 24 hours.

### Optional AI analysis

If you turn on **AI analysis** in the popup, the normalized excerpt described above (with personal details already removed) may be sent to the configured AI provider to help classify uncertain emails. It is off by default.

## 4. Scam reports (only with your explicit consent)

When you click **Report as scam**, you see a preview of exactly what will be sent, and must tick: _"The text of this email will be sent to MailShield for analysis. Personal details will be removed."_

Before anything is sent, MailShield removes in your browser: account and card numbers, phone numbers, email addresses, UPI IDs, OTP-like codes, PAN and Aadhaar numbers, and your own name and email address. The server applies the same redaction again.

A report contains the redacted subject and text, the sender address and display name, the links, attachment file names, the category you chose and your optional comment. Reports are used to detect scam campaigns: similar reports from several different users are grouped, reviewed, and turned into a "signature" that warns all users about similar emails. Administrators may read redacted reports when reviewing them. Reporting also adds the sender to your personal blocklist.

## 5. Feedback and "open anyway"

If you mark a warning as a false alarm or correct, or open a blocked link anyway, MailShield records that event (scan reference, link domain, risk score, optional comment) to improve accuracy.

## 6. Your choices and rights

- **Turn cloud protection off** at any time in the popup. MailShield then works locally only.
- **Delete my data** in the popup deletes, from the server, your install record, scan records, feedback, overrides, lists and reports, and clears the extension's local storage. Signatures already built from many users' reports keep only aggregate counts.
- Uninstalling the extension removes all local data. Server records then expire (scans after 90 days); to remove them immediately, use **Delete my data** before uninstalling.

## 7. Security

All traffic uses HTTPS. The extension contains no database credentials or third-party API keys. Server access is protected by signed tokens, input validation and rate limiting, and administrator access is separately protected.

## 8. Chrome Web Store Limited Use

MailShield's use of information received from Gmail pages adheres to the Chrome Web Store User Data Policy, including the Limited Use requirements. Data is used only to provide and improve MailShield's single purpose, protection from malicious email. It is not transferred to third parties except as described above for security checks, not used for advertising, and not used to determine creditworthiness or for lending.

## 9. Children

MailShield is not directed at children under 13 and does not knowingly collect their data.

## 10. Changes and contact

We will update this page and the "Last updated" date if this policy changes. For questions or deletion requests, contact: **privacy@your-domain.example** _(replace before publishing)_.
