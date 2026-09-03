# PhishGuard

PhishGuard is a web-based phishing awareness and detection tool for suspicious emails, SMS or WhatsApp messages, URLs, and attachment filenames. It uses transparent warning signs and practical safety guidance.

## Features

- Email checks for urgency, account threats, sensitive-information requests, sender domains, OTP requests, and links.
- SMS / WhatsApp checks for reward lures, pressure language, sensitive requests, and URLs included in the message.
- URL checks for HTTPS, unusual length, sensitive keywords, IP destinations, obscured destinations, and lookalike domains.
- Attachment checks for double extensions, executable files, archives, and macro-enabled documents.
- JPEG, PNG, and WebP screenshot uploads with local OCR for SMS / WhatsApp messages.

## Risk score

| Score | Level | Meaning |
| ---: | --- | --- |
| 0–20 | Low risk | No obvious phishing indicators detected. |
| 21–40 | Medium risk | Some suspicious characteristics detected. |
| 41–60 | Suspicious | Several indicators deserve a closer look. |
| 61–100 | High risk | Multiple strong phishing indicators detected. |

The score is an educational signal, not a definitive security verdict. Always verify unexpected requests through an official website or trusted contact channel.

## Privacy and safety

- Message analysis runs in the browser.
- Screenshot OCR runs locally in the browser.
- Attachments are never opened or executed; only their names and extensions are inspected.
- Do not upload or paste passwords, one-time codes, or other secrets.

## Run locally

```bash
pnpm install
pnpm --filter @workspace/phishguard run dev
```

The main application lives in `artifacts/phishguard/`. The repository-root `index.html` is a lightweight project landing page; the Vite application entry point is `artifacts/phishguard/index.html`.

## Scope

PhishGuard is intended for awareness and education. It does not replace antivirus software, email security gateways, incident-response procedures, or professional security advice.
