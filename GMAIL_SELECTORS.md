# Gmail selectors: where they live and how to update them

Gmail is a single-page app with obfuscated class names (`a3s`, `gD`, `hP`, …) that change from time to time. To make breakage cheap to fix, **every Gmail DOM selector is in one file:**

```
extension/content/selectors.js
```

No other file contains Gmail selectors. `extract.js` and `main.js` only read `MailShield.selectors` and `MailShield.selectorPatterns`.

| Key | What it must match | Current value |
|---|---|---|
| `messageBody` | The rendered body of an **opened** message. This is the key selector: no match means nothing gets scanned. | `div.a3s` |
| `messageContainer` | The wrapper of one expanded message (contains the sender chip and attachments) | `div.adn` |
| `subject` | The conversation subject heading | `h2.hP` |
| `sender` | The sender chip carrying `email="…"` and `name="…"` attributes | `span.gD[email]` |
| `senderFallback` | Any element with an `email` attribute in the message header | `h3 span[email]` |
| `attachmentName` | The visible attachment file name | `span.aV3` |
| `attachmentDownload` | An element with `download_url="mime:filename:url"` | `[download_url]` |
| `headerDetailsRow` | Rows of the "show details" header table (used for Reply-To) | `table.ajC tr` |
| `accountButton` | The account avatar link (used only to redact the user's own name/email from reports) | `a[aria-label^="Google Account"]` |

## How to fix it when detection stops working

1. Open Gmail, open an email, and open DevTools → **Elements**.
2. Right-click the email body text → **Inspect**. Find the nearest stable ancestor of the body (today `div.a3s`). Prefer attributes such as `role`, `aria-*`, `email`, `name` or `download_url` over class names when Gmail offers them.
3. Check a candidate in the Console, for example `document.querySelectorAll('div.a3s').length`. It should equal the number of expanded messages.
4. Update the value in `selectors.js` and reload the extension at `chrome://extensions` (↻), then reload Gmail.
5. Check that the badge or banner appears above the body, that sender and subject are right (open a WARNING-level test email and look at the reasons), and that link clicks are intercepted.

`main.js` re-scans on every DOM mutation (debounced 300 ms) and remembers handled bodies in a WeakMap, so re-rendered messages are picked up automatically. Interception uses a capture-phase `click`/`auxclick` listener on `window`, so it doesn't depend on Gmail's own link handlers.
