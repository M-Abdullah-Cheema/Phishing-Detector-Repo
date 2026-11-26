# PhishGuard Mail Analyzer

A Manifest V3 Chrome extension that detects phishing emails in Gmail and explains why each one was flagged.
Plain HTML, CSS and JavaScript: no build step, no dependencies, no network requests.

## Install (unpacked)

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and select this folder.
3. Open <https://mail.google.com/> and open any email. A banner appears above the message and the toolbar badge shows the verdict (`!` likely phishing, `?` suspicious, `OK` low risk or trusted).

After editing the code, click the reload icon on the extension card and refresh the Gmail tab.

## Files

| File | Role |
| --- | --- |
| `manifest.json` | MV3 manifest. Permissions: `storage` and host access to `https://mail.google.com/*` only. |
| `background.js` | Non-persistent service worker. Validates messages, stores results, updates the badge. |
| `analyzer.js` | Detection engine. Pure functions with no DOM, `chrome.*` or network access. |
| `providers/gmail.js` | Gmail adapter: finds opened messages and extracts sender, subject, body, links and attachments. |
| `content.js` | Runs on Gmail: watches for opened emails, runs the analyzer, renders the banner. |
| `ui.js` | Rendering helpers shared by the banner and the popup. |
| `popup.html` / `popup.js` | Toolbar popup: verdict for the open email(s) and the trusted-sender list. |
| `styles.css` | Banner and popup styles (all classes prefixed `pg-` so they cannot clash with Gmail). |
| `icons/` | 16, 48 and 128 px toolbar and store icons. |
| `tests/` | Unit tests, evaluation script, fixtures and the Playwright end-to-end tests (see below). Not shipped. |
| `scripts/package.js` | Validates the manifest and builds `phishguard-extension.zip`. Not shipped. |
| `EVALUATION.md` | Generated evaluation report: confusion matrix, metrics, rule breakdown. |
| `DEMO_GUIDE.md` | Four-minute presentation script with an offline backup. |
| `package.json` | npm script shortcuts only; the extension has no dependencies. |

## How detection works

Each rule that fires adds its weight to a 0–100 risk score and produces a finding with a title, an explanation and the concrete evidence:

| Rule | Weight |
| --- | --- |
| Sender domain imitates a brand (look-alike characters, typos, brand + "secure"/"login" etc., brand in subdomain) | 40 |
| Display name claims a brand the sender domain does not belong to (40 if sent from free webmail) | 30–40 |
| Display name contains a different email address | 35 |
| Link text shows one domain but the link opens another | 30 |
| Link goes to a domain imitating a brand | 30 |
| Punycode / non-Latin characters in a domain | 30 |
| Link to a raw IP address | 25 |
| Dangerous attachment (executable, double extension, macro document, HTML, archive) | 10–50 |
| Requests for passwords, payment or personal data | 10 each, max 30 |
| Urgency or threat language | 5 each, max 20 |
| URL shortener, abused top-level domain (.xyz, .top, .zip, …) | 10 |
| Generic greeting ("Dear Customer") | 5 |

Verdicts: score ≥ 60 is **likely phishing**, ≥ 30 is **suspicious**, below 30 is **low risk**. Senders on the trusted list get the verdict **trusted**, but their findings are still shown.

## Manifest V3 and privacy design

- **No in-memory state across worker sleep.** `background.js` keeps everything in `chrome.storage.local` (`tabResults`, `trustedSenders`). Results for closed tabs and previous browser sessions are removed.
- **No remote code.** There is no `eval`, `new Function` or remote script. The extension pages use the CSP `script-src 'self'`. Email-derived text is only inserted with `textContent`, never `innerHTML`.
- **Local analysis only.** Email content is analyzed inside the content script and never sent anywhere. Only the results (verdict, score, findings, subject and sender) are stored, locally.
- **Untrusted input is validated.** The service worker accepts results only from top-level Gmail frames, and only trust changes from Gmail or the popup. It validates and size-limits every field before storing it.

## Commands

All commands run from the project folder. None of them needs `npm install` except the end-to-end tests and the demo.

| Command | Does |
| --- | --- |
| `npm test` (or `node tests/run-node.js`) | 45 Node unit tests |
| `npm run evaluate` (or `node tests/evaluate-metrics.js`) | Runs the labeled evaluation set and rewrites `EVALUATION.md` |
| `npm run check-manifest` | Manifest V3 / store checks only |
| `npm run package` (or `node scripts/package.js`) | Checks, then writes `phishguard-extension.zip` |
| `npm run test:e2e` | 24 end-to-end checks against the real extension (needs the e2e setup below) |
| `npm run demo` | Offline demo: Chromium with the extension and sample emails (see `DEMO_GUIDE.md`) |

## Evaluation

`tests/evaluate-metrics.js` runs the unmodified analyzer over 36 labeled emails (19 phishing, 17 benign) in `tests/fixtures/evaluation-set.js` and writes `EVALUATION.md`. Results at the time of writing, counting any warning as a detection:

| Accuracy | Precision | Recall | False-positive rate |
| ---: | ---: | ---: | ---: |
| 91.7% | 94.4% | 89.5% | 5.9% |

See `EVALUATION.md` for the confusion matrices, the per-rule breakdown, and an analysis of the three misclassified emails. The dataset is small and hand-built, so treat these as behaviour on known patterns, not real-world performance.

## Packaging

`npm run package` first checks the manifest:
- valid version string
- name and description length limits (75 / 132 characters)
- only the `storage` permission and Gmail host access
- service worker background
- a strict CSP
- 16/48/128 PNG icons of the right size
- no `eval` or remote scripts

It then zips only the files referenced by `manifest.json` and `popup.html`, which is 12 runtime files at about 26 KB. Since the zip is built from that list, `tests/`, `node_modules/`, screenshots, docs and git files are never included. The resulting `phishguard-extension.zip` can be uploaded to the Chrome Web Store or submitted as-is. To try it, unzip it and use **Load unpacked** on the extracted folder.

## Tests

- Node (no `npm install` needed): `node tests/run-node.js`
- Browser: serve the folder over HTTP (for example `npx http-server` or `python -m http.server`), then open `tests/test-runner.html`. This also runs the Gmail adapter tests against mock Gmail markup.
- Real-extension smoke test (dev-only, uses Playwright; the extension itself stays dependency-free):

  ```
  cd tests/e2e
  npm install
  npx playwright install chromium
  npm test            # set HEADED=1 to watch
  ```

  This loads the unpacked extension into Chromium (`--load-extension`) and serves Gmail-like pages at `https://mail.google.com/` through request interception, so the real service worker, content scripts and popup run. It checks:
   - banner colors, placement and the reasons toggle
   - the toolbar badge
   - single-message, thread, lazy-loaded and renamed-markup views
   - Trust and Remove for senders
   - the popup's contents
   - stopping and restarting the service worker
   - per-tab storage cleanup when tabs close

  Screenshots are saved to `tests/e2e/screenshots/`. To run the same checks against the packaged build, set `PHISHGUARD_EXTENSION_DIR` to the unzipped `phishguard-extension.zip` folder.

`popup.html` can also be opened as a normal tab for debugging: `chrome-extension://<id>/popup.html?tabId=<tab id>` shows a specific tab. Without `tabId`, it shows the most recently scanned Gmail tab.

## Known limitations

- Gmail's class names (`div.adn`, `div.a3s`, `span.gD`, `h2.hP`) are undocumented and may change. All selectors are kept in `providers/gmail.js`, and each has fallbacks based on longer-lived attributes (`data-message-id`, `div.ii`, the `[email]` attribute inside the sender `h3`, and the page title). When a fallback is used, the console shows `[PhishGuard] Gmail markup differs from what PhishGuard expects: …`. The same warning appears when a conversation looks open but no message could be extracted for 5 seconds.
- Domain parsing uses a small built-in list of multi-part suffixes instead of the full Public Suffix List.
- The brand list is curated, so impersonation of brands that aren't on it is only caught by the generic rules.
- Heuristics cannot see email headers (SPF, DKIM, DMARC, Reply-To) because Gmail does not expose them in the page.
- Newsletters that route links through click-tracking domains can trigger the link-text-mismatch rule.
- Phrase rules match whole words, so variants such as "gift cards" or "urgently" are not matched by `gift card` or `urgent`.

## Presenting

`DEMO_GUIDE.md` has a timed four-minute script:
- the threat and the architecture
- a live walkthrough of the benign, suspicious and phishing emails and the trust toggle
- the evaluation results and limitations
- how to prepare the sample emails in Gmail

If Gmail or the network fails, `npm run demo` runs the real extension on local sample emails with no internet needed.

## Adding another webmail provider

Create `providers/<name>.js` that pushes an object with `id`, `matches(location)` and `findOpenMessages(document, location)` onto `globalThis.PhishGuardProviders` (see `providers/gmail.js`). Then add the file and the site's URL pattern to `manifest.json`.
