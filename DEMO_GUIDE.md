# PhishGuard Mail Analyzer: 4-Minute Demo Guide

A timed script for the live presentation, with a backup path that works with no Wi-Fi and no Gmail.

| Time | Segment | What's on screen |
| --- | --- | --- |
| 0:00 – 0:30 | 1. Threat overview | Title slide or README |
| 0:30 – 1:15 | 2. Architecture and security design | Architecture diagram below |
| 1:15 – 3:00 | 3. Live walkthrough | Gmail (or the offline demo) |
| 3:00 – 3:40 | 4. Evaluation results | `EVALUATION.md` |
| 3:40 – 4:00 | 5. Limitations and close | `EVALUATION.md` section 8 |

---

## Before the presentation (do this the day before)

1. **Load the extension:** go to `chrome://extensions`, turn on Developer mode, click **Load unpacked**, and select the project folder. Then pin PhishGuard from the puzzle-piece menu so the badge is visible.
2. **Prepare three emails in Gmail** by sending them to yourself from a second account:

   | Email | How to make it | Expected result |
   | --- | --- | --- |
   | Benign | Any real notification (GitHub, LMS, a classmate). | Green banner, `OK` badge |
   | Suspicious | Set the second account's display name to **Amazon Support**. Body: "There was a problem with your recent order. Reply to resolve it." | Orange banner, `?` badge, score 40 |
   | Phishing | Display name **PayPal Security**. Body: "Dear Customer, unusual activity was detected. Please verify your account within 24 hours or your account will be suspended." Insert a link (Ctrl+K) with text `https://www.paypal.com/signin` and web address `http://paypa1-security.com/login`. | Red banner, `!` badge, score 90+ |

   Gmail blocks `.exe` attachments, so show the **dangerous attachment** rule with the offline demo, which has `PayPal_Invoice_2026.pdf.exe`.
3. **Test the backup:** run `cd tests/e2e && npm install && npx playwright install chromium && npm run demo` once while you have internet. After that it works offline.
4. **Open these tabs ahead of time:** `EVALUATION.md` (rendered preview) and this guide.

---

## 1. Threat overview (0:00 – 0:30)

> "Phishing is still the most common way attackers get initial access. They copy a brand like PayPal, register a look-alike domain like `paypa1-security.com`, hide the real link behind trusted-looking text, and pressure you with urgency. Spam filters catch a lot, but some still reach the inbox, and users rarely get told *why* an email is dangerous. PhishGuard is a Chrome extension that analyzes each email you open in Gmail and explains, in plain language, exactly which warning signs it found."

## 2. Architecture and security design (0:30 – 1:15)

```
 Gmail page (mail.google.com)
 ┌──────────────────────────────────────────────────────────┐
 │ content.js  ── watches for opened emails (MutationObserver)│
 │   ├─ providers/gmail.js  extract sender, links, body, attachments
 │   ├─ analyzer.js         13 heuristic rules → score 0-100 + reasons
 │   └─ ui.js               banner built with textContent only
 └───────────────┬──────────────────────────────────────────┘
                 │ chrome.runtime.sendMessage (results only, no body text)
 ┌───────────────▼──────────────┐      ┌──────────────────────────┐
 │ background.js (MV3 service   │◄────►│ chrome.storage.local      │
 │ worker, stops when idle)     │      │ tabResults, trustedSenders│
 │ validates input, sets badge  │      └────────────▲─────────────┘
 └──────────────────────────────┘                   │
                                        popup.html / popup.js
```

> "There are four design points."

- **Local-only analysis:** "`analyzer.js` is pure JavaScript with zero network calls. Email content never leaves the browser, and only the verdict and reasons are stored."
- **Manifest V3 ephemeral service worker:** "Chrome can stop `background.js` at any time, so it keeps no state in memory. Everything lives in `chrome.storage.local`. Our end-to-end test literally stops the worker and checks that nothing is lost and closed tabs are still cleaned up."
- **XSS safety:** "Email content is attacker-controlled, so the banner never uses `innerHTML`. Every string goes in through `textContent`, there is no `eval`, and the extension's content security policy is `script-src 'self'`."
- **Least privilege and input validation:** "The only permissions are `storage` and `mail.google.com`. The service worker treats messages from the Gmail page as untrusted: it checks the sender and size-limits every field."
- **Adapter layer:** "Gmail-specific selectors are isolated in `providers/gmail.js`, with fallbacks and console warnings if Gmail changes its markup."

## 3. Live walkthrough (1:15 – 3:00)

**3a. Benign email, about 20 seconds.** Open the benign email.
> "A normal email gets a small green *Low risk* banner and an `OK` badge on the toolbar icon. No warning signs, so nothing to read."

**3b. Suspicious email, about 30 seconds.** Open the "Amazon Support" email.
> "This one is orange with a `?` badge. Click **Why?**: the sender name says Amazon, but it was sent from a free Gmail address that Amazon never uses. That's worth 40 points, which crosses the 30-point *suspicious* threshold. The reasons are collapsible, so users aren't overwhelmed."

**3c. High-risk phishing, about 35 seconds.** Open the "PayPal Security" email.
> "Now red, with a `!` badge, and the reasons are expanded automatically. Each reason shows its points: brand impersonation from free webmail (+40), and link text that shows `paypal.com` but actually opens `paypa1-security.com` (+30). Urgency phrases and a request to verify the account add more. The score is capped at 100. Every reason includes the actual evidence, so the user learns the pattern, not just the verdict."

Hover the link to show the real destination matches the evidence. If you're on the offline demo, also point out the `.pdf.exe` attachment reason: "disguised as .pdf, really .exe".

**3d. Trust sender toggle, about 20 seconds.** Click **Trust sender**.
> "If PhishGuard is wrong about a sender, the user can trust that exact address. It asks for confirmation on a red email, because trusting a phisher is the worst mistake. The banner turns blue but still says how many indicators were detected."

Open the toolbar popup:
> "The popup shows the verdict, score and reasons, plus the trusted-senders list. Click **Remove**, and the banner in Gmail goes red again immediately."

## 4. Evaluation results (3:00 – 3:40)

Show `EVALUATION.md`, sections 2 and 5.

> "We evaluated the unmodified analyzer on 36 labeled emails: 19 phishing and 17 benign, including deliberately hard cases. Counting any warning as a detection:"

| Metric | Value |
| --- | ---: |
| Accuracy | 91.7% (33 / 36) |
| Precision | 94.4% (17 TP, 1 FP) |
| Recall | 89.5% (17 of 19 phishing caught) |
| False-positive rate | 5.9% (1 of 17 benign) |

> "If we only count the red *likely phishing* verdict, precision is 100% but recall drops to 47%. The orange tier is what catches the rest. The most useful rule was brand impersonation: it fired on 58% of phishing emails and never on a benign one."

## 5. Limitations and close (3:40 – 4:00)

> "There are three honest limitations."
> 1. "**DOM fragility:** Gmail's class names are undocumented and can change. Our fallbacks and warnings reduce the risk, but don't remove it."
> 2. "**No SPF, DKIM or DMARC:** Gmail doesn't put the raw authentication headers in the page, so we can't verify that the sender address is genuine. Both of our misses, a gift-card BEC scam and a lure on a clean new domain, need that kind of signal, or domain reputation."
> 3. "**Click-tracking false positives:** our one false alarm was a Mailchimp newsletter whose links go through a tracking domain. The *Trust sender* button handles repeat senders."
>
> "PhishGuard shows that useful, *explainable* phishing detection can run entirely in the browser without sending a single byte of email to a server. Thank you."

---

## Backup: offline demo (no Wi-Fi or Gmail needed)

Use this if Gmail won't load, the account is locked, or the network is down. Each option needs less setup than the one before it.

**A. Real extension on local Gmail-like pages (best backup).** This runs the actual extension: banner, badge, popup and trust toggle all work.
```
cd tests/e2e
npm run demo
```
A Chromium window opens with these tabs:
- Benign (green)
- Suspicious (orange)
- Phishing (red, with the `.pdf.exe` attachment)
- A thread with mixed verdicts
- The unit-test page

The terminal prints a popup link for each tab (`chrome-extension://…/popup.html?tabId=…`). You can also pin the extension and click its icon. Follow the walkthrough in section 3 unchanged, and close the window when you're done.

**B. Automated proof, about 1 minute.**
```
npm run test:e2e      # 24 end-to-end checks against the real extension
npm test              # 45 Node unit tests
npm run evaluate      # prints the confusion matrix
```

**C. Browser unit-test page.** Serve the folder (for example `python -m http.server`), then open `http://localhost:8000/tests/test-runner.html` to show 53 passing tests. Option A already opens this page as its last tab.

**D. Static fallback.** Show the screenshots saved by the last end-to-end run in `tests/e2e/screenshots/`:
- `phishing-banner.png`
- `thread-view.png`
- `popup-thread.png`
- `trusted-banner.png`
- `popup-trusted.png`

---

## Likely questions

- **"Why not use machine learning?"** Explainability and privacy. Every point in the score maps to a rule a user can understand, and nothing needs a server or training data. An ML model could be added later as one more local signal.
- **"Can an attacker bypass it?"** Yes. An email with no brand, no look-alike domain and no links scores low (see the business email compromise miss). PhishGuard is a second layer on top of Gmail's own filtering, not a replacement.
- **"What does it store?"** Only the verdict, score, reasons, subject and sender for emails open in each tab, and those are deleted when the tab closes. Trusted senders persist until removed. Email bodies are never stored.
- **"Why does the score cap at 100?"** It's a risk indicator, not a probability. The red threshold is 60, so several strong signals together are already conclusive.
