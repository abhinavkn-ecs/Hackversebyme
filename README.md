# Hackversebyme – PhishGuard Secure

PhishGuard Secure is a local-first, zero-cost, client-side phishing and threat detection web application designed to analyze messages and domain structures for security threats. Built using vanilla HTML5, CSS, and modern JavaScript, the application executes entirely within the user's browser memory workspace. Because it performs all analyses locally without initiating external API requests or outbound network handshakes, it ensures absolute data privacy—preventing sensitive corporate email content or credentials from leaking onto external networks.

## Core Features

*   **7-Layer Message Threat Analyzer:** Scans raw messages, email body copy, or SMS texts against 7 distinct threat categories (Urgency, Harvesting, Untrusted URLs, Financial Bait, Social Engineering, Brand Impersonation, and Structured Info Requests) to compute a precise threat index.
*   **Domain Integrity Checker:** Inspects suspicious hostnames and links for structural manipulation, transport insecurity (HTTP), domain shortening masks, suspicious top-level domains (TLDs like `.xyz` or `.tk`), brand spoofing, and dangerous URL query parameters.
*   **Explainable Risk Scoring:** Features interactive visual score rings (0 to 100) with corresponding severity classification badges (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
*   **Dynamic Visual Pattern Markup:** Automatically highlights flagged keyphrases in the analyzed text with color-coded markers matching the threat category, helping users trace the exact reason for the flag.
*   **Security Operations (SecOps) Metrics Dashboard:** Displays historical analytics logs, threat type distributions, and local workstation session volumes.
*   **Structured Report Export:** Automatically compiles threat intelligence reports formatted with timestamps, metric breakdowns, and original payload buffers, ready to copy to the clipboard in one click.
*   **Zero-Cost Static Architecture:** Fully self-contained inside three static assets (`index.html`, `style.css`, `script.js`), allowing deployment to any free hosting tier (GitHub Pages, Netlify, Vercel) with zero operational fees.

---

## Technical Specifications

### Implementation Context
- **Strict Local Sandbox Isolation** – No telemetry collected, no cookies, and zero external network requests.
- **Vanilla Web Stack** – Pure HTML5, Vanilla CSS3 (glassmorphism/dark mode system), and ES2022 JavaScript.
- **Persistence** – Data stored in browser-level `localStorage` indexes.
- **Zero Package Dependencies** – Lightweight, secure, and fast with no `npm install` requirements.

### Threats Matrix Covered
- Email Phishing & Spear-Phishing Payloads
- SMS Smishing & WhatsApp Redirects
- Malicious Domain & Sub-domain Redirects
- Brand Spoofing (impersonating financial/social services)
- Advance-Fee Schemes & Financial Baits
- Credential Harvesting Page Signatures

---

## How It Works (Under the Hood)

### 1. Linguistic Parser & Weighted Threat Indexing
When text is submitted, the engine processes it against a signature database containing over 200 pattern vectors across 7 categories. It calculates hits for each category, normalizes them, and processes them through a priority-weighted average formula:

$$
\text{Threat Index} = \min\left(100, \frac{\sum (\text{Category Score} \times \text{Category Weight})}{\sum \text{Category Weight}}\right)
$$

The categories are weighted according to severity:
*   **Credential Harvesting** (Weight: 30) – e.g. `confirm your password`, `verify identity`
*   **Urgency Signatures** (Weight: 25) – e.g. `account locked`, `expires today`
*   **Structured Info Request** (Weight: 20) – e.g. `social security`, `mother maiden`
*   **Financial Bait** (Weight: 20) – e.g. `won jackpot`, `transfer funds`
*   **Untrusted Hostnames** (Weight: 20) – e.g. `bit.ly`, `http://`
*   **Social Engineering** (Weight: 15) – e.g. `IRS`, `kindly`, `official notice`
*   **Brand Impersonation** (Weight: 15) – e.g. `paypal`, `google`, `wells fargo`

### 2. Lexical Regex Highlight Engine
A dynamic regular expression compiler sorts matched phrases by string length to prevent overlapping match bugs, replacing matching keywords with `<mark class="[category-class]">` tags to highlight threats in real time.

### 3. Heuristic Domain Auditor
The domain inspector parses URL inputs into component segments and tests them against:
*   **Transport Security:** Verifies whether `https://` is active.
*   **Shortener Vectors:** Matches domain patterns against known URL shortener domains (like `bit.ly`, `tinyurl.com`).
*   **Brand Checksums:** Analyzes hostnames for brand spoofing (e.g., checking if a domain contains the word `paypal` but does not resolve to `paypal.com` or `paypal.net`).
*   **Lexical Integrity:** Flags domains with high hyphen counts (`-`) and phishing parameters in queries (e.g., containing key-value pairs like `verify`, `token`, `login`).

---

## How to Run Locally (Zero Setup)

1. Open `index.html` directly in a browser (double-click the file or run `start index.html` from PowerShell).
2. Paste a sample message into the textarea on the **Message Inspect** page and click **Scan Payload**.
3. Go to the **Domain Inspect** page to check URLs for redirect masking and brand spoofing.
4. View metrics and historical logs under the **Analytics** tab.

## Free Deployment Options

| Platform | Steps | Cost |
|----------|-------|------|
| **GitHub Pages** | Push the three files to a repo and enable Pages from the `main` branch. | Free |
| **Netlify** | Drag-and-drop the project folder onto the Netlify dashboard. | Free |
| **Vercel** | Connect your GitHub repository to Vercel and auto-deploy. | Free |
| **Cloudflare Pages** | Link your GitHub repository and build static files. | Free |

---
*Built for Hackverse X – showcasing a functional, elegant security UI with zero-cost backend dependency.*
