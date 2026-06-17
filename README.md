# PhishGuard AI – Free, Zero‑Cost Phishing Detection Demo

## Overview
This is a **completely free** web‑based prototype that lets users paste any text (email, SMS, message, URL) and instantly receive a **risk score** using client‑side keyword heuristics. No external APIs, no paid services, and no server‑side components – everything runs in the browser.

## Why No Cost?
- **No third‑party API keys** – the detection logic lives in `script.js` and uses a static list of phishing‑related keywords.
- **Static hosting** – the site consists of only three static files (`index.html`, `style.css`, `script.js`). Host it on any free static site provider (GitHub Pages, Netlify, Vercel, Cloudflare Pages) without any charge.
- **Open‑source tooling** – all dependencies are plain HTML + CSS + JavaScript; no build tools, npm packages, or cloud services needed.

## How to Run Locally (Zero Setup)
1. Open `index.html` directly in a browser (double‑click the file or run `start index.html` from PowerShell).
2. Paste a sample message into the textarea and click **Detect**.
3. Observe the animated risk score and explanatory text.

## Free Deployment Options
| Platform | Steps | Cost |
|----------|-------|------|
| **GitHub Pages** | Push the three files to a repo and enable Pages from the `main` branch. | Free |
| **Netlify** | Drag‑and‑drop the folder onto the Netlify dashboard. | Free tier (no credit‑card required) |
| **Vercel** | Connect a GitHub repo and deploy. | Free tier |
| **Cloudflare Pages** | Link a repo and deploy. | Free |

## Extending Without Paying
If you later want a smarter model **still for free**, consider loading a tiny TensorFlow.js model that runs entirely in‑browser (e.g., a small Naïve Bayes classifier trained on a public phishing dataset). The model file can be hosted alongside the static assets and loaded with `tf.loadLayersModel()`. This adds no monetary cost, only a modest increase in page size.

---
*Built for Hackverse X – showcase a functional, elegant UI with zero‑cost backend.*
