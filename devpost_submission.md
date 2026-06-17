# Devpost Submission Details

### Project Title
PhishGuard Secure

### One-line tagline
A local-first, zero-leakage, explainable phishing detection sandbox powered by client-side heuristics and LLM analytics.

### The Problem it Solves
Linguistic attacks and credential harvesting scams are the primary threat vectors for security compromise. Existing cloud security solutions submit raw email payloads to remote systems, violating privacy policies and incurring continuous subscription billing. PhishGuard Secure runs fully in browser memory, checking payloads and domains offline without data leakage or server cost.

### How it Works
1. **Linguistic Parser Engine**: Scans text against 200+ signatures across 7 weighted layers (Urgency: 25, Harvesting: 30, Untrusted Hostnames: 20, Financial Bait: 20, Social Engineering: 15, Brand Impersonation: 15, and Structured Information Requests: 20) and computes a threat index:
   $$\text{Threat Index} = \min\left(100, \frac{\sum (\text{Category Score} \times \text{Category Weight})}{\sum \text{Category Weight}}\right)$$
2. **Lexical Regex Highlight Engine**: Sorts patterns by length and maps matches to styling wrappers, color-coding risk phrases.
3. **Heuristic Domain Auditor**: Breaks down URLs to check for HTTPS presence, redirect shortening loops, lexical spoof patterns, hyphen parameters, and query signatures against an extensible brand database.
4. **LLM contextual summary**: For scores > 30, it securely triggers the Anthropic Claude API (claude-3-5-sonnet) directly from the client side to generate a 2-sentence contextual explanation.
5. **Local Logging**: Stores historical session logs in localStorage for complete offline integrity.

### Technologies Used
- HTML5, CSS3 (glassmorphism/dark mode system)
- Vanilla ES2022 JavaScript
- Anthropic Claude API (direct client-side access)
- Browser LocalStorage API

### What Makes it Unique
- **Zero Network Exposure**: Threat extraction runs offline without server dependencies.
- **Explainable Scoring**: Displays inline markers showing why a message was classified under a specific category.
- **Minimalist Aesthetic**: Clean, responsive layout utilizing semantic design without animations.

### Future Improvements
- Tiny TensorFlow.js ML model loaded locally.
- Mail Client EML/MSG parser extension.
- Chromium offline threat auditing plugin.
