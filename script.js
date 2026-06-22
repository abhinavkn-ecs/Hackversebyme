// ── PhishGuard Secure Threat Intelligence Engine ──

// ─── THREAT INTELLIGENCE CATEGORIES ──────────────────────────
const CATS = [
  { id:'urgency',  name:'Urgency Signature',      color:'#fef08a', cls:'m-urgency',  w:25,
    kw:['urgent','immediately','right away','action required','act now','limited time','expires today','last chance','suspended','disabled','terminated','within 24 hours','within 48 hours','respond immediately','failure to respond','final warning','warning','account locked'] },
  { id:'cred',     name:'Harvesting Signature',   color:'#fee2e2', cls:'m-cred',     w:30,
    kw:['verify your account','confirm your password','enter your password','update your credentials','login to verify','sign in to confirm','provide your username','submit your details','re-enter','otp','one-time password','security code','verify identity','confirm your email','validate your account','reset your password'] },
  { id:'url',      name:'Untrusted Hostnames',    color:'#dbeafe', cls:'m-url',      w:20,
    kw:['bit.ly','tinyurl','goo.gl','ow.ly','rb.gy','shorturl','click here','click this link','click the link','open this link','follow this link','login link','secure-','account-','banking-','paypal-','amazon-','apple-login','google-secure','microsoft-account','.xyz','.tk','.ml','http://'] },
  { id:'finance',  name:'Financial Bait Signature',color:'#dcfce7', cls:'m-financial',w:20,
    kw:['prize','winner','won','lottery','jackpot','gift card','cash reward','refund','compensation','claim your reward','free money','investment','profit','crypto','bitcoin','transfer funds','wire transfer','bank details','payment required','congratulations','you have been chosen','inheritance'] },
  { id:'social',   name:'Social Engineering Signature',color:'#f3e8ff', cls:'m-social',   w:15,
    kw:['your boss','your manager','ceo','hr department','it department','tech support','customer service','helpdesk','government','irs','police','fbi','official notice','legal action','debt collector','court order','kindly','dear customer','dear user','dear friend','trusted partner'] },
  { id:'imperson', name:'Brand Impersonation',    color:'#ffedd5', cls:'m-imperson',   w:15,
    kw:['paypal','amazon','apple','google','microsoft','netflix','facebook','instagram','whatsapp','your bank','chase bank','wells fargo','bank of america','citibank','irs','fedex','ups','dhl','usps','docusign','dropbox','zoom'] },
  { id:'sensitive',name:'Structured Info Request',color:'#fae8ff', cls:'m-sensitive',     w:20,
    kw:['social security','ssn','date of birth','dob','credit card','card number','cvv','expiry date','bank account','routing number','passport','driver license','tax id','mother maiden','security question','full name and address','national id'] }
];

// EXTENSIBLE BRAND SPOOF LIST: Add brand names here in lowercase to check for domain spoofing.
const BRAND_SPOOF_LIST = [
  'paypal','google','apple','microsoft','amazon','netflix',
  'facebook','instagram','whatsapp','chase','wellsfargo',
  'citibank','bankofamerica','fedex','ups','dhl','usps',
  'docusign','dropbox','zoom','bank'
];

// Recognised legitimate TLDs per brand (used in domain spoofing check)
const LEGIT_TLDS = ['.com', '.net', '.org', '.edu', '.gov'];

// ─── STATE ───────────────────────────────────────────────────
let history = [];
try {
  history = JSON.parse(localStorage.getItem('pg_h') || '[]');
  if (!Array.isArray(history)) history = [];
} catch {
  history = [];
}

// ─── DOM READY ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Cache DOM references once
  const $ = (id) => document.getElementById(id);
  const scanInput        = $('scanInput');
  const urlInput         = $('urlInput');
  const scanDetect       = $('scanDetectBtn');
  const scanClear        = $('scanClearBtn');
  const validationError  = $('validationError');
  const safeMessageBanner= $('safeMessageBanner');
  const scanResult       = $('scanResult');
  const scoreNum         = $('scoreNum');
  const severityBadge    = $('severityBadge');
  const scoreGaugeFill   = $('scoreGaugeFill');
  const breakdownPanel   = $('breakdownPanel');
  const aiAnalysisText   = $('aiAnalysisText');
  const domainAuditList  = $('domainAuditList');
  const highlightText    = $('highlightText');
  const historySection   = $('historySection');
  const historyTableBody = $('historyTableBody');
  const exportLogsBtn    = $('exportLogsBtn');
  const toggleHistoryBtn = $('toggleHistoryBtn');
  const brandInfoBtn     = $('brandInfoBtn');
  const brandListCard    = $('brandListCard');
  const themeToggleBtn   = $('themeToggleBtn');

  // ─── THEME ─────────────────────────────────────────────────
  const savedTheme = localStorage.getItem('theme') || 'dark';
  if (savedTheme === 'light') {
    document.body.classList.add('light-theme');
  }

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      document.body.classList.toggle('light-theme');
      const isLight = document.body.classList.contains('light-theme');
      localStorage.setItem('theme', isLight ? 'light' : 'dark');
    });
  }

  // ─── BRAND LIST TOGGLE ─────────────────────────────────────
  if (brandInfoBtn && brandListCard) {
    brandInfoBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const isHidden = brandListCard.style.display === 'none' || brandListCard.style.display === '';
      brandListCard.style.display = isHidden ? 'block' : 'none';
      brandInfoBtn.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
    });
  }

  // ─── HISTORY COLLAPSE ──────────────────────────────────────
  if (toggleHistoryBtn && historySection) {
    const toggleCollapse = () => {
      historySection.classList.toggle('collapsed');
      const expanded = !historySection.classList.contains('collapsed');
      toggleHistoryBtn.setAttribute('aria-expanded', String(expanded));
    };
    toggleHistoryBtn.addEventListener('click', toggleCollapse);
    toggleHistoryBtn.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleCollapse();
      }
    });
  }

  // ─── EXPORT LOGS ───────────────────────────────────────────
  if (exportLogsBtn) {
    exportLogsBtn.addEventListener('click', (e) => {
      e.stopPropagation(); // prevent history toggle
      exportLogs();
    });
  }

  // ─── PRESET TEMPLATES ──────────────────────────────────────
  const PRESETS = {
    'phish-bank': {
      text: 'URGENT SECURITY ALERT: We detected unauthorized login attempts to your Chase Bank account from IP: 192.168.1.109. Please verify your account credentials immediately by clicking the secure login link. Failure to respond within 24 hours will result in permanent suspension of your banking profile.',
      url: 'chase-security-verify.xyz'
    },
    'phish-urgency': {
      text: 'Dear customer, your Microsoft email account password expires today. Reset your password now to avoid service interruption and losing your mailbox files. Enter your password on our secure-portal verification page immediately.',
      url: 'http://microsoft-secure-account.xyz/verify'
    },
    'safe-work': {
      text: 'Hi Team, just a reminder that our weekly progress meeting is scheduled for tomorrow morning at 10 AM. We will review the Q2 roadmap updates and discuss the deployment steps. Let me know if you have any questions or items to add to the agenda.',
      url: 'https://company.internal/wiki'
    }
  };

  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const data = PRESETS[btn.dataset.preset];
      if (data) {
        scanInput.value = data.text;
        urlInput.value = data.url;
        scanDetect.click();
      }
    });
  });

  // ─── CLEAR / RESET ────────────────────────────────────────
  if (scanClear) {
    scanClear.addEventListener('click', () => {
      scanInput.value = '';
      urlInput.value = '';
      validationError.style.display = 'none';
      safeMessageBanner.style.display = 'none';
      scanResult.style.display = 'none';
      highlightText.textContent = 'Scan output highlights will appear here\u2026';
      resetGauge(scoreGaugeFill);
    });
  }

  // ─── MAIN SCAN HANDLER ────────────────────────────────────
  if (scanDetect) {
    scanDetect.addEventListener('click', () => {
      const textVal = scanInput.value.trim();
      const urlVal = urlInput.value.trim();

      // Validate
      if (!textVal) {
        validationError.style.display = 'block';
        return;
      }
      validationError.style.display = 'none';
      safeMessageBanner.style.display = 'none';
      scanResult.style.display = 'none';

      // Analyze
      const analysisResult = analyze(textVal);
      const urlResult = urlVal ? analyzeUrl(urlVal) : null;
      const finalScore = urlResult
        ? Math.max(analysisResult.score, urlResult.score)
        : analysisResult.score;
      const severity = getSeverity(finalScore);

      // Render score with count-up animation
      animateScore(scoreNum, finalScore);
      severityBadge.textContent = severity.label;
      severityBadge.className = `severity-badge ${severity.cls}`;

      // Update SVG gauge
      updateGauge(scoreGaugeFill, finalScore);

      // Safe banner
      safeMessageBanner.style.display = finalScore < 30 ? 'flex' : 'none';

      // Threat breakdown
      const triggeredCats = analysisResult.cats.filter(c => c.hits > 0);
      renderBreakdown(breakdownPanel, triggeredCats);

      // Highlights
      highlightText.innerHTML = buildHighlight(textVal, analysisResult.words);

      // Domain audit
      renderDomainAudit(domainAuditList, urlResult, urlVal);

      // AI summary
      aiAnalysisText.textContent = generateLocalSummary(finalScore, severity.label.toLowerCase(), triggeredCats);

      // Show results with animation
      scanResult.classList.remove('results-animation');
      void scanResult.offsetWidth; // reflow to restart animation
      scanResult.classList.add('results-animation');
      scanResult.style.display = 'block';

      // Log and update history
      saveHistory(textVal, finalScore, severity.label);
      renderHistoryTable(historyTableBody);
    });
  }

  // Initial history render
  renderHistoryTable(historyTableBody);
});

// ─── SEVERITY CLASSIFIER ──────────────────────────────────────
function getSeverity(score) {
  if (score <= 30) return { label: 'Safe', cls: 'badge-safe' };
  if (score <= 60) return { label: 'Suspicious', cls: 'badge-suspicious' };
  if (score <= 85) return { label: 'Likely Phishing', cls: 'badge-likely' };
  return { label: 'Critical', cls: 'badge-critical' };
}

// ─── TEXT ANALYSIS ENGINE ─────────────────────────────────────
function analyze(text) {
  const lo = text.toLowerCase();
  const words = {};
  const cats = CATS.map(cat => {
    let hits = 0;
    const matchedExamples = [];
    for (const kw of cat.kw) {
      if (lo.includes(kw)) {
        hits++;
        if (!words[kw]) words[kw] = cat.cls;
        if (matchedExamples.length < 3) matchedExamples.push(kw);
      }
    }
    // Normalize: scale so 2-3 hits in a category already produce a meaningful score
    const threshold = Math.max(cat.kw.length * 0.2, 1);
    const catScore = Math.min(100, Math.round((hits / threshold) * 100));
    return { ...cat, hits, catScore, matchedExamples };
  });

  const totalWeight = cats.reduce((s, c) => s + c.w, 0);
  const weightedSum = cats.reduce((s, c) => s + c.catScore * c.w, 0);
  const score = Math.min(100, Math.round(weightedSum / totalWeight));

  return { score, cats, words };
}

// ─── HIGHLIGHT BUILDER ────────────────────────────────────────
function buildHighlight(text, words) {
  const keys = Object.keys(words);
  if (!keys.length) return escHTML(text) || 'No text submitted.';

  // Sort by length descending to prevent partial overlap matches
  const sorted = keys.sort((a, b) => b.length - a.length);
  const re = new RegExp('(' + sorted.map(escRE).join('|') + ')', 'gi');

  // We must apply escHTML per-segment to avoid breaking HTML entities in matches
  const parts = text.split(re);
  return parts.map(part => {
    const cls = words[part.toLowerCase()];
    return cls
      ? `<mark class="${cls}">${escHTML(part)}</mark>`
      : escHTML(part);
  }).join('');
}

// ─── DOMAIN / URL ANALYSIS ────────────────────────────────────
function analyzeUrl(raw) {
  let score = 0;
  const checks = [];

  const hasScheme = /^https?:\/\//i.test(raw);
  const cleanUrl = hasScheme ? raw : 'http://' + raw;
  const isSecure = cleanUrl.startsWith('https://');

  checks.push({
    label: 'Transport Layer',
    ok: isSecure ? 'ok' : 'bad',
    text: isSecure ? 'HTTPS Active' : 'Unencrypted HTTP'
  });
  if (!isSecure) score += 25;

  const shortDomains = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'rb.gy', 't.co', 'is.gd', 'buff.ly'];
  const isShort = shortDomains.some(d => cleanUrl.toLowerCase().includes(d));
  checks.push({
    label: 'Redirect Masking',
    ok: isShort ? 'warn' : 'ok',
    text: isShort ? 'Shortened Domain' : 'Direct Target'
  });
  if (isShort) score += 20;

  const suspTLDs = ['.xyz', '.tk', '.ml', '.cf', '.ga', '.gq'];
  const hasSuspTLD = suspTLDs.some(t => cleanUrl.toLowerCase().includes(t));
  checks.push({
    label: 'TLD Evaluation',
    ok: hasSuspTLD ? 'bad' : 'ok',
    text: hasSuspTLD ? 'High-risk TLD extension' : 'Standard TLD'
  });
  if (hasSuspTLD) score += 30;

  // Extract hostname for brand spoofing checks
  let domainPart = '';
  try {
    domainPart = new URL(cleanUrl).hostname.toLowerCase();
  } catch {
    domainPart = cleanUrl.replace(/https?:\/\//, '').split('/')[0].toLowerCase();
  }

  const hasBrandSpoof = BRAND_SPOOF_LIST.some(b =>
    domainPart.includes(b) &&
    !LEGIT_TLDS.some(tld => domainPart.endsWith(b + tld))
  );
  checks.push({
    label: 'Brand Checksum',
    ok: hasBrandSpoof ? 'bad' : 'ok',
    text: hasBrandSpoof ? 'Brand spoofing detected' : 'Neutral Domain Name'
  });
  if (hasBrandSpoof) score += 35;

  const hyphenCount = (domainPart.match(/-/g) || []).length;
  const hasDash = hyphenCount > 1;
  checks.push({
    label: 'Lexical Integrity',
    ok: hasDash ? 'warn' : 'ok',
    text: hasDash ? `High hyphen count (${hyphenCount})` : 'Clean Lexical Structure'
  });
  if (hasDash) score += 10;

  const suspParams = ['token', 'verify', 'account', 'password', 'login', 'redirect', 'confirm'];
  const hasPhishParams = suspParams.some(p => cleanUrl.toLowerCase().includes(p));
  checks.push({
    label: 'Query Parameters',
    ok: hasPhishParams ? 'warn' : 'ok',
    text: hasPhishParams ? 'Phish query signatures' : 'Standard Queries'
  });
  if (hasPhishParams) score += 15;

  return { score: Math.min(100, score), checks };
}

// ─── UI RENDER HELPERS ────────────────────────────────────────
function renderBreakdown(panel, triggeredCats) {
  if (triggeredCats.length > 0) {
    panel.innerHTML = triggeredCats.map(c => `
      <div class="explain-item">
        <div class="explain-header">
          <span class="explain-cat-name">${escHTML(c.name)}</span>
          <span class="explain-meta">${c.hits} hit${c.hits > 1 ? 's' : ''} &middot; Weight: ${c.w}</span>
        </div>
        <div class="explain-examples">Matched: "${c.matchedExamples.map(escHTML).join('", "')}"</div>
      </div>
    `).join('');
  } else {
    panel.innerHTML = '<div style="color: var(--text-light)">No threat signatures matching standard categories were detected.</div>';
  }
}

function renderDomainAudit(container, urlResult, urlVal) {
  if (urlResult) {
    container.innerHTML = urlResult.checks.map(c => `
      <div class="domain-result-row">
        <span class="domain-check-label">${escHTML(c.label)}</span>
        <span class="domain-check-status status-${c.ok}">${escHTML(c.text)}</span>
      </div>
    `).join('');
  } else if (urlVal) {
    container.innerHTML = '<div class="domain-result-row"><span class="domain-check-label">Format Check</span><span class="domain-check-status status-bad">Invalid Hostname URL</span></div>';
  } else {
    container.innerHTML = '<div style="color: var(--text-light)">Submit a domain/URL to inspect.</div>';
  }
}

// ─── GAUGE ANIMATION ──────────────────────────────────────────
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 40; // r=40 → 251.327

function updateGauge(el, score) {
  if (!el) return;
  const offset = GAUGE_CIRCUMFERENCE - (score / 100) * GAUGE_CIRCUMFERENCE;
  el.style.strokeDashoffset = offset;

  let strokeColor, glowColor;
  if (score <= 30) {
    strokeColor = 'var(--sev-safe)';
    glowColor = 'rgba(16, 185, 129, 0.3)';
  } else if (score <= 60) {
    strokeColor = 'var(--sev-susp)';
    glowColor = 'rgba(245, 158, 11, 0.3)';
  } else if (score <= 85) {
    strokeColor = 'var(--sev-likely)';
    glowColor = 'rgba(249, 115, 22, 0.3)';
  } else {
    strokeColor = 'var(--sev-crit)';
    glowColor = 'rgba(236, 72, 153, 0.4)';
  }

  el.style.stroke = strokeColor;
  el.style.filter = `drop-shadow(0 0 6px ${glowColor})`;
}

function resetGauge(el) {
  if (!el) return;
  el.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
  el.style.stroke = 'var(--sev-safe)';
  el.style.filter = 'none';
}

// ─── SCORE COUNT-UP ANIMATION ─────────────────────────────────
function animateScore(el, target) {
  if (!el) return;
  const duration = 600;
  const start = performance.now();

  function tick(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // Ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(eased * target);
    el.innerHTML = `${current}<span>/100</span>`;
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ─── LOCAL AI SUMMARY GENERATOR ───────────────────────────────
function generateLocalSummary(score, level, triggeredCats) {
  if (score <= 30) {
    return 'No threats detected — AI analysis not required.';
  }

  const phrases = triggeredCats.flatMap(c => c.matchedExamples);
  let sentence1, sentence2;

  if (level.includes('critical')) {
    sentence1 = 'This text block represents a highly dangerous, critical-severity credential harvesting or corporate spoofing campaign.';
  } else if (level.includes('likely')) {
    sentence1 = 'This communication indicates a targeted social engineering or financial bait scheme designed to elicit immediate action.';
  } else {
    sentence1 = 'This payload contains mild suspicious markers, primarily triggering warning indicators around urgency and external redirects.';
  }

  if (triggeredCats.some(c => c.id === 'cred' || c.id === 'sensitive')) {
    const examples = phrases.slice(0, 2).map(p => `"${p}"`).join(' and ');
    sentence2 = `It targets identity files and security details using phrase highlights like ${examples}.`;
  } else if (triggeredCats.some(c => c.id === 'urgency')) {
    sentence2 = 'It attempts to induce stress and bypass rational checks by enforcing strict execution constraints.';
  } else if (triggeredCats.some(c => c.id === 'finance')) {
    sentence2 = 'It lures the user with promise triggers of payments or compensation credits.';
  } else {
    sentence2 = 'Security teams suggest confirming the authenticity of the sender channel before clicking embedded hostlinks.';
  }

  return `${sentence1} ${sentence2}`;
}

// ─── LOGGING & HISTORY ─────────────────────────────────────────
function saveHistory(txt, score, severity) {
  const preview = txt.replace(/\n/g, ' ').slice(0, 60) + (txt.length > 60 ? '…' : '');
  const timestamp = new Date().toLocaleString([], { hour12: false });
  history.unshift({ timestamp, score, severity, preview });
  if (history.length > 30) history.length = 30; // truncate efficiently
  try {
    localStorage.setItem('pg_h', JSON.stringify(history));
  } catch {
    // localStorage quota exceeded — silently degrade
  }
}

function renderHistoryTable(tbody) {
  if (!tbody) return;

  if (history.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No execution records logged. Run a scan to populate.</td></tr>';
    return;
  }

  const badgeMap = {
    'Safe': 'badge-safe',
    'Suspicious': 'badge-suspicious',
    'Likely Phishing': 'badge-likely',
    'Critical': 'badge-critical'
  };

  tbody.innerHTML = history.map(h => {
    const cls = badgeMap[h.severity] || 'badge-safe';
    return `
      <tr>
        <td>${escHTML(h.timestamp)}</td>
        <td>${h.score}</td>
        <td><span class="severity-badge ${cls}" style="padding:0.15rem 0.4rem;font-size:0.75rem">${escHTML(h.severity)}</span></td>
        <td style="font-family:monospace">${escHTML(h.preview)}</td>
      </tr>
    `;
  }).join('');
}

function exportLogs() {
  const raw = localStorage.getItem('pg_h') || '[]';
  let formatted;
  try {
    formatted = JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    formatted = raw;
  }
  const blob = new Blob([formatted], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `phishguard-logs-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── UTILITIES ────────────────────────────────────────────────
function escHTML(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escRE(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
