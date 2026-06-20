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
  'paypal',
  'google',
  'apple',
  'microsoft',
  'amazon',
  'netflix',
  'facebook',
  'instagram',
  'whatsapp',
  'chase',
  'wellsfargo',
  'citibank',
  'bankofamerica',
  'fedex',
  'ups',
  'dhl',
  'usps',
  'docusign',
  'dropbox',
  'zoom',
  'bank'
];

// ─── STATE ───────────────────────────────────────────────────
let history = JSON.parse(localStorage.getItem('pg_h') || '[]');

// ─── DOM ELEMENTS ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const scanInput        = document.getElementById('scanInput');
  const urlInput         = document.getElementById('urlInput');
  const scanDetect       = document.getElementById('scanDetectBtn');
  const scanClear        = document.getElementById('scanClearBtn');
  const validationError  = document.getElementById('validationError');
  const safeMessageBanner= document.getElementById('safeMessageBanner');
  const scanResult       = document.getElementById('scanResult');
  const scoreNum         = document.getElementById('scoreNum');
  const severityBadge    = document.getElementById('severityBadge');
  const scoreGaugeFill   = document.getElementById('scoreGaugeFill');
  const breakdownPanel   = document.getElementById('breakdownPanel');
  const aiAnalysisText   = document.getElementById('aiAnalysisText');
  const domainAuditList  = document.getElementById('domainAuditList');
  const highlightText    = document.getElementById('highlightText');
  const historySection   = document.getElementById('historySection');
  const historyTableBody = document.getElementById('historyTableBody');
  const exportLogsBtn    = document.getElementById('exportLogsBtn');
  const toggleHistoryBtn = document.getElementById('toggleHistoryBtn');
  const brandInfoBtn     = document.getElementById('brandInfoBtn');
  const brandListCard    = document.getElementById('brandListCard');
  const themeToggleBtn   = document.getElementById('themeToggleBtn');

  // Initialize theme from localStorage
  const savedTheme = localStorage.getItem('theme') || 'dark';
  if (savedTheme === 'light') {
    document.body.classList.add('light-theme');
  }

  // Theme toggle listener
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      document.body.classList.toggle('light-theme');
      const isLight = document.body.classList.contains('light-theme');
      localStorage.setItem('theme', isLight ? 'light' : 'dark');
    });
  }

  // Toggle brand list tooltip/card
  if (brandInfoBtn && brandListCard) {
    brandInfoBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const isHidden = brandListCard.style.display === 'none' || brandListCard.style.display === '';
      brandListCard.style.display = isHidden ? 'block' : 'none';
    });
  }

  // Toggle collapsible logs
  if (toggleHistoryBtn && historySection) {
    toggleHistoryBtn.addEventListener('click', () => {
      historySection.classList.toggle('collapsed');
    });
  }

  // Export logs listener
  if (exportLogsBtn) {
    exportLogsBtn.addEventListener('click', () => {
      exportLogs();
    });
  }

  // Preset templates listener
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
      const type = btn.getAttribute('data-preset');
      const data = PRESETS[type];
      if (data) {
        scanInput.value = data.text;
        urlInput.value = data.url;
        // Automatically trigger scan for user convenience
        const detectBtn = document.getElementById('scanDetectBtn');
        if (detectBtn) detectBtn.click();
      }
    });
  });

  // Clear inputs and state listener
  if (scanClear) {
    scanClear.addEventListener('click', () => {
      scanInput.value = '';
      urlInput.value = '';
      validationError.style.display = 'none';
      safeMessageBanner.style.display = 'none';
      scanResult.style.display = 'none';
      highlightText.innerHTML = 'Scan output highlights will appear here...';
      if (scoreGaugeFill) {
        scoreGaugeFill.style.strokeDashoffset = 251.327;
        scoreGaugeFill.style.stroke = 'var(--sev-safe)';
        scoreGaugeFill.style.filter = 'none';
      }
    });
  }

  // Scan handler
  if (scanDetect) {
    scanDetect.addEventListener('click', () => {
      const textVal = scanInput.value.trim();
      const urlVal = urlInput.value.trim();

      // Check empty validation
      if (!textVal) {
        validationError.style.display = 'block';
        return;
      }
      validationError.style.display = 'none';
      safeMessageBanner.style.display = 'none';
      scanResult.style.display = 'none';

      // Perform analysis
      const analysisResult = analyze(textVal);
      const urlResult = urlVal ? analyzeUrl(urlVal) : null;

      // Handle combined metrics if URL exists
      let finalScore = analysisResult.score;
      if (urlResult) {
        finalScore = Math.max(analysisResult.score, urlResult.score);
      }

      // Determine severity
      const severity = getSeverity(finalScore);

      // Render Score & Badge
      scoreNum.innerHTML = `${finalScore}<span>/100</span>`;
      severityBadge.textContent = severity.label;
      severityBadge.className = `severity-badge ${severity.cls}`;

      // Update SVG gauge fill and color
      if (scoreGaugeFill) {
        const radius = 40;
        const circumference = 2 * Math.PI * radius; // 251.327
        const offset = circumference - (finalScore / 100) * circumference;
        scoreGaugeFill.style.strokeDashoffset = offset;

        // Change stroke color dynamically based on severity
        let strokeColor = 'var(--sev-safe)';
        let glowColor = 'rgba(16, 185, 129, 0.3)';
        if (finalScore > 30 && finalScore <= 60) {
          strokeColor = 'var(--sev-susp)';
          glowColor = 'rgba(245, 158, 11, 0.3)';
        } else if (finalScore > 60 && finalScore <= 85) {
          strokeColor = 'var(--sev-likely)';
          glowColor = 'rgba(249, 115, 22, 0.3)';
        } else if (finalScore > 85) {
          strokeColor = 'var(--sev-crit)';
          glowColor = 'rgba(236, 72, 153, 0.4)';
        }
        scoreGaugeFill.style.stroke = strokeColor;
        scoreGaugeFill.style.setProperty('--gauge-glow', glowColor);
        scoreGaugeFill.style.filter = `drop-shadow(0 0 6px ${glowColor})`;
      }

      // Render Safe Banner if score < 30
      if (finalScore < 30) {
        safeMessageBanner.style.display = 'flex';
      } else {
        safeMessageBanner.style.display = 'none';
      }

      // Render Threat Breakdown panel
      const triggeredCats = analysisResult.cats.filter(c => c.hits > 0);
      if (triggeredCats.length > 0) {
        breakdownPanel.innerHTML = triggeredCats.map(c => `
          <div class="explain-item">
            <div class="explain-header">
              <span class="explain-cat-name">${c.name}</span>
              <span class="explain-meta">${c.hits} hit${c.hits > 1 ? 's' : ''} &middot; Weight: ${c.w}</span>
            </div>
            <div class="explain-examples">Matched: "${c.matchedExamples.join('", "')}"</div>
          </div>
        `).join('');
      } else {
        breakdownPanel.innerHTML = `<div class="body-text" style="color: var(--text-light)">No threat signatures matching standard categories were detected.</div>`;
      }

      // Render Highlights
      highlightText.innerHTML = buildHighlight(textVal, analysisResult.words);

      // Render Domain Audit Log
      if (urlResult) {
        domainAuditList.innerHTML = urlResult.checks.map(c => `
          <div class="domain-result-row">
            <span class="domain-check-label">${c.label}</span>
            <span class="domain-check-status status-${c.ok}">${c.text}</span>
          </div>
        `).join('');
      } else if (urlVal) {
        domainAuditList.innerHTML = `<div class="domain-result-row"><span class="domain-check-label">Format Check</span><span class="domain-check-status status-bad">Invalid Hostname URL</span></div>`;
      } else {
        domainAuditList.innerHTML = `<div class="body-text" style="color: var(--text-light)">Submit a domain/URL to inspect.</div>`;
      }

      // Generate local security summary
      aiAnalysisText.textContent = generateLocalSummary(finalScore, severity.label.toLowerCase(), triggeredCats);

      // Display the Results Card with Animation
      scanResult.classList.remove('results-animation');
      void scanResult.offsetWidth; // Trigger reflow to restart CSS animation
      scanResult.classList.add('results-animation');
      scanResult.style.display = 'block';

      // Save to logs history list
      saveHistory(textVal, finalScore, severity.label);
      renderHistoryTable();
    });
  }

  // Render history table on load
  renderHistoryTable();
});

// ─── INTERNALS ────────────────────────────────────────────────
function getSeverity(score) {
  if (score <= 30) return { label: 'Safe', cls: 'badge-safe' };
  if (score <= 60) return { label: 'Suspicious', cls: 'badge-suspicious' };
  if (score <= 85) return { label: 'Likely Phishing', cls: 'badge-likely' };
  return { label: 'Critical', cls: 'badge-critical' };
}

function analyze(text) {
  const lo = text.toLowerCase();
  const words = {};
  const cats = CATS.map(cat => {
    let hits = 0;
    const matchedExamples = [];
    cat.kw.forEach(kw => {
      if (lo.includes(kw)) {
        hits++;
        if (!words[kw]) words[kw] = cat.cls;
        if (matchedExamples.length < 2) {
          matchedExamples.push(kw);
        }
      }
    });
    const catScore = Math.min(100, Math.round((hits / Math.max(cat.kw.length * 0.22, 1)) * 100));
    return { ...cat, hits, catScore, matchedExamples };
  });

  const totalWeight = cats.reduce((s, c) => s + c.w, 0);
  const weightedSum = cats.reduce((s, c) => s + c.catScore * c.w, 0);
  const score = Math.min(100, Math.round(weightedSum / totalWeight));

  return { score, cats, words };
}

function buildHighlight(text, words) {
  if (!Object.keys(words).length) {
    return escHTML(text) || 'No text submitted.';
  }
  const sorted = Object.keys(words).sort((a, b) => b.length - a.length);
  const re = new RegExp('(' + sorted.map(escRE).join('|') + ')', 'gi');
  return escHTML(text).replace(re, m => `<mark class="${words[m.toLowerCase()] || 'm-social'}">${m}</mark>`);
}

function analyzeUrl(raw) {
  let score = 0;
  const checks = [];

  const hasHTTPS = raw.startsWith('https://') || raw.startsWith('http://');
  const cleanUrl = hasHTTPS ? raw : 'http://' + raw;
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

  const suspTLD = ['.xyz', '.tk', '.ml', '.cf', '.ga', '.gq'];
  const hasSuspTLD = suspTLD.some(t => cleanUrl.toLowerCase().includes(t));
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
  } catch (e) {
    domainPart = cleanUrl.replace(/https?:\/\//, '').split('/')[0].toLowerCase();
  }

  const hasBrandSpoof = BRAND_SPOOF_LIST.some(b => 
    domainPart.includes(b) && 
    !domainPart.endsWith(b + '.com') && 
    !domainPart.endsWith(b + '.net') && 
    !domainPart.endsWith(b + '.org') &&
    !domainPart.endsWith(b + '.edu') &&
    !domainPart.endsWith(b + '.gov')
  );
  checks.push({
    label: 'Brand Checksum',
    ok: hasBrandSpoof ? 'bad' : 'ok',
    text: hasBrandSpoof ? 'Brand spoofing detected' : 'Neutral Domain Name'
  });
  if (hasBrandSpoof) score += 35;

  const hasDash = (domainPart.match(/-/g) || []).length > 1;
  checks.push({
    label: 'Lexical Integrity',
    ok: hasDash ? 'warn' : 'ok',
    text: hasDash ? 'High hyphens count' : 'Clean Lexical Structure'
  });
  if (hasDash) score += 10;

  const suspParams = ['token', 'verify', 'account', 'password', 'login', 'redirect', 'confirm'].some(p => 
    cleanUrl.toLowerCase().includes(p)
  );
  checks.push({
    label: 'Queries Parameter',
    ok: suspParams ? 'warn' : 'ok',
    text: suspParams ? 'Phish query signatures' : 'Standard Queries'
  });
  if (suspParams) score += 15;

  score = Math.min(100, score);

  return { score, checks };
}

// ─── LOCAL SECURITY SUMMARY GENERATOR ─────────────────────────
function generateLocalSummary(score, level, triggeredCats) {
  if (score <= 30) {
    return 'No threats detected — AI analysis not required.';
  }

  const catNames = triggeredCats.map(c => c.name);
  const phrases = triggeredCats.flatMap(c => c.matchedExamples);

  let sentence1 = "";
  let sentence2 = "";

  if (level.includes('critical')) {
    sentence1 = `This text block represents a highly dangerous, critical-severity credential harvesting or corporate spoofing campaign.`;
  } else if (level.includes('likely')) {
    sentence1 = `This communication indicates a targeted social engineering or financial bait scheme designed to elicit immediate action.`;
  } else {
    sentence1 = `This payload contains mild suspicious markers, primarily triggering warning indicators around urgency and external redirects.`;
  }

  if (triggeredCats.some(c => c.id === 'cred' || c.id === 'sensitive')) {
    sentence2 = `It targets identity files and security details using phrase highlights like ${phrases.slice(0, 2).map(p => `"${p}"`).join(' and ')}.`;
  } else if (triggeredCats.some(c => c.id === 'urgency')) {
    sentence2 = `It attempts to induce stress and bypass rational checks by enforcing strict execution constraints.`;
  } else if (triggeredCats.some(c => c.id === 'finance')) {
    sentence2 = `It lures the user with promise triggers of payments or compensation credits.`;
  } else {
    sentence2 = `Security teams suggest confirming the authenticity of the sender channel before clicking embedded hostlinks.`;
  }

  return `${sentence1} ${sentence2}`;
}

// ─── LOGGING & HISTORY ─────────────────────────────────────────
function saveHistory(txt, score, severity) {
  const preview = txt.replace(/\n/g, ' ').slice(0, 60) + (txt.length > 60 ? '...' : '');
  const timestamp = new Date().toLocaleString([], { hour12: false });
  history.unshift({ timestamp, score, severity, preview });
  if (history.length > 30) history.pop();
  localStorage.setItem('pg_h', JSON.stringify(history));
}

function renderHistoryTable() {
  const historyTableBody = document.getElementById('historyTableBody');
  if (!historyTableBody) return;

  if (history.length === 0) {
    historyTableBody.innerHTML = `<tr><td colspan="4" class="empty-state">No execution records logged. Run a scan to populate.</td></tr>`;
    return;
  }

  historyTableBody.innerHTML = history.map(h => {
    let badgeClass = 'badge-safe';
    if (h.severity === 'Suspicious') badgeClass = 'badge-suspicious';
    else if (h.severity === 'Likely Phishing') badgeClass = 'badge-likely';
    else if (h.severity === 'Critical') badgeClass = 'badge-critical';

    return `
      <tr>
        <td>${h.timestamp}</td>
        <td>${h.score}</td>
        <td><span class="severity-badge ${badgeClass}" style="padding: 0.15rem 0.4rem; font-size: 0.75rem;">${h.severity}</span></td>
        <td style="font-family: monospace;">${escHTML(h.preview)}</td>
      </tr>
    `;
  }).join('');
}

function exportLogs() {
  const logs = localStorage.getItem('pg_h') || '[]';
  const blob = new Blob([JSON.stringify(JSON.parse(logs), null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  a.href = url;
  a.download = `phishguard-logs-${timestamp}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ─── UTILS ────────────────────────────────────────────────────
function escHTML(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escRE(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
