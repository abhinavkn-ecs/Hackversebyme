// ── PhishGuard Secure Threat Intelligence Engine ──

// ─── THREAT INTELLIGENCE CATEGORIES ──────────────────────────
const CATS = [
  { id:'urgency',  name:'Urgency Signature',      color:'#ffd740', cls:'m-urgency',  w:25,
    kw:['urgent','immediately','right away','action required','act now','limited time','expires today','last chance','suspended','disabled','terminated','within 24 hours','within 48 hours','respond immediately','failure to respond','final warning','warning','account locked'] },
  { id:'cred',     name:'Harvesting Signature',   color:'#ff5252', cls:'m-cred',     w:30,
    kw:['verify your account','confirm your password','enter your password','update your credentials','login to verify','sign in to confirm','provide your username','submit your details','re-enter','otp','one-time password','security code','verify identity','confirm your email','validate your account','reset your password'] },
  { id:'url',      name:'Untrusted Hostnames',    color:'#3b82f6', cls:'m-url',      w:20,
    kw:['bit.ly','tinyurl','goo.gl','ow.ly','rb.gy','shorturl','click here','click this link','click the link','open this link','follow this link','login link','secure-','account-','banking-','paypal-','amazon-','apple-login','google-secure','microsoft-account','.xyz','.tk','.ml','http://'] },
  { id:'finance',  name:'Financial Bait Signature',color:'#10b981', cls:'m-financial',w:20,
    kw:['prize','winner','won','lottery','jackpot','gift card','cash reward','refund','compensation','claim your reward','free money','investment','profit','crypto','bitcoin','transfer funds','wire transfer','bank details','payment required','congratulations','you have been chosen','inheritance'] },
  { id:'social',   name:'Social Engineering Signature',color:'#ffffff', cls:'m-social',   w:15,
    kw:['your boss','your manager','ceo','hr department','it department','tech support','customer service','helpdesk','government','irs','police','fbi','official notice','legal action','debt collector','court order','kindly','dear customer','dear user','dear friend','trusted partner'] },
  { id:'imperson', name:'Brand Impersonation',    color:'#ffd740', cls:'m-social',   w:15,
    kw:['paypal','amazon','apple','google','microsoft','netflix','facebook','instagram','twitter','whatsapp','your bank','chase bank','wells fargo','bank of america','citibank','irs','fedex','ups','dhl','usps','docusign','dropbox','zoom'] },
  { id:'sensitive',name:'Structured Info Request',color:'#ff5252', cls:'m-cred',     w:20,
    kw:['social security','ssn','date of birth','dob','credit card','card number','cvv','expiry date','bank account','routing number','passport','driver license','tax id','mother maiden','security question','full name and address','national id'] }
];

const SAMPLE = `Dear Customer,

Your account access has been SUSPENDED due to anomalies detected in our database. You are requested to verify identity immediately to prevent full lockouts.

Execute verification by confirming password credentials at:
http://portal-secure-verify.xyz/login?id=920a1

Non-compliance within 24 hours will result in automatic escalation and administrative lockouts.

System Operations Team`;

const PSYCH = {
  low:'Signature analysis detected negligible threat indicators. Continue normal validation procedures before trusting payload.',
  medium:'Audit indicates mild psychological manipulation tactics (urgency mimics, authority references). Attackers leverage trusted brand context to bypass standard rational checks.',
  high:'Significant risk profile. The payload utilizes high-severity manipulation vectors (escalation threats + identity request + unofficial redirection hosts). Do not process any instructions.',
  critical:'Validated high-risk attack. Multiple structural vectors match known credential theft and spoofing profiles. Isolate the message payload immediately.'
};

const ADVICE = {
  low:['Verify communication source through verified telephone or internal channels.','Do not interact with links if you did not solicit the transaction.','Log payload as standard validation scan if required by policy.'],
  medium:['Do not interact with embedded redirection links.','Access target platform manually by typing the verified URL address.','Check the sender domain syntax for spoof patterns.','Request source re-verification.'],
  high:['Do not download attachments or execute external payloads.','Avoid submitting authorization codes or identity profiles.','Forward payload data to your security operations center.','If credentials were submitted, initiate target system password resets and revoke active sessions.'],
  critical:['Isolate payload stream and delete from target inbox.','Report attack metrics to anti-phishing registry (reportphishing.antiphishing.org).','If account authentication info was exposed, perform credential rotation immediately.','Inform financial processors if transaction cards or bank details were submitted.']
};

// ─── STATE ───────────────────────────────────────────────────
let history = JSON.parse(localStorage.getItem('pg_h') || '[]');

// ─── PAGE ROUTING ─────────────────────────────────────────────
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.remove('hidden');
  const nb = document.getElementById('nb-' + id);
  if (nb) nb.classList.add('active');
  window.scrollTo(0, 0);
  if (id === 'dashboard') renderDashboard();
}

function toggleMenu() {
  document.getElementById('mobileMenu').classList.toggle('hidden');
}

// ─── HERO COUNTER ANIMATION ───────────────────────────────────
window.addEventListener('load', () => {
  document.querySelectorAll('.stat-num[data-target]').forEach(el => {
    const target = +el.dataset.target;
    animCount(el, 0, target, 1000);
  });
});

// ─── DYNAMIC SVG ICON PROVIDER ────────────────────────────────
function getCategorySvg(id) {
  const base = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="width: 14px; height: 14px; display: block; opacity: 0.85;">';
  switch (id) {
    case 'urgency':
      return base + '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"></svg>';
    case 'cred':
      return base + '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
    case 'url':
      return base + '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';
    case 'finance':
      return base + '<line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>';
    case 'social':
      return base + '<circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><path d="M2 12h20"/></svg>';
    case 'imperson':
      return base + '<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>';
    case 'sensitive':
      return base + '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>';
    default:
      return base + '<circle cx="12" cy="12" r="10"/></svg>';
  }
}

// ─── SCANNER PAGE ─────────────────────────────────────────────
const scanInput    = document.getElementById('scanInput');
const scanCC       = document.getElementById('scanCharCount');
const scanDetect   = document.getElementById('scanDetectBtn');
const scanSample   = document.getElementById('scanSampleBtn');
const scanClear    = document.getElementById('scanClearBtn');
const scanLoad     = document.getElementById('scanLoadBar');
const scanResult   = document.getElementById('scanResult');
const scanHolder   = document.getElementById('scanPlaceholder');
const scanRing     = document.getElementById('scanRing');
const scanScoreNum = document.getElementById('scanScoreNum');
const scanBadge    = document.getElementById('scanBadge');
const scanSummary  = document.getElementById('scanSummary');
const scanCopyBtn  = document.getElementById('scanCopyBtn');
const scanBreakdown= document.getElementById('scanBreakdown');
const scanHighlight= document.getElementById('scanHighlight');
const scanPsych    = document.getElementById('scanPsych');
const scanAdvice   = document.getElementById('scanAdvice');

scanInput.addEventListener('input', () => { scanCC.textContent = scanInput.value.length + ' bytes'; });
scanSample.addEventListener('click', () => { scanInput.value = SAMPLE; scanCC.textContent = SAMPLE.length + ' bytes'; });
scanClear.addEventListener('click', () => { scanInput.value = ''; scanCC.textContent = '0 bytes'; scanResult.classList.add('hidden'); scanHolder.classList.remove('hidden'); });

scanDetect.addEventListener('click', () => {
  const txt = scanInput.value.trim();
  if (!txt) { shake(scanInput); return; }
  scanLoad.classList.remove('hidden');
  scanResult.classList.add('hidden');
  scanHolder.classList.add('hidden');
  scanDetect.disabled = true;
  setTimeout(() => {
    const r = analyze(txt);
    scanLoad.classList.add('hidden');
    scanDetect.disabled = false;
    renderScanResult(r, txt);
    saveHistory(txt, r.score, r.level);
  }, 600);
});

function renderScanResult(r, txt) {
  // Ring
  const circ = 314;
  scanRing.style.strokeDashoffset = circ;
  scanRing.style.stroke = riskColor(r.level);
  setTimeout(() => { scanRing.style.strokeDashoffset = circ - (r.score / 100) * circ; }, 60);
  animCount(scanScoreNum, 0, r.score, 600);

  // Badge & summary
  const labels = { low:'LOW SEVERITY', medium:'MEDIUM SEVERITY', high:'HIGH SEVERITY', critical:'CRITICAL SEVERITY' };
  const summaries = { low:'No critical threat signatures identified in payload buffer.', medium:'Anomalies identified. Proceed with caution.', high:'High threat density. Payload matches social engineering tactics.', critical:'Threat signatures matched. Action requested immediately.' };
  scanBadge.textContent = labels[r.level];
  scanBadge.className = 'risk-badge badge-' + r.level;
  scanSummary.textContent = summaries[r.level];

  // Breakdown
  scanBreakdown.innerHTML = r.cats.map(c => `
    <div class="bd-row">
      <span class="bd-icon" style="color: ${c.color};">${getCategorySvg(c.id)}</span>
      <span class="bd-name">${c.name}</span>
      <div class="bd-bar-wrap"><div class="bd-bar" style="width:0%;background:${c.color}" data-w="${c.catScore}"></div></div>
      <span class="bd-val" style="color:${c.color}">${c.catScore}</span>
    </div>`).join('');
  requestAnimationFrame(() => { document.querySelectorAll('.bd-bar').forEach(b => b.style.width = b.dataset.w + '%'); });

  // Highlight
  scanHighlight.innerHTML = buildHighlight(txt, r.words);
  // Psych & advice
  scanPsych.textContent = PSYCH[r.level];
  scanAdvice.innerHTML = ADVICE[r.level].map(a => `<li>${a}</li>`).join('');

  // Store report
  scanResult.dataset.report = buildReport(r, txt);
  scanResult.classList.remove('hidden');
  scanResult.scrollIntoView({ behavior:'smooth', block:'start' });
}

scanCopyBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(scanResult.dataset.report || '').then(showToast);
});

// ─── URL CHECKER ──────────────────────────────────────────────
const urlInput   = document.getElementById('urlInput');
const urlCheckBtn= document.getElementById('urlCheckBtn');
const urlResult  = document.getElementById('urlResult');
const urlRing    = document.getElementById('urlRing');
const urlScoreNum= document.getElementById('urlScoreNum');
const urlBadge   = document.getElementById('urlBadge');
const urlSummary = document.getElementById('urlSummary');
const urlChecks  = document.getElementById('urlChecks');
const urlAdvice  = document.getElementById('urlAdvice');

const URL_SAMPLES = {
  safe: 'https://www.wikipedia.org/wiki/Phishing',
  phish: 'http://identity-portal-secure-verify.xyz/login?account=client',
  short: 'https://bit.ly/49Xm2eZ'
};

function loadUrlSample(t) { urlInput.value = URL_SAMPLES[t]; }

urlCheckBtn.addEventListener('click', () => {
  const u = urlInput.value.trim();
  if (!u) { shake(urlInput); return; }
  analyzeUrl(u);
});

urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') urlCheckBtn.click(); });

function analyzeUrl(raw) {
  let score = 0;
  const checks = [];

  const hasHTTPS = raw.startsWith('https://');
  checks.push({ label:'Transport Layer', ok: hasHTTPS ? 'ok' : 'bad', text: hasHTTPS ? 'HTTPS Active' : 'Unencrypted HTTP' });
  if (!hasHTTPS) score += 25;

  const shortDomains = ['bit.ly','tinyurl.com','goo.gl','ow.ly','rb.gy','t.co','is.gd','buff.ly'];
  const isShort = shortDomains.some(d => raw.includes(d));
  checks.push({ label:'Redirect Masking', ok: isShort ? 'warn' : 'ok', text: isShort ? 'Shortened Domain' : 'Direct Target' });
  if (isShort) score += 20;

  const suspTLD = ['.xyz','.tk','.ml','.cf','.ga','.gq'];
  const hasSuspTLD = suspTLD.some(t => raw.toLowerCase().includes(t));
  checks.push({ label:'TLD Evaluation', ok: hasSuspTLD ? 'bad' : 'ok', text: hasSuspTLD ? 'High-risk TLD extension' : 'Standard TLD' });
  if (hasSuspTLD) score += 30;

  const brands = ['paypal','amazon','apple','google','microsoft','netflix','facebook','instagram','bank'];
  const domainPart = raw.replace(/https?:\/\//,'').split('/')[0].toLowerCase();
  const hasBrandSpoof = brands.some(b => domainPart.includes(b) && !domainPart.endsWith(b+'.com') && !domainPart.endsWith(b+'.net'));
  checks.push({ label:'Brand Checksum', ok: hasBrandSpoof ? 'bad' : 'ok', text: hasBrandSpoof ? 'Brand spoofing detected' : 'Neutral Domain Name' });
  if (hasBrandSpoof) score += 35;

  const hasDash = (domainPart.match(/-/g) || []).length > 1;
  checks.push({ label:'Lexical Integrity', ok: hasDash ? 'warn' : 'ok', text: hasDash ? 'High hyphens count' : 'Clean Lexical Structure' });
  if (hasDash) score += 10;

  const hasParams = raw.includes('?') && raw.includes('=');
  const suspParams = ['token','verify','account','password','login','redirect','confirm'].some(p => raw.toLowerCase().includes(p));
  checks.push({ label:'Queries Parameter', ok: suspParams ? 'warn' : 'ok', text: suspParams ? 'Phish query signatures' : 'Standard Queries' });
  if (suspParams) score += 15;

  score = Math.min(100, score);
  const level = score >= 70 ? 'critical' : score >= 45 ? 'high' : score >= 20 ? 'medium' : 'low';

  // Render
  const circ = 314;
  urlRing.style.strokeDashoffset = circ;
  urlRing.style.stroke = riskColor(level);
  setTimeout(() => { urlRing.style.strokeDashoffset = circ - (score / 100) * circ; }, 60);
  animCount(urlScoreNum, 0, score, 600);

  const labels = { low:'LOW THREAT', medium:'MEDIUM RISK', high:'HIGH RISK', critical:'CRITICAL THREAT' };
  urlBadge.textContent = labels[level];
  urlBadge.className = 'risk-badge badge-' + level;

  const summaries = { low:'Host verification indicates low threat potential.', medium:'Host verification reveals warning parameters.', high:'Security alert. Hostname matches standard spoofing architectures.', critical:'Isolate domain. High likelihood of adversarial credential harvesting.' };
  urlSummary.textContent = summaries[level];

  urlChecks.innerHTML = checks.map(c => `
    <div class="url-check-row">
      <span class="check-icon" style="color: ${c.ok==='ok'?'var(--success)':c.ok==='warn'?'var(--warn)':'var(--danger)'};">
        ${c.ok==='ok'?'✓':c.ok==='warn'?'⚠':'✗'}
      </span>
      <span class="check-label">${c.label}</span>
      <span class="check-result check-${c.ok}">${c.text}</span>
    </div>`).join('');

  const advText = { low:'Audited target is safe under standard operational contexts.', medium:'Audit parameter flags warning. Navigate to resource manually.', high:'Do not open this URL. Inform workstation supervisor of threat indicators.', critical:'Do not connect to host. Block connection vector.' };
  urlAdvice.textContent = advText[level];

  urlResult.classList.remove('hidden');
  urlResult.scrollIntoView({ behavior:'smooth', block:'start' });
}

// ─── DASHBOARD ────────────────────────────────────────────────
function renderDashboard() {
  const total = history.length;
  const low   = history.filter(h => h.level === 'low').length;
  const med   = history.filter(h => h.level === 'medium').length;
  const high  = history.filter(h => h.level === 'high' || h.level === 'critical').length;
  const avg   = total ? Math.round(history.reduce((s, h) => s + h.score, 0) / total) : 0;

  document.getElementById('dsTotalScans').textContent = total;
  document.getElementById('dsHighRisk').textContent = high;
  document.getElementById('dsMedRisk').textContent = med;
  document.getElementById('dsLowRisk').textContent = low;

  // Chart
  const maxH = Math.max(low, med, high, 1);
  ['low','med','high','crit'].forEach(k => document.getElementById('cb-'+k).style.height = '0%');
  const ec = document.getElementById('emptyChart');
  if (!total) { ec.style.display='flex'; }
  else {
    ec.style.display='none';
    setTimeout(() => {
      document.getElementById('cb-low').style.height  = (low / maxH * 100) + '%';
      document.getElementById('cb-med').style.height  = (med / maxH * 100) + '%';
      const crit = history.filter(h => h.level==='critical').length;
      document.getElementById('cb-high').style.height = ((high-crit) / maxH * 100) + '%';
      document.getElementById('cb-crit').style.height = (crit / maxH * 100) + '%';
    }, 100);
  }

  // Avg ring
  const avgRing = document.getElementById('avgRing');
  const circ = 314;
  avgRing.style.strokeDashoffset = circ;
  if (total) {
    const lvl = avg>=70?'critical':avg>=45?'high':avg>=20?'medium':'low';
    avgRing.style.stroke = riskColor(lvl);
    setTimeout(() => { avgRing.style.strokeDashoffset = circ - (avg/100)*circ; }, 100);
    document.getElementById('avgScoreNum').textContent = avg;
    document.getElementById('avgLabel').textContent = 'Based on ' + total + ' execution record' + (total>1?'s':'');
  } else {
    document.getElementById('avgScoreNum').textContent = '—';
    document.getElementById('avgLabel').textContent = 'Audit history clear';
  }

  // History table
  const dh = document.getElementById('dashHistory');
  if (!total) {
    dh.innerHTML = '<p class="empty-state">Audit logs clear. <button class="link-btn" onclick="showPage(\'scanner\')">Start inspection →</button></p>';
  } else {
    dh.innerHTML = history.map(h => `
      <div class="dash-history-row">
        <span class="dh-score" style="color:${riskColor(h.level)}">${h.score}</span>
        <span class="dh-level" style="color:${riskColor(h.level)}">${h.level.toUpperCase()}</span>
        <span class="dh-preview">${escHTML(h.preview)}</span>
        <span class="dh-time">${h.time}</span>
      </div>`).join('');
  }
}

document.getElementById('dashClearBtn').addEventListener('click', () => {
  history = [];
  localStorage.removeItem('pg_h');
  renderDashboard();
});

// ─── CORE ANALYSIS ────────────────────────────────────────────
function analyze(text) {
  const lo = text.toLowerCase();
  const words = {};
  const cats = CATS.map(cat => {
    let hits = 0;
    cat.kw.forEach(kw => {
      if (lo.includes(kw)) { hits++; if (!words[kw]) words[kw] = cat.cls; }
    });
    const catScore = Math.min(100, Math.round((hits / Math.max(cat.kw.length * 0.22, 1)) * 100));
    return { ...cat, hits, catScore };
  });
  const score = Math.min(100, Math.round(cats.reduce((s, c) => s + c.catScore * c.w, 0) / cats.reduce((s, c) => s + c.w, 0)));
  const level = score>=70?'critical':score>=45?'high':score>=20?'medium':'low';
  return { score, level, cats, words };
}

function buildHighlight(text, words) {
  if (!Object.keys(words).length) return '<span style="color:var(--text-dark)">No adversarial syntax profiles detected.</span>';
  const sorted = Object.keys(words).sort((a,b) => b.length - a.length);
  const re = new RegExp('(' + sorted.map(escRE).join('|') + ')', 'gi');
  return escHTML(text).replace(re, m => `<mark class="${words[m.toLowerCase()]||'m-social'}">${m}</mark>`);
}

function buildReport(r, txt) {
  return [
    '=======================================',
    '        PHISHGUARD THREAT AUDIT REPORT ',
    '=======================================',
    'Timestamp: ' + new Date().toISOString(),
    'Severity Classification: ' + r.level.toUpperCase(),
    'Composite Threat Index: ' + r.score + '/100',
    '',
    '--- Signature Analysis Breakdown ---',
    ...r.cats.map(c => c.name + ': ' + c.catScore + '/100'),
    '',
    '--- Inspected Payload Stream ---',
    txt,
    '======================================='
  ].join('\n');
}

function saveHistory(txt, score, level) {
  history.unshift({ preview: txt.replace(/\n/g,' ').slice(0,70), score, level, time: new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) });
  if (history.length > 30) history.pop();
  localStorage.setItem('pg_h', JSON.stringify(history));
}

// ─── UTILS ────────────────────────────────────────────────────
function riskColor(l) { return { low:'#10b981', medium:'#f59e0b', high:'#ef4444', critical:'#ec4899' }[l]||'#3b82f6'; }

function animCount(el, from, to, dur) {
  const start = performance.now();
  (function step(now) {
    const p = Math.min((now - start) / dur, 1);
    el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(step);
  })(performance.now());
}

function escHTML(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function escRE(s) { return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'); }

function shake(el) {
  el.style.animation = 'none';
  el.offsetHeight;
  el.style.animation = 'shk .4s ease';
  setTimeout(() => el.style.animation='', 500);
}

function showToast() {
  const t = document.getElementById('toast');
  t.classList.remove('hidden');
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.classList.add('hidden'), 350); }, 2000);
}

// Shake keyframe
const s = document.createElement('style');
s.textContent = '@keyframes shk{0%,100%{transform:none}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}';
document.head.appendChild(s);
