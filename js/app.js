const API = 'http://localhost:5050';
let state = { emails: [], activeId: null, folder: 'inbox', search: '', view: 'inbox' };

async function api(path, opts = {}) {
  try {
    const res = await fetch(`${API}${path}`, { headers: { 'Content-Type': 'application/json' }, ...opts });
    return await res.json();
  } catch (e) { console.error('API Error:', e); toast('API connection failed', 'warn'); return null; }
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
async function checkAuth() {
  const data = await api('/api/auth-check');
  if (data && data.logged_in) {
    showApp(data.email);
  } else {
    showLogin();
  }
}

function showLogin() {
  document.getElementById('login-screen').style.display = 'flex';
  document.getElementById('app').style.display = 'none';
}

function showApp(email) {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  document.getElementById('user-email').textContent = email || '';
  loadEmails();
  loadStats();
  setTimeout(() => scanAll(), 500);
}

async function doLogin() {
  const email = document.getElementById('login-email').value.trim();
  const pw = document.getElementById('login-password').value.trim();
  const errEl = document.getElementById('login-error');
  const btn = document.getElementById('login-btn');
  const btnText = document.getElementById('login-btn-text');
  const spinner = document.getElementById('login-spinner');

  if (!email || !pw) { errEl.textContent = 'Please enter both email and app password.'; errEl.classList.add('show'); return; }

  btn.disabled = true; btnText.textContent = 'Connecting...'; spinner.style.display = '';
  errEl.classList.remove('show');

  try {
    const res = await fetch(`${API}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pw })
    });
    const data = await res.json();
    if (data.ok && data.requires_2fa) {
      document.getElementById('2fa-email-display').textContent = data.email;
      document.querySelectorAll('.login-card').forEach(c => c.style.display = 'none');
      document.getElementById('2fa-card').style.display = 'block';
      setTimeout(() => document.getElementById('login-2fa').focus(), 100);
    } else if (data.ok) {
      btnText.textContent = 'Syncing your emails...';
      showApp(data.email);
      if (data.synced > 0) toast(`Synced ${data.synced} emails from your inbox`);
      else if (data.sync_error) toast('Logged in but sync had an issue — try Sync button', 'warn');
    } else {
      errEl.textContent = data.error || 'Login failed.';
      errEl.classList.add('show');
    }
  } catch (e) {
    errEl.textContent = 'Cannot connect to server. Make sure Flask is running on port 5050.';
    errEl.classList.add('show');
  } finally {
    btn.disabled = false; btnText.textContent = 'Connect Securely'; spinner.style.display = 'none';
  }
}

async function verify2FA() {
  const code = document.getElementById('login-2fa').value.trim();
  const errEl = document.getElementById('2fa-error');
  const btn = document.getElementById('2fa-btn');
  const btnText = document.getElementById('2fa-btn-text');
  const spinner = document.getElementById('2fa-spinner');

  if (!code || code.length < 6) { errEl.textContent = 'Enter the 6-digit code.'; errEl.classList.add('show'); return; }

  btn.disabled = true; btnText.textContent = 'Verifying...'; spinner.style.display = '';
  errEl.classList.remove('show');

  try {
    const res = await fetch(`${API}/api/verify-2fa`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    const data = await res.json();
    if (data.ok) {
      btnText.textContent = 'Syncing emails...';
      showApp(data.email);
      if (data.synced > 0) toast(`Synced ${data.synced} recent emails. Background sync started.`);
      else if (data.sync_error) toast('Logged in but initial sync had an issue.', 'warn');
    } else {
      errEl.textContent = data.error || 'Verification failed.';
      errEl.classList.add('show');
    }
  } catch (e) {
    errEl.textContent = 'Connection error.';
    errEl.classList.add('show');
  } finally {
    btn.disabled = false; btnText.textContent = 'Verify Code'; spinner.style.display = 'none';
  }
}

function cancel2FA() {
  document.getElementById('2fa-card').style.display = 'none';
  document.querySelector('.login-card').style.display = 'block';
  document.getElementById('login-2fa').value = '';
}

async function doLogout() {
  await api('/api/logout', { method: 'POST' });
  showLogin();
}

function skipLogin() {
  showApp('demo@shieldmail.ai');
}

function selectProvider(domain) {
  const emailInput = document.getElementById('login-email');
  const current = emailInput.value;
  // Keep username part if already typed
  const username = current.includes('@') ? current.split('@')[0] : current;
  emailInput.value = username ? `${username}@${domain}` : `@${domain}`;
  emailInput.focus();
  if (!username) emailInput.setSelectionRange(0, 0);
  // Highlight selected provider
  document.querySelectorAll('.provider-btn').forEach(b => b.classList.remove('selected'));
  event.currentTarget.classList.add('selected');
  // Update placeholder
  const hints = {'gmail.com':'Gmail App Password','outlook.com':'Outlook Password','yahoo.com':'Yahoo App Password'};
  document.getElementById('login-password').placeholder = hints[domain] || 'App Password or IMAP Password';
}

// ── DATA ─────────────────────────────────────────────────────────────────────
async function loadEmails() {
  const params = new URLSearchParams({ folder: state.folder });
  if (state.search) params.set('search', state.search);
  const data = await api(`/api/emails?${params}`);
  if (data) { state.emails = data; renderEmailList(); updateSidebarCounts(); }
}

async function loadStats() {
  const data = await api('/api/stats');
  if (!data) return;
  const s = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  s('stat-scanned', data.scanned); s('stat-phish', data.phishing); s('stat-safe', data.safe);
  s('dv-total', data.total); s('dv-scanned', data.scanned); s('dv-phishing', data.phishing);
  s('dv-safe', data.safe); s('dv-unread', data.unread);
  const ib = document.getElementById('inbox-badge');
  if (ib) { ib.textContent = data.unread; ib.style.display = data.unread > 0 ? '' : 'none'; }
  drawCharts(data);
}

async function updateSidebarCounts() {
  const data = await api('/api/stats');
  if (!data) return;
  const s = (id, v, show) => { const el = document.getElementById(id); if (el) { el.textContent = v; el.style.display = show ? '' : 'none'; } };
  s('inbox-badge', data.unread, data.unread > 0);
  s('phish-badge', data.phishing, data.phishing > 0);
  s('stat-scanned', data.scanned, true); s('stat-phish', data.phishing, true); s('stat-safe', data.safe, true);
}

// ── RENDER ────────────────────────────────────────────────────────────────────
function renderEmailList() {
  const list = document.getElementById('email-items');
  if (!list) return;
  list.innerHTML = '';
  if (state.emails.length === 0) {
    list.innerHTML = '<div style="padding:40px 20px;text-align:center;color:var(--muted);font-size:13px;font-family:var(--mono)">No emails found</div>';
    return;
  }
  state.emails.forEach(email => {
    const div = document.createElement('div');
    div.className = 'email-item' + (email.id === state.activeId ? ' active' : '') + (!email.is_read ? ' unread' : '');
    div.onclick = () => openEmail(email.id);
    let badge = '<span class="threat-pill pending"><i class="ti ti-clock" style="font-size:12px"></i> Pending</span>';
    if (email.scan) {
      badge = email.scan.label === 'phishing'
        ? `<span class="threat-pill phishing"><i class="ti ti-alert-triangle" style="font-size:12px"></i> Phishing · ${email.scan.p_phishing}%</span>`
        : `<span class="threat-pill safe"><i class="ti ti-shield-check" style="font-size:12px"></i> Safe · ${email.scan.p_safe}%</span>`;
    }
    div.innerHTML = `<div class="ei-top"><span class="ei-sender">${esc(email.sender_name)}</span><span class="ei-time">${esc(email.date||'')}</span></div>
      <div class="ei-subject">${esc(email.subject)}</div>
      <div class="ei-preview">${esc((email.body||'').slice(0,90).replace(/\n/g,' '))}</div>
      <div class="ei-badges">${badge}<span class="star-icon ${email.is_starred?'active':''}" onclick="event.stopPropagation();toggleStar(${email.id})"><i class="ti ti-star${email.is_starred?'-filled':''}"></i></span></div>`;
    list.appendChild(div);
  });
}

function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

// ── OPEN EMAIL ───────────────────────────────────────────────────────────────
async function openEmail(id) {
  state.activeId = id;
  const email = state.emails.find(e => e.id === id);
  if (!email) return;
  email.is_read = true;
  hideAllViews();
  document.getElementById('email-view').classList.add('show');
  document.querySelector('.analysis-panel').classList.remove('hidden');
  document.getElementById('empty-state').style.display = 'none';
  document.getElementById('ev-subject').textContent = email.subject;
  document.getElementById('ev-name').textContent = email.sender_name;
  document.getElementById('ev-addr').textContent = `<${email.sender_email}>`;
  document.getElementById('ev-date').textContent = email.date;
  document.getElementById('ev-body').textContent = email.body;
  const av = document.getElementById('ev-avatar');
  const colors = ['#6366f1','#ec4899','#f59e0b','#10b981','#3b82f6','#8b5cf6','#ef4444','#14b8a6'];
  av.style.background = colors[id % colors.length];
  av.textContent = (email.sender_name || '?')[0].toUpperCase();
  const rta = document.getElementById('reply-textarea');
  if (rta) rta.placeholder = `Reply to ${email.sender_name}...`;
  renderEmailList();
  if (email.scan) { showAnalysisResult(email.scan); }
  else { showScanLoading(); const r = await api(`/api/emails/${id}/rescan`,{method:'POST'}); if(r&&!r.error){email.scan=r;showAnalysisResult(r);renderEmailList();} }
  api(`/api/emails/${id}`);
}

function goBack() {
  state.activeId = null;
  document.getElementById('email-view').classList.remove('show');
  document.querySelector('.analysis-panel').classList.add('hidden');
  document.getElementById('empty-state').style.display = '';
  renderEmailList();
}

// ── ANALYSIS ─────────────────────────────────────────────────────────────────
function showScanLoading() { document.getElementById('scan-loading').style.display='flex'; document.getElementById('analysis-result').style.display='none'; }

function showAnalysisResult(data) {
  document.getElementById('scan-loading').style.display = 'none';
  document.getElementById('analysis-result').style.display = 'block';
  const isPhish = data.label === 'phishing';
  document.getElementById('verdict-card').className = `verdict-card ${data.label}`;
  document.getElementById('verdict-ico').innerHTML = isPhish ? '<i class="ti ti-alert-triangle" style="font-size:34px"></i>' : '<i class="ti ti-shield-check" style="font-size:34px"></i>';
  const lbl = document.getElementById('verdict-lbl');
  lbl.textContent = isPhish ? 'PHISHING DETECTED' : 'VERIFIED SAFE';
  lbl.className = `verdict-lbl ${data.label}`;
  document.getElementById('verdict-conf').textContent = `${data.confidence}% confidence`;
  const pct = data.p_phishing;
  const bar = document.getElementById('risk-fill');
  bar.style.width = pct + '%';
  bar.style.background = pct > 70 ? 'var(--danger)' : pct > 40 ? 'var(--warn)' : 'var(--safe)';
  document.getElementById('risk-pct').textContent = pct + '%';
  if (data.features) {
    const grid = document.getElementById('feat-grid');
    const META = [
      {key:'url_count',label:'URLs Found',bad:v=>v>2},{key:'has_ip_url',label:'IP-Based URL',bad:v=>v>0},
      {key:'avg_url_len',label:'Avg URL Len',bad:v=>v>50},{key:'urgency_score',label:'Urgency Score',bad:v=>v>3},
      {key:'num_exclamations',label:'Exclamations',bad:v=>v>2},{key:'num_questions',label:'Questions',bad:v=>v>3},
      {key:'body_length',label:'Body Length',bad:()=>false},{key:'unique_word_ratio',label:'Word Uniqueness',bad:v=>v<0.4},
      {key:'flesch_score',label:'Readability',bad:()=>false},{key:'has_html',label:'Contains HTML',bad:v=>v>0},
      {key:'num_forms',label:'HTML Forms',bad:v=>v>0},{key:'num_links_html',label:'HTML Links',bad:v=>v>3},
    ];
    grid.innerHTML = '';
    META.forEach(({key,label,bad}) => {
      const val = data.features[key];
      const fmt = typeof val==='number'&&val%1!==0?val.toFixed(2):val;
      grid.innerHTML += `<div class="feat-row"><span class="feat-name">${label}</span><span class="feat-val ${bad(val)?'r':'g'}">${fmt}</span></div>`;
    });
  }
}

// ── ACTIONS ──────────────────────────────────────────────────────────────────
async function toggleStar(id) {
  const res = await api(`/api/emails/${id}/star`,{method:'PUT'});
  if(res){const e=state.emails.find(x=>x.id===id);if(e)e.is_starred=res.is_starred;renderEmailList();}
}
async function trashEmail() {
  if(!state.activeId)return;
  await api(`/api/emails/${state.activeId}/trash`,{method:'PUT'});
  toast('Email moved to trash'); goBack(); loadEmails();
}
async function rescanEmail() {
  if(!state.activeId)return; showScanLoading();
  const r=await api(`/api/emails/${state.activeId}/rescan`,{method:'POST'});
  if(r&&!r.error){const e=state.emails.find(x=>x.id===state.activeId);if(e)e.scan=r;showAnalysisResult(r);renderEmailList();}
}

// ── COMPOSE ──────────────────────────────────────────────────────────────────
function openCompose(t,s,b){
  document.getElementById('modal-bg').classList.add('open');
  document.getElementById('c-to').value=t||'';document.getElementById('c-subject').value=s||'';
  document.getElementById('c-body').value=b||'';
  document.getElementById('cm-result').className='cm-result';document.getElementById('cm-result').textContent='';
  setTimeout(()=>document.getElementById('c-to').focus(),100);
}
function closeCompose(){document.getElementById('modal-bg').classList.remove('open')}
function handleOverlayClick(e){if(e.target===document.getElementById('modal-bg'))closeCompose()}

async function analyzeCompose(){
  const subj=document.getElementById('c-subject').value,body=document.getElementById('c-body').value;
  if(!subj&&!body)return;
  document.getElementById('cm-spinner').style.display='';
  try{
    const data=await api('/predict',{method:'POST',body:JSON.stringify({subject:subj,body})});
    if(!data)return;
    const el=document.getElementById('cm-result');
    el.className=`cm-result show ${data.label}`;
    el.innerHTML=data.label==='phishing'
      ?`<strong>PHISHING DETECTED</strong> — ${data.confidence}% confidence. Risk: ${data.p_phishing}%`
      :`<strong>Appears Safe</strong> — ${data.confidence}% confidence. Risk: ${data.p_phishing}%`;
  }finally{document.getElementById('cm-spinner').style.display='none'}
}

async function sendEmail(){
  const to=document.getElementById('c-to').value,subj=document.getElementById('c-subject').value||'(no subject)',body=document.getElementById('c-body').value;
  if(!to){toast('Recipient required','warn');return}
  document.getElementById('cm-spinner').style.display='';
  const res=await api('/api/send',{method:'POST',body:JSON.stringify({to,subject:subj,body})});
  document.getElementById('cm-spinner').style.display='none';
  if(res&&res.ok){toast('Email sent successfully!');closeCompose();loadEmails();}
  else toast(res?.error||'Failed to send','warn');
}

async function sendReply(){
  const email=state.emails.find(e=>e.id===state.activeId);if(!email)return;
  const body=document.getElementById('reply-textarea').value;if(!body.trim())return;
  const res=await api('/api/send',{method:'POST',body:JSON.stringify({to:email.sender_email,subject:`Re: ${email.subject}`,body})});
  if(res&&res.ok){toast('Reply sent!');document.getElementById('reply-textarea').value='';}
  else toast(res?.error||'Failed to send reply','warn');
}

// ── SYNC ─────────────────────────────────────────────────────────────────────
async function syncEmails(){
  const btn=document.querySelector('.sync-btn');if(btn)btn.classList.add('spinning');
  const res=await api('/api/sync',{method:'POST'});
  if(btn)btn.classList.remove('spinning');
  if(res&&!res.error){toast(`Synced ${res.synced} new email${res.synced!==1?'s':''}`);loadEmails();loadStats();}
  else toast(res?.error||'Sync failed','warn');
}
async function scanAll(){
  const res=await api('/api/scan-all',{method:'POST'});
  if(res){toast(`Scanned ${res.scanned} emails`);loadEmails();loadStats();}
}

// ── NAV ──────────────────────────────────────────────────────────────────────
function setNav(folder,el){
  document.querySelectorAll('.nav-item').forEach(i=>i.classList.remove('active'));
  if(el)el.classList.add('active');
  if(folder==='dashboard'){state.view='dashboard';hideAllViews();document.querySelector('.dashboard-view').classList.add('show');document.querySelector('.analysis-panel').classList.add('hidden');document.getElementById('empty-state').style.display='none';loadStats();return}
  if(folder==='settings'){state.view='settings';hideAllViews();document.querySelector('.settings-view').classList.add('show');document.querySelector('.analysis-panel').classList.add('hidden');document.getElementById('empty-state').style.display='none';loadSettings();return}
  state.view='inbox';state.folder=folder;state.activeId=null;hideAllViews();
  document.getElementById('empty-state').style.display='';document.querySelector('.analysis-panel').classList.add('hidden');
  const titles={inbox:'Inbox',starred:'Starred',sent:'Sent',trash:'Trash',phishing:'Phishing',safe:'Verified Safe'};
  document.getElementById('list-title').textContent=titles[folder]||'Inbox';loadEmails();
}
function hideAllViews(){document.getElementById('email-view').classList.remove('show');document.querySelector('.dashboard-view').classList.remove('show');document.querySelector('.settings-view').classList.remove('show')}

let searchTimeout;
function onSearch(val){clearTimeout(searchTimeout);state.search=val;searchTimeout=setTimeout(()=>loadEmails(),250)}

// ── SETTINGS ─────────────────────────────────────────────────────────────────
async function loadSettings(){
  const data=await api('/api/settings');if(!data)return;
  document.getElementById('s-email').value=data.gmail_email||'';
  document.getElementById('s-password').value=data.gmail_app_password||'';
}
async function saveSettings(){
  const res=await api('/api/settings',{method:'PUT',body:JSON.stringify({gmail_email:document.getElementById('s-email').value,gmail_app_password:document.getElementById('s-password').value})});
  if(res&&res.ok)toast('Settings saved!');
}

// ── TOAST ────────────────────────────────────────────────────────────────────
function toast(msg,type){
  const c=document.getElementById('toast-container'),t=document.createElement('div');
  t.className='toast';
  t.innerHTML=`<i class="ti ti-${type==='warn'?'alert-triangle':'shield-check'} toast-icon"></i><span>${msg}</span>`;
  c.appendChild(t);setTimeout(()=>{t.classList.add('out');setTimeout(()=>t.remove(),300)},3500);
}

// ── CHARTS ───────────────────────────────────────────────────────────────────
function drawCharts(s){drawDonut(s);drawBar(s)}
function drawDonut(stats){
  const canvas=document.getElementById('chart-donut');if(!canvas)return;
  const ctx=canvas.getContext('2d');const w=canvas.width=canvas.offsetWidth*2,h=canvas.height=canvas.offsetHeight*2;ctx.scale(2,2);
  const cw=w/2,ch=h/2,cx=cw/2,cy=ch/2,r=Math.min(cw,ch)/2-20;ctx.clearRect(0,0,cw,ch);
  const total=(stats.phishing||0)+(stats.safe||0)||1;
  const slices=[{val:stats.safe||0,color:'#00e5a0'},{val:stats.phishing||0,color:'#ff3860'}];
  let angle=-Math.PI/2;
  slices.forEach(s=>{const sw=(s.val/total)*Math.PI*2;ctx.beginPath();ctx.arc(cx,cy,r,angle,angle+sw);ctx.arc(cx,cy,r*0.6,angle+sw,angle,true);ctx.closePath();ctx.fillStyle=s.color;ctx.fill();angle+=sw});
  ctx.fillStyle='#e8ecf4';ctx.font='700 18px "DM Sans"';ctx.textAlign='center';ctx.fillText(total,cx,cy-2);
  ctx.fillStyle='#505878';ctx.font='500 9px "JetBrains Mono"';ctx.fillText('TOTAL',cx,cy+12);
}
function drawBar(stats){
  const canvas=document.getElementById('chart-bar');if(!canvas)return;
  const ctx=canvas.getContext('2d');const w=canvas.width=canvas.offsetWidth*2,h=canvas.height=canvas.offsetHeight*2;ctx.scale(2,2);
  const cw=w/2,ch=h/2;ctx.clearRect(0,0,cw,ch);
  const bars=[{label:'Total',val:stats.total||0,color:'#6366f1'},{label:'Scanned',val:stats.scanned||0,color:'#00b4d8'},{label:'Safe',val:stats.safe||0,color:'#00e5a0'},{label:'Phishing',val:stats.phishing||0,color:'#ff3860'}];
  const max=Math.max(...bars.map(b=>b.val),1),bW=(cw-40)/bars.length-8,baseY=ch-24;
  bars.forEach((b,i)=>{const x=20+i*(bW+8),bH=(b.val/max)*(baseY-10);ctx.fillStyle=b.color;ctx.beginPath();ctx.roundRect(x,baseY-bH,bW,bH,4);ctx.fill();
  ctx.fillStyle='#505878';ctx.font='500 8px "JetBrains Mono"';ctx.textAlign='center';ctx.fillText(b.label,x+bW/2,ch-8);
  ctx.fillStyle='#e8ecf4';ctx.font='700 10px "DM Sans"';ctx.fillText(b.val,x+bW/2,baseY-bH-5)});
}

// ── INIT ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => checkAuth());
