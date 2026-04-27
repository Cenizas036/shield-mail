"""
ShieldMail — AI-Powered Email Client with Phishing Detection
Flask backend: Gmail IMAP/SMTP, SQLite storage, ML phishing analysis.
"""
import re, warnings, os, json, sqlite3, imaplib, smtplib, traceback
import email as email_mod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime

warnings.filterwarnings("ignore")

import joblib
import numpy as np
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS

# ── Load model ───────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
pipeline = joblib.load(MODEL_PATH)
FEATURES = pipeline.feature_names_in_.tolist()

app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app)

DB_PATH = os.path.join(BASE_DIR, "shieldmail.db")

# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════════════
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT,
        folder TEXT DEFAULT 'inbox',
        sender_name TEXT,
        sender_email TEXT,
        recipient TEXT,
        subject TEXT,
        body_text TEXT,
        body_html TEXT,
        date_str TEXT,
        date_ts REAL DEFAULT 0,
        is_read INTEGER DEFAULT 0,
        is_starred INTEGER DEFAULT 0,
        is_trash INTEGER DEFAULT 0,
        scan_label TEXT,
        scan_confidence REAL,
        scan_p_phishing REAL,
        scan_p_safe REAL,
        scan_features TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT
    )''')
    # Defaults
    for k, v in {'gmail_email':'','gmail_app_password':'','auto_scan':'1', 'pending_email':'', 'pending_app_pw':'', 'pending_2fa_code':''}.items():
        c.execute('INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)', (k,v))
    conn.commit()
    conn.close()

# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE EXTRACTION & ML
# ══════════════════════════════════════════════════════════════════════════════
URL_RE   = re.compile(r'https?://\S+', re.I)
IP_RE    = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}', re.I)
TAG_RE   = re.compile(r'<[^>]+>')
FORM_RE  = re.compile(r'<form', re.I)
AHREF_RE = re.compile(r'<a\s[^>]*href', re.I)
URGENCY_WORDS = [
    "urgent","immediately","verify","suspended","account","confirm",
    "password","click here","limited","expire","warning","alert",
    "action required","update now","login",
]

def count_syllables(w):
    w = w.lower().strip(".,!?;:")
    if len(w) <= 3: return 1
    c = 0; pv = False
    for ch in w:
        iv = ch in "aeiouy"
        if iv and not pv: c += 1
        pv = iv
    if w.endswith("e"): c = max(1, c-1)
    return max(1, c)

def flesch_score(text):
    sents = max(1, len(re.split(r'[.!?]+', text)))
    wds = re.findall(r'\b\w+\b', text)
    if not wds: return 50.0
    syls = sum(count_syllables(w) for w in wds)
    n = len(wds)
    return round(max(0, min(100, 206.835 - 1.015*(n/sents) - 84.6*(syls/n))), 2)

def extract_features(subject, body):
    full = f"{subject} {body}"
    urls = URL_RE.findall(full)
    return {
        "url_count": len(urls),
        "has_ip_url": int(bool(IP_RE.search(full))),
        "avg_url_len": (sum(len(u) for u in urls)/len(urls)) if urls else 0.0,
        "urgency_score": sum(1 for w in URGENCY_WORDS if w in full.lower()),
        "num_exclamations": full.count("!"),
        "num_questions": full.count("?"),
        "body_length": len(body),
        "unique_word_ratio": (lambda ws: len(set(ws))/len(ws) if ws else 0)(re.findall(r'\b\w+\b', body.lower())),
        "flesch_score": flesch_score(body),
        "has_html": int(bool(TAG_RE.search(body))),
        "num_forms": len(FORM_RE.findall(body)),
        "num_links_html": len(AHREF_RE.findall(body)),
    }

def run_scan(subject, body):
    feats = extract_features(subject, body)
    X = np.array([[feats[f] for f in FEATURES]])
    pred = int(pipeline.predict(X)[0])
    proba = pipeline.predict_proba(X)[0].tolist()
    return {
        "label": "phishing" if pred == 1 else "safe",
        "confidence": round(proba[pred]*100, 1),
        "p_phishing": round(proba[1]*100, 1),
        "p_safe": round(proba[0]*100, 1),
        "features": feats,
    }

def scan_email_row(db, row_id):
    """Scan an email in DB and update its scan columns."""
    row = db.execute('SELECT subject, body_text FROM emails WHERE id=?', (row_id,)).fetchone()
    if not row: return None
    result = run_scan(row['subject'] or '', row['body_text'] or '')
    db.execute('''UPDATE emails SET scan_label=?, scan_confidence=?,
        scan_p_phishing=?, scan_p_safe=?, scan_features=? WHERE id=?''',
        (result['label'], result['confidence'], result['p_phishing'],
         result['p_safe'], json.dumps(result['features']), row_id))
    db.commit()
    return result

# ══════════════════════════════════════════════════════════════════════════════
#  UNIVERSAL IMAP / SMTP (auto-detect provider)
# ══════════════════════════════════════════════════════════════════════════════
PROVIDERS = {
    'gmail.com':     {'imap':'imap.gmail.com',       'smtp':'smtp.gmail.com',       'smtp_port':587},
    'googlemail.com':{'imap':'imap.gmail.com',       'smtp':'smtp.gmail.com',       'smtp_port':587},
    'outlook.com':   {'imap':'outlook.office365.com', 'smtp':'smtp.office365.com',   'smtp_port':587},
    'hotmail.com':   {'imap':'outlook.office365.com', 'smtp':'smtp.office365.com',   'smtp_port':587},
    'live.com':      {'imap':'outlook.office365.com', 'smtp':'smtp.office365.com',   'smtp_port':587},
    'yahoo.com':     {'imap':'imap.mail.yahoo.com',   'smtp':'smtp.mail.yahoo.com',  'smtp_port':587},
    'yahoo.in':      {'imap':'imap.mail.yahoo.com',   'smtp':'smtp.mail.yahoo.com',  'smtp_port':587},
    'icloud.com':    {'imap':'imap.mail.me.com',      'smtp':'smtp.mail.me.com',     'smtp_port':587},
    'me.com':        {'imap':'imap.mail.me.com',      'smtp':'smtp.mail.me.com',     'smtp_port':587},
    'aol.com':       {'imap':'imap.aol.com',          'smtp':'smtp.aol.com',         'smtp_port':587},
    'zoho.com':      {'imap':'imap.zoho.com',         'smtp':'smtp.zoho.com',        'smtp_port':587},
    'protonmail.com':{'imap':'127.0.0.1',             'smtp':'127.0.0.1',            'smtp_port':1025},
    'yandex.com':    {'imap':'imap.yandex.com',       'smtp':'smtp.yandex.com',      'smtp_port':587},
}

def get_provider(email_addr):
    domain = email_addr.split('@')[-1].lower()
    return PROVIDERS.get(domain, {'imap':f'imap.{domain}','smtp':f'smtp.{domain}','smtp_port':587})
def _decode_header(h):
    if not h: return ""
    parts = decode_header(h)
    out = []
    for p, cs in parts:
        out.append(p.decode(cs or 'utf-8', errors='replace') if isinstance(p, bytes) else p)
    return ''.join(out)

def _get_body(msg):
    text = html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            payload = part.get_payload(decode=True)
            if not payload: continue
            cs = part.get_content_charset() or 'utf-8'
            decoded = payload.decode(cs, errors='replace')
            if ct == "text/plain": text = decoded
            elif ct == "text/html": html = decoded
    else:
        payload = msg.get_payload(decode=True)
        cs = msg.get_content_charset() or 'utf-8'
        if payload:
            decoded = payload.decode(cs, errors='replace')
            if msg.get_content_type() == "text/html": html = decoded
            else: text = decoded
    return text, html

def fetch_emails_imap(email_addr, app_pw, max_n=50):
    prov = get_provider(email_addr)
    mail = imaplib.IMAP4_SSL(prov['imap'])
    mail.login(email_addr, app_pw)
    mail.select('INBOX')
    _, msgs = mail.search(None, 'ALL')
    ids = msgs[0].split()[-max_n:]
    results = []
    for eid in reversed(ids):
        _, data = mail.fetch(eid, '(RFC822)')
        if not data or not data[0]: continue
        msg = email_mod.message_from_bytes(data[0][1])
        mid = msg.get('Message-ID','')
        subj = _decode_header(msg.get('Subject','(no subject)'))
        name, addr = parseaddr(msg.get('From',''))
        name = _decode_header(name) or addr.split('@')[0]
        _, recip = parseaddr(msg.get('To',''))
        ds = msg.get('Date','')
        try:
            dt = parsedate_to_datetime(ds)
            ts = dt.timestamp(); df = dt.strftime('%b %d, %I:%M %p')
        except: ts = 0; df = ds
        bt, bh = _get_body(msg)
        results.append(dict(message_id=mid,sender_name=name,sender_email=addr,
            recipient=recip,subject=subj,body_text=bt,body_html=bh,date_str=df,date_ts=ts))
    mail.logout()
    return results

def send_email_smtp(email_addr, app_pw, to, subject, body):
    prov = get_provider(email_addr)
    msg = MIMEMultipart()
    msg['From'] = email_addr
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    with smtplib.SMTP(prov['smtp'], prov['smtp_port']) as s:
        s.starttls(); s.login(email_addr, app_pw); s.send_message(msg)

import threading
import random

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# ── Auth ─────────────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    d = request.get_json(force=True)
    email_addr = d.get('email', '').strip()
    app_pw = d.get('password', '').strip()
    if not email_addr or not app_pw:
        return jsonify({'ok': False, 'error': 'Email and password are required'}), 400
    # Validate email format
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email_addr):
        return jsonify({'ok': False, 'error': 'Invalid email format'}), 400
    # Auto-detect provider and try IMAP connection
    prov = get_provider(email_addr)
    try:
        mail = imaplib.IMAP4_SSL(prov['imap'])
        mail.login(email_addr, app_pw)
        mail.logout()
    except imaplib.IMAP4.error:
        domain = email_addr.split('@')[-1].lower()
        if domain in ('gmail.com', 'googlemail.com'):
            return jsonify({'ok': False, 'error': 'Gmail rejected your login. Gmail does NOT allow regular passwords for IMAP. You must use a 16-character App Password. Steps: 1) Enable 2-Step Verification at myaccount.google.com/security, 2) Generate an App Password at myaccount.google.com/apppasswords, 3) Use that password here instead.'}), 401
        elif domain in ('outlook.com', 'hotmail.com', 'live.com'):
            return jsonify({'ok': False, 'error': 'Outlook rejected your login. Make sure IMAP is enabled in your Outlook settings (Settings → Mail → Sync email → enable IMAP). Then use your regular Outlook password.'}), 401
        elif domain in ('yahoo.com', 'yahoo.in'):
            return jsonify({'ok': False, 'error': 'Yahoo rejected your login. You need a Yahoo App Password. Go to Yahoo Account Security → Generate App Password. Also make sure "Allow apps that use less secure sign-in" is enabled.'}), 401
        else:
            return jsonify({'ok': False, 'error': f'Login failed for {domain}. Check your email and password. Make sure IMAP access is enabled in your email provider settings.'}), 401
    except Exception as ex:
        return jsonify({'ok': False, 'error': f'Cannot connect to mail server: {str(ex)}'}), 500
    # Generate 6-digit 2FA code
    code = str(random.randint(100000, 999999))
    
    # Send code to their own email
    try:
        body = f"Hello,\n\nYour ShieldMail 2FA verification code is: {code}\n\nIf you did not request this, please ignore this email.\n\n— ShieldMail Security"
        send_email_smtp(email_addr, app_pw, email_addr, "Your ShieldMail Login Code", body)
    except Exception as ex:
        return jsonify({'ok': False, 'error': f'Failed to send 2FA email: {str(ex)}'}), 500

    # Save to pending state
    db = get_db()
    db.execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', ('pending_email', email_addr))
    db.execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', ('pending_app_pw', app_pw))
    db.execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', ('pending_2fa_code', code))
    db.commit()
    
    return jsonify({'ok': True, 'requires_2fa': True, 'email': email_addr})

def background_sync(email_addr, app_pw):
    """Fetches all remaining emails slowly in the background to prevent timeouts"""
    try:
        fetched = fetch_emails_imap(email_addr, app_pw, max_n=5000) # large limit
        db = get_db()
        for e in fetched:
            exists = db.execute('SELECT id FROM emails WHERE message_id=?',(e['message_id'],)).fetchone()
            if exists: continue
            c = db.execute('''INSERT INTO emails (message_id,folder,sender_name,sender_email,
                recipient,subject,body_text,body_html,date_str,date_ts)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (e['message_id'] or f'msg-{e["date_ts"]}','inbox',
                 e['sender_name'],e['sender_email'],e['recipient'],e['subject'],
                 e['body_text'],e['body_html'],e['date_str'],e['date_ts']))
            db.commit()
            scan_email_row(db, c.lastrowid)
    except Exception as ex:
        print(f"Background sync error: {ex}")

@app.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    d = request.get_json(force=True)
    code = d.get('code', '').strip()
    
    db = get_db()
    saved_code = db.execute("SELECT value FROM settings WHERE key='pending_2fa_code'").fetchone()
    email_addr = db.execute("SELECT value FROM settings WHERE key='pending_email'").fetchone()
    app_pw = db.execute("SELECT value FROM settings WHERE key='pending_app_pw'").fetchone()
    
    if not saved_code or saved_code['value'] != code:
        return jsonify({'ok': False, 'error': 'Invalid or expired verification code'}), 401
        
    em = email_addr['value']
    pw = app_pw['value']
    
    # Save active credentials and clear old emails
    db.execute('DELETE FROM emails')
    db.execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', ('gmail_email', em))
    db.execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', ('gmail_app_password', pw))
    # Clear pending state
    db.execute("UPDATE settings SET value='' WHERE key IN ('pending_email','pending_app_pw','pending_2fa_code')")
    db.commit()

    # Sync first 5 instantly (to dramatically speed up login time)
    synced = 0
    try:
        fetched = fetch_emails_imap(em, pw, max_n=5)
        for e in fetched:
            exists = db.execute('SELECT id FROM emails WHERE message_id=?',(e['message_id'],)).fetchone()
            if exists: continue
            c = db.execute('''INSERT INTO emails (message_id,folder,sender_name,sender_email,
                recipient,subject,body_text,body_html,date_str,date_ts)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (e['message_id'] or f'msg-{e["date_ts"]}','inbox',
                 e['sender_name'],e['sender_email'],e['recipient'],e['subject'],
                 e['body_text'],e['body_html'],e['date_str'],e['date_ts']))
            db.commit()
            scan_email_row(db, c.lastrowid)
            synced += 1
            
        # Start background sync for the rest
        threading.Thread(target=background_sync, args=(em, pw), daemon=True).start()
        
        return jsonify({'ok': True, 'email': em, 'synced': synced})
    except Exception as ex:
        return jsonify({'ok': True, 'email': em, 'synced': 0, 'sync_error': str(ex)})

@app.route('/api/logout', methods=['POST'])
def logout():
    db = get_db()
    db.execute("UPDATE settings SET value='' WHERE key='gmail_email'")
    db.execute("UPDATE settings SET value='' WHERE key='gmail_app_password'")
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/auth-check')
def auth_check():
    db = get_db()
    em = db.execute("SELECT value FROM settings WHERE key='gmail_email'").fetchone()
    if em and em['value']:
        return jsonify({'logged_in': True, 'email': em['value']})
    return jsonify({'logged_in': False})

@app.route('/predict', methods=['POST'])
def predict():
    d = request.get_json(force=True)
    return jsonify(run_scan(d.get('subject',''), d.get('body','')))

@app.route('/health')
def health():
    return jsonify({"status":"ok","model":"RandomForest Pipeline"})

# ── Email CRUD ───────────────────────────────────────────────────────────────
def _row_to_dict(r):
    return {
        'id':r['id'],'message_id':r['message_id'],'folder':r['folder'],
        'sender_name':r['sender_name'],'sender_email':r['sender_email'],
        'recipient':r['recipient'],'subject':r['subject'],
        'body':r['body_text'] or '','body_html':r['body_html'] or '',
        'date':r['date_str'],'date_ts':r['date_ts'],
        'is_read':bool(r['is_read']),'is_starred':bool(r['is_starred']),
        'scan': {
            'label':r['scan_label'],'confidence':r['scan_confidence'],
            'p_phishing':r['scan_p_phishing'],'p_safe':r['scan_p_safe'],
            'features':json.loads(r['scan_features']) if r['scan_features'] else None
        } if r['scan_label'] else None,
    }

@app.route('/api/emails')
def list_emails():
    db = get_db(); folder = request.args.get('folder','inbox')
    search = request.args.get('search','')
    q = 'SELECT * FROM emails WHERE is_trash=0'; p = []
    if folder == 'starred': q += ' AND is_starred=1'
    elif folder == 'sent': q += " AND folder='sent'"
    elif folder == 'trash': q = 'SELECT * FROM emails WHERE is_trash=1'; p = []
    elif folder == 'phishing': q += " AND scan_label='phishing'"
    elif folder == 'safe': q += " AND scan_label='safe'"
    else: q += " AND folder='inbox'"
    if search:
        q += ' AND (subject LIKE ? OR sender_name LIKE ? OR body_text LIKE ?)'
        s = f'%{search}%'; p += [s,s,s]
    q += ' ORDER BY date_ts DESC'
    return jsonify([_row_to_dict(r) for r in db.execute(q, p).fetchall()])

@app.route('/api/emails/<int:eid>')
def get_email(eid):
    db = get_db()
    r = db.execute('SELECT * FROM emails WHERE id=?',(eid,)).fetchone()
    if not r: return jsonify({'error':'Not found'}), 404
    db.execute('UPDATE emails SET is_read=1 WHERE id=?',(eid,)); db.commit()
    return jsonify(_row_to_dict(r))

@app.route('/api/emails/<int:eid>/star', methods=['PUT'])
def toggle_star(eid):
    db = get_db()
    db.execute('UPDATE emails SET is_starred = 1 - is_starred WHERE id=?',(eid,)); db.commit()
    r = db.execute('SELECT is_starred FROM emails WHERE id=?',(eid,)).fetchone()
    return jsonify({'is_starred': bool(r['is_starred']) if r else False})

@app.route('/api/emails/<int:eid>/trash', methods=['PUT'])
def trash_email(eid):
    db = get_db()
    db.execute('UPDATE emails SET is_trash=1 WHERE id=?',(eid,)); db.commit()
    return jsonify({'ok': True})

@app.route('/api/emails/<int:eid>/rescan', methods=['POST'])
def rescan(eid):
    db = get_db(); result = scan_email_row(db, eid)
    return jsonify(result) if result else (jsonify({'error':'Not found'}), 404)

# ── Sync Emails ──────────────────────────────────────────────────────────────
@app.route('/api/sync', methods=['POST'])
def sync_emails():
    db = get_db()
    em = db.execute("SELECT value FROM settings WHERE key='gmail_email'").fetchone()
    pw = db.execute("SELECT value FROM settings WHERE key='gmail_app_password'").fetchone()
    if not em or not pw or not em['value'] or not pw['value']:
        return jsonify({'error':'Email not configured. Please login first.'}), 400
    try:
        fetched = fetch_emails_imap(em['value'], pw['value'])
        new_count = 0
        for e in fetched:
            exists = db.execute('SELECT id FROM emails WHERE message_id=?',(e['message_id'],)).fetchone()
            if exists: continue
            c = db.execute('''INSERT INTO emails (message_id,folder,sender_name,sender_email,
                recipient,subject,body_text,body_html,date_str,date_ts)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                ('inbox' if not e['message_id'] else e['message_id'],'inbox',
                 e['sender_name'],e['sender_email'],e['recipient'],e['subject'],
                 e['body_text'],e['body_html'],e['date_str'],e['date_ts']))
            db.commit()
            scan_email_row(db, c.lastrowid)
            new_count += 1
        return jsonify({'synced': new_count, 'total': len(fetched)})
    except Exception as ex:
        return jsonify({'error': str(ex)}), 500

# ── Send ─────────────────────────────────────────────────────────────────────
@app.route('/api/send', methods=['POST'])
def send_email():
    db = get_db(); d = request.get_json(force=True)
    em = db.execute("SELECT value FROM settings WHERE key='gmail_email'").fetchone()
    pw = db.execute("SELECT value FROM settings WHERE key='gmail_app_password'").fetchone()
    to = d.get('to',''); subj = d.get('subject',''); body = d.get('body','')
    if not to: return jsonify({'error':'Recipient required'}), 400
    if em and pw and em['value'] and pw['value']:
        try:
            send_email_smtp(em['value'], pw['value'], to, subj, body)
        except Exception as ex:
            return jsonify({'error': f'SMTP error: {ex}'}), 500
    # Save to sent
    import time
    db.execute('''INSERT INTO emails (message_id,folder,sender_name,sender_email,
        recipient,subject,body_text,date_str,date_ts)
        VALUES (?,?,?,?,?,?,?,?,?)''',
        (f'sent-{time.time()}','sent','You',em['value'] if em else 'you',
         to,subj,body,datetime.now().strftime('%b %d, %I:%M %p'),time.time()))
    db.commit()
    return jsonify({'ok': True})

# ── Stats ────────────────────────────────────────────────────────────────────
@app.route('/api/stats')
def stats():
    db = get_db()
    total = db.execute('SELECT COUNT(*) c FROM emails WHERE is_trash=0').fetchone()['c']
    scanned = db.execute('SELECT COUNT(*) c FROM emails WHERE scan_label IS NOT NULL AND is_trash=0').fetchone()['c']
    phish = db.execute("SELECT COUNT(*) c FROM emails WHERE scan_label='phishing' AND is_trash=0").fetchone()['c']
    safe = db.execute("SELECT COUNT(*) c FROM emails WHERE scan_label='safe' AND is_trash=0").fetchone()['c']
    unread = db.execute('SELECT COUNT(*) c FROM emails WHERE is_read=0 AND is_trash=0').fetchone()['c']
    return jsonify({'total':total,'scanned':scanned,'phishing':phish,'safe':safe,'unread':unread})

# ── Settings ─────────────────────────────────────────────────────────────────
@app.route('/api/settings', methods=['GET'])
def get_settings():
    db = get_db()
    rows = db.execute('SELECT key, value FROM settings').fetchall()
    s = {r['key']: r['value'] for r in rows}
    if 'gmail_app_password' in s and s['gmail_app_password']:
        s['gmail_app_password'] = '••••••••'
    return jsonify(s)

@app.route('/api/settings', methods=['PUT'])
def update_settings():
    db = get_db(); d = request.get_json(force=True)
    for k, v in d.items():
        if k == 'gmail_app_password' and v == '••••••••': continue
        db.execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', (k, v))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/scan-all', methods=['POST'])
def scan_all():
    db = get_db()
    rows = db.execute('SELECT id FROM emails WHERE scan_label IS NULL AND is_trash=0').fetchall()
    for r in rows:
        scan_email_row(db, r['id'])
    return jsonify({'scanned': len(rows)})

# ══════════════════════════════════════════════════════════════════════════════
#  INIT & RUN
# ══════════════════════════════════════════════════════════════════════════════
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)