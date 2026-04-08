import os, json, uuid, hashlib, hmac, secrets, logging
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, jsonify,
                   session, redirect, url_for, make_response, abort)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# ── APP ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# ── RATE LIMITER ──────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address, app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)

# ── DATABASE ────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = bool(DATABASE_URL)

DATA_DIR = "data"
USERS_FILE        = os.path.join(DATA_DIR, "users.json")
PROMOS_FILE       = os.path.join(DATA_DIR, "promos.json")
TRANSACTIONS_FILE = os.path.join(DATA_DIR, "transactions.json")
STORE_FILE        = os.path.join(DATA_DIR, "store.json")
AUDIT_FILE        = os.path.join(DATA_DIR, "audit.json")
SQLITE_FILE       = os.path.join(DATA_DIR, "saoluis.db")

# SQLite (Windows / dev local)
import sqlite3
def get_sqlite():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(SQLITE_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def get_pg():
    try:
        import psycopg2
    except ImportError:
        raise RuntimeError("psycopg2 nao instalado. Configure DATABASE_URL ou use SQLite.")
    url = DATABASE_URL
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    conn = psycopg2.connect(url)
    conn.autocommit = True
    return conn

def use_sqlite():
    return not USE_PG

def init_pg():
    conn = get_pg()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT, email TEXT UNIQUE, password TEXT,
        role TEXT, phone TEXT, points INTEGER DEFAULT 0,
        member_since TEXT, card_number TEXT,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS promos (
        id TEXT PRIMARY KEY, title TEXT, product TEXT,
        discount TEXT, bonus_pct REAL, active BOOLEAN,
        created_at TEXT, expires_at TEXT, target TEXT
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY, user_id TEXT, type TEXT,
        points INTEGER, description TEXT, date TEXT,
        created_by TEXT
    );
    CREATE TABLE IF NOT EXISTS store (
        key TEXT PRIMARY KEY, value TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY, actor TEXT, action TEXT,
        target TEXT, detail TEXT, ip TEXT, ts TIMESTAMP DEFAULT NOW()
    );
    """)
    cur.close()
    log.info("PostgreSQL tables ready")

def init_sqlite():
    conn = get_sqlite()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT, email TEXT UNIQUE, password TEXT,
        role TEXT, phone TEXT, points INTEGER DEFAULT 0,
        member_since TEXT, card_number TEXT,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT
    );
    CREATE TABLE IF NOT EXISTS promos (
        id TEXT PRIMARY KEY, title TEXT, product TEXT,
        discount TEXT, bonus_pct REAL, active INTEGER DEFAULT 1,
        created_at TEXT, expires_at TEXT, target TEXT
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY, user_id TEXT, type TEXT,
        points INTEGER, description TEXT, date TEXT,
        created_by TEXT
    );
    CREATE TABLE IF NOT EXISTS store (
        key TEXT PRIMARY KEY, value TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT, action TEXT, target TEXT,
        detail TEXT, ip TEXT, ts TEXT
    );
    """)
    conn.commit()
    conn.close()
    log.info("SQLite tables ready")

# ── JSON FALLBACK HELPERS ─────────────────────────────────────────────────────
def load_json(path, default):
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default

def save_json(path, data):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# ── UNIVERSAL DB HELPERS ──────────────────────────────────────────────────────
def _row_to_dict(row):
    if row is None: return None
    if isinstance(row, dict): return row
    if isinstance(row, sqlite3.Row): return dict(row)
    return row

def db_get_user_by_email(email):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("SELECT id,name,email,password,role,phone,points,member_since,card_number,failed_attempts,locked_until FROM users WHERE email=%s OR phone=%s", (email, email))
        row = cur.fetchone(); cur.close()
        if not row: return None
        cols=["id","name","email","password","role","phone","points","member_since","card_number","failed_attempts","locked_until"]
        return dict(zip(cols, row))
    conn = get_sqlite(); cur = conn.execute("SELECT * FROM users WHERE email=? OR phone=?", (email, email))
    row = cur.fetchone(); conn.close()
    return _row_to_dict(row)

def db_get_user(uid):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("SELECT id,name,email,password,role,phone,points,member_since,card_number,failed_attempts,locked_until FROM users WHERE id=%s", (uid,))
        row = cur.fetchone(); cur.close()
        if not row: return None
        cols=["id","name","email","password","role","phone","points","member_since","card_number","failed_attempts","locked_until"]
        return dict(zip(cols, row))
    conn = get_sqlite(); cur = conn.execute("SELECT * FROM users WHERE id=?", (uid,))
    row = cur.fetchone(); conn.close()
    return _row_to_dict(row)

def db_save_user(u):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("""INSERT INTO users (id,name,email,password,role,phone,points,member_since,card_number,failed_attempts,locked_until)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,email=EXCLUDED.email,password=EXCLUDED.password,
        phone=EXCLUDED.phone,points=EXCLUDED.points,failed_attempts=EXCLUDED.failed_attempts,locked_until=EXCLUDED.locked_until""",
        (u["id"],u["name"],u.get("email",""),u["password"],u["role"],u.get("phone",""),
         u.get("points",0),u.get("member_since",""),u.get("card_number",""),
         u.get("failed_attempts",0),u.get("locked_until")))
        cur.close(); return
    conn = get_sqlite()
    conn.execute("""INSERT INTO users (id,name,email,password,role,phone,points,member_since,card_number,failed_attempts,locked_until)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET name=excluded.name,email=excluded.email,password=excluded.password,
    phone=excluded.phone,points=excluded.points,failed_attempts=excluded.failed_attempts,locked_until=excluded.locked_until""",
    (u["id"],u["name"],u.get("email",""),u["password"],u["role"],u.get("phone",""),
     u.get("points",0),u.get("member_since",""),u.get("card_number",""),
     u.get("failed_attempts",0),str(u.get("locked_until","")) if u.get("locked_until") else None))
    conn.commit(); conn.close()

def db_all_customers():
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("SELECT id,name,email,phone,points,member_since,card_number FROM users WHERE role='customer' ORDER BY points DESC")
        rows = cur.fetchall(); cur.close()
        cols=["id","name","email","phone","points","member_since","card_number"]
        return [dict(zip(cols,r)) for r in rows]
    conn = get_sqlite()
    rows = conn.execute("SELECT id,name,email,phone,points,member_since,card_number FROM users WHERE role='customer' ORDER BY points DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def db_get_promos(active_only=False):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        q = "SELECT id,title,product,discount,bonus_pct,active,created_at,expires_at,target FROM promos" + (" WHERE active=TRUE" if active_only else "") + " ORDER BY created_at DESC"
        cur.execute(q); rows = cur.fetchall(); cur.close()
        cols=["id","title","product","discount","bonus_pct","active","created_at","expires_at","target"]
        return [dict(zip(cols,r)) for r in rows]
    conn = get_sqlite()
    q = "SELECT * FROM promos" + (" WHERE active=1" if active_only else "") + " ORDER BY created_at DESC"
    rows = conn.execute(q).fetchall(); conn.close()
    return [dict(r) for r in rows]

def db_save_promo(p):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("INSERT INTO promos (id,title,product,discount,bonus_pct,active,created_at,expires_at,target) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (p["id"],p["title"],p["product"],p["discount"],p["bonus_pct"],p["active"],p["created_at"],p["expires_at"],p.get("target","all")))
        cur.close(); return
    conn = get_sqlite()
    conn.execute("INSERT INTO promos (id,title,product,discount,bonus_pct,active,created_at,expires_at,target) VALUES (?,?,?,?,?,?,?,?,?)",
    (p["id"],p["title"],p["product"],p["discount"],p["bonus_pct"],1 if p["active"] else 0,p["created_at"],p["expires_at"],p.get("target","all")))
    conn.commit(); conn.close()

def db_save_transaction(t):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("INSERT INTO transactions (id,user_id,type,points,description,date,created_by) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (t["id"],t["user_id"],t["type"],t["points"],t["description"],t["date"],t.get("created_by","system")))
        cur.close(); return
    conn = get_sqlite()
    conn.execute("INSERT INTO transactions (id,user_id,type,points,description,date,created_by) VALUES (?,?,?,?,?,?,?)",
    (t["id"],t["user_id"],t["type"],t["points"],t["description"],t["date"],t.get("created_by","system")))
    conn.commit(); conn.close()

def db_get_transactions(user_id):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("SELECT id,user_id,type,points,description,date,created_by FROM transactions WHERE user_id=%s ORDER BY date DESC LIMIT 30", (user_id,))
        rows = cur.fetchall(); cur.close()
        cols=["id","user_id","type","points","description","date","created_by"]
        return [dict(zip(cols,r)) for r in rows]
    conn = get_sqlite()
    rows = conn.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY date DESC LIMIT 30", (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def db_get_store():
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("SELECT key,value FROM store"); rows = cur.fetchall(); cur.close()
        return {r[0]:r[1] for r in rows} if rows else default_store()
    conn = get_sqlite()
    rows = conn.execute("SELECT key,value FROM store").fetchall(); conn.close()
    return {r["key"]:r["value"] for r in rows} if rows else default_store()

def db_save_store(data):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        for k,v in data.items():
            cur.execute("INSERT INTO store(key,value) VALUES(%s,%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",(k,str(v)))
        cur.close(); return
    conn = get_sqlite()
    for k,v in data.items():
        conn.execute("INSERT INTO store(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,str(v)))
    conn.commit(); conn.close()

def db_audit(actor, action, target="", detail="", ip=""):
    ts = datetime.now().isoformat()
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("INSERT INTO audit_log(actor,action,target,detail,ip) VALUES(%s,%s,%s,%s,%s)",(actor,action,target,detail,ip))
        cur.close()
    else:
        conn = get_sqlite()
        conn.execute("INSERT INTO audit_log(actor,action,target,detail,ip,ts) VALUES(?,?,?,?,?,?)",(actor,action,target,detail,ip,ts))
        conn.commit(); conn.close()
    log.info(f"AUDIT | {actor} | {action} | {target} | {detail}")

def default_store():
    return {"name":"Supermercado São Luis","slogan":"A sua escolha Feliz!",
            "phone":"(61) 3393-3233","address":"QR 209 - Santa Maria, Brasília-DF",
            "points_per_real":"1","max_discount":"10","whatsapp_notify":"true"}

def db_delete_user(uid):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=%s AND role='customer'", (uid,))
        deleted = cur.rowcount; cur.close()
        return deleted > 0
    conn = get_sqlite()
    cur = conn.execute("DELETE FROM users WHERE id=? AND role='customer'", (uid,))
    conn.commit(); deleted = cur.rowcount; conn.close()
    return deleted > 0

def db_cadastro_by_owner(name, phone, pw):
    """Dono cadastra cliente direto no painel"""
    uid  = "c_" + str(uuid.uuid4())[:8]
    card = f"SL-{str(uuid.uuid4())[:4].upper()}-{str(uuid.uuid4())[:4].upper()}-DF"
    u = {"id":uid, "name":name.strip(),
         "email": f"{uid}@saoluis.local",
         "password": hash_pw(pw or uid),
         "role":"customer", "phone":phone.strip(),
         "points":0, "member_since":datetime.now().strftime("%Y-%m-%d"),
         "card_number":card, "failed_attempts":0}
    db_save_user(u)
    return u

# ── HELPERS ───────────────────────────────────────────────────────────────────
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def make_card_qr_token(card_number):
    secret = app.secret_key if isinstance(app.secret_key, bytes) else app.secret_key.encode()
    return hmac.new(secret, card_number.encode(), hashlib.sha256).hexdigest()[:16]

def get_tier(pts):
    if pts >= 4000: return "Ouro"
    if pts >= 1000: return "Prata"
    return "Bronze"

def get_discount(pts, active_promo=None):
    base = 0.5
    if pts >= 5000: base = 10
    elif pts >= 4000: base = 8
    elif pts >= 3000: base = 6
    elif pts >= 2000: base = 4
    elif pts >= 1000: base = 2
    elif pts >= 500:  base = 1
    if active_promo:
        base = min(base + float(active_promo.get("bonus_pct", 0)), 10)
    return base

def send_whatsapp(phone, message):
    INST = os.environ.get("ZAPI_INSTANCE","")
    TOKEN= os.environ.get("ZAPI_TOKEN","")
    if not INST or not TOKEN:
        log.info(f"[WhatsApp simulado] {phone}: {message[:60]}")
        return True
    import requests as req
    clean = phone.replace("+","").replace("-","").replace(" ","").replace("(","").replace(")","")
    try:
        r = req.post(
            f"https://api.z-api.io/instances/{INST}/token/{TOKEN}/send-text",
            json={"phone": clean, "message": message}, timeout=8)
        return r.status_code == 200
    except Exception as e:
        log.error(f"WhatsApp error: {e}")
        return False

# ── DECORATORS ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error":"Não autenticado"}), 401
            return redirect(url_for("login_page"))
        session.modified = True
        return f(*a, **kw)
    return dec

def owner_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if session.get("role") != "owner":
            return jsonify({"error":"Acesso negado"}), 403
        return f(*a, **kw)
    return dec

# ── SEED ──────────────────────────────────────────────────────────────────────
def seed():
    os.makedirs(DATA_DIR, exist_ok=True)
    if USE_PG:
        try: init_pg()
        except Exception as e: log.error(f"PG init error: {e}")
    else:
        try: init_sqlite()
        except Exception as e: log.error(f"SQLite init error: {e}")

    # seed owner
    owner = db_get_user("owner_1")
    if not owner:
        db_save_user({"id":"owner_1","name":"Dono São Luis",
            "email":"dono@saoluis.com.br","password":hash_pw("saoluis123"),
            "role":"owner","phone":"61999999999","points":0,
            "member_since":datetime.now().strftime("%Y-%m-%d"),
            "card_number":"","failed_attempts":0})
        log.info("Seed: owner criado")

    # seed client
    c = db_get_user("client_1")
    if not c:
        db_save_user({"id":"client_1","name":"Maria Silva",
            "email":"maria@email.com","password":hash_pw("123456"),
            "role":"customer","phone":"61988887777","points":4820,
            "member_since":"2024-01-15","card_number":"SL-8847-3321-DF",
            "failed_attempts":0})
        db_save_transaction({"id":str(uuid.uuid4()),"user_id":"client_1",
            "type":"purchase","points":120,"description":"Compra no São Luis",
            "date":"2025-07-05 09:42","created_by":"caixa"})
        log.info("Seed: cliente demo criado")

    # seed store
    store = db_get_store()
    if not store:
        db_save_store(default_store())

# ── PAGES ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("owner_dashboard" if session.get("role")=="owner" else "customer_card"))
    return render_template("splash.html")

@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("icons/favicon.ico")

@app.route("/login")
def login_page():
    if "user_id" in session:
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/cliente")
@login_required
def customer_card():
    if session.get("role") == "owner":
        return redirect(url_for("owner_dashboard"))
    return render_template("cliente.html")

@app.route("/dono")
@login_required
@owner_required
def owner_dashboard():
    return render_template("dono.html")

@app.route("/cadastro")
def cadastro_page():
    return render_template("cadastro.html")

@app.route("/offline")
def offline():
    return render_template("offline.html")

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(429)
def rate_limit_handler(e):
    return jsonify({"error":"Muitas tentativas. Aguarde alguns minutos."}), 429

# ── FORCE HTTPS ───────────────────────────────────────────────────────────────
@app.before_request
def force_https():
    if not app.debug and request.headers.get("X-Forwarded-Proto","https") == "http":
        return redirect(request.url.replace("http://","https://"), 301)

# ── AUTH API ──────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def api_login():
    data = request.json or {}
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
    ip    = request.remote_addr

    if not email or not pw:
        return jsonify({"ok":False,"msg":"Preencha todos os campos"}), 400

    u = db_get_user_by_email(email)
    if not u:
        db_audit("anon", "login_failed", email, "usuário não encontrado", ip)
        return jsonify({"ok":False,"msg":"Email ou senha incorretos"}), 401

    # check lock
    locked = u.get("locked_until")
    if locked:
        locked_dt = datetime.fromisoformat(str(locked)) if isinstance(locked,str) else locked
        if datetime.now() < locked_dt:
            mins = int((locked_dt - datetime.now()).seconds / 60) + 1
            return jsonify({"ok":False,"msg":f"Conta bloqueada. Tente em {mins} minuto(s)."}), 429

    if u["password"] != hash_pw(pw):
        attempts = u.get("failed_attempts", 0) + 1
        u["failed_attempts"] = attempts
        if attempts >= 5:
            u["locked_until"] = (datetime.now() + timedelta(minutes=15)).isoformat()
            db_audit(email, "account_locked", email, f"{attempts} tentativas", ip)
        db_save_user(u)
        remaining = max(0, 5 - attempts)
        msg = "Senha incorreta." + (f" {remaining} tentativa(s) restante(s)." if remaining > 0 else " Conta bloqueada por 15 min.")
        return jsonify({"ok":False,"msg":msg}), 401

    # success
    u["failed_attempts"] = 0
    u["locked_until"] = None
    db_save_user(u)
    session.permanent = True
    session["user_id"] = u["id"]
    session["role"]    = u["role"]
    session["name"]    = u["name"]
    db_audit(u["name"], "login", u["id"], "login bem-sucedido", ip)
    return jsonify({"ok":True,"role":u["role"],"name":u["name"]})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    if "name" in session:
        db_audit(session["name"], "logout", session.get("user_id",""), "", request.remote_addr)
    session.clear()
    return jsonify({"ok":True})

@app.route("/api/cadastro", methods=["POST"])
@limiter.limit("3 per minute")
def api_cadastro():
    data = request.json or {}
    name  = data.get("name","").strip()
    email = data.get("email","").strip().lower()
    phone = data.get("phone","").strip()
    pw    = data.get("password","")

    if not name or not pw:
        return jsonify({"ok":False,"msg":"Nome e senha são obrigatórios"}), 400
    if len(pw) < 6:
        return jsonify({"ok":False,"msg":"Senha muito curta (mínimo 6 caracteres)"}), 400
    if email and db_get_user_by_email(email):
        return jsonify({"ok":False,"msg":"Email já cadastrado"}), 400

    uid  = "c_" + str(uuid.uuid4())[:8]
    card = f"SL-{str(uuid.uuid4())[:4].upper()}-{str(uuid.uuid4())[:4].upper()}-DF"
    u = {"id":uid,"name":name,"email":email or f"{uid}@saoluis.local",
         "password":hash_pw(pw),"role":"customer","phone":phone,
         "points":0,"member_since":datetime.now().strftime("%Y-%m-%d"),
         "card_number":card,"failed_attempts":0}
    db_save_user(u)

    store = db_get_store()
    msg = (f"🏪 Bem-vindo ao {store.get('name','São Luis')}!\n"
           f"✅ Seu cartão digital está ativo!\n"
           f"💳 Cartão: {card}\n"
           f"⭐ Acumule pontos e ganhe descontos de até 10%!\n"
           f"📍 {store.get('address','')}\n"
           f"A sua escolha Feliz! 🎉")
    if phone:
        send_whatsapp(phone, msg)

    db_audit(name, "cadastro", uid, f"phone:{phone}", request.remote_addr)
    return jsonify({"ok":True,"card":card})

@app.route("/api/change_password", methods=["POST"])
@login_required
def api_change_password():
    data = request.json or {}
    u = db_get_user(session["user_id"])
    if u["password"] != hash_pw(data.get("current","")):
        return jsonify({"ok":False,"msg":"Senha atual incorreta"}), 400
    new_pw = data.get("new","")
    if len(new_pw) < 6:
        return jsonify({"ok":False,"msg":"Nova senha muito curta"}), 400
    u["password"] = hash_pw(new_pw)
    db_save_user(u)
    db_audit(session["name"], "change_password", session["user_id"], "", request.remote_addr)
    return jsonify({"ok":True})

# ── CLIENTE API ───────────────────────────────────────────────────────────────
@app.route("/api/cliente/me")
@login_required
def api_me():
    u = db_get_user(session["user_id"])
    if not u:
        session.clear()
        return jsonify({"error":"Sessão inválida"}), 401
    pts = u.get("points",0)
    promos = db_get_promos(active_only=True)
    active_promo = promos[0] if promos else None
    token = make_card_qr_token(u.get("card_number",""))
    return jsonify({
        "name": u["name"], "card_number": u.get("card_number",""),
        "qr_token": token, "points": pts, "tier": get_tier(pts),
        "discount": get_discount(pts, active_promo),
        "member_since": u.get("member_since",""), "phone": u.get("phone","")
    })

@app.route("/api/cliente/transactions")
@login_required
def api_transactions():
    return jsonify(db_get_transactions(session["user_id"]))

@app.route("/api/cliente/promos")
@login_required
def api_promos():
    return jsonify(db_get_promos(active_only=True))

# ── DONO API ──────────────────────────────────────────────────────────────────
@app.route("/api/dono/stats")
@login_required
@owner_required
def api_stats():
    customers = db_all_customers()
    promos    = db_get_promos(active_only=True)
    tier_counts = {"Ouro":0,"Prata":0,"Bronze":0}
    for c in customers:
        tier_counts[get_tier(c.get("points",0))] += 1
    return jsonify({
        "total_customers": len(customers),
        "today_purchases": max(12, len(customers)//3),
        "today_revenue":   max(1800, len(customers)*5),
        "active_promos":   len(promos),
        "tiers":           tier_counts,
        "engagement":      [45,62,38,80,55,95,72]
    })

@app.route("/api/dono/clientes")
@login_required
@owner_required
def api_clientes():
    customers = db_all_customers()
    result = []
    for c in customers:
        pts = c.get("points",0)
        result.append({
            "id":c["id"],"name":c["name"],"points":pts,
            "tier":get_tier(pts),"discount":get_discount(pts),
            "phone":c.get("phone",""),"member_since":c.get("member_since","")
        })
    return jsonify(result)

@app.route("/api/dono/send_promo", methods=["POST"])
@login_required
@owner_required
def api_send_promo():
    data = request.json or {}
    days_map = {"1":1,"2":2,"3":3,"7":7}
    days_val = days_map.get(str(data.get("days","1")), 1)
    promo = {
        "id": str(uuid.uuid4()),
        "title":     data.get("title","Promoção"),
        "product":   data.get("product",""),
        "discount":  data.get("discount","5%"),
        "bonus_pct": float(str(data.get("discount","5%")).replace("%","").replace(",",".")),
        "active":    True,
        "created_at":datetime.now().strftime("%Y-%m-%d %H:%M"),
        "expires_at":(datetime.now()+timedelta(days=days_val)).strftime("%Y-%m-%d"),
        "target":    data.get("target","all"),
    }
    db_save_promo(promo)

    store     = db_get_store()
    customers = db_all_customers()
    target    = data.get("target","all")
    if target == "ouro":
        targets = [c for c in customers if get_tier(c.get("points",0))=="Ouro"]
    elif target == "prata_ouro":
        targets = [c for c in customers if get_tier(c.get("points",0)) in ["Ouro","Prata"]]
    else:
        targets = customers

    sent = 0
    for c in targets:
        if not c.get("phone"): continue
        msg = (f"🏪 {store.get('name','São Luis')}\n"
               f"🔥 PROMOÇÃO: {promo['title']}\n"
               f"📦 {promo['product']}\n"
               f"💰 {promo['discount']} OFF para clientes fidelidade!\n"
               f"⏰ Válido por {days_val} dia(s)\n"
               f"📍 {store.get('address','')}\n"
               f"A sua escolha Feliz! 🎉")
        if send_whatsapp(c["phone"], msg):
            sent += 1

    db_audit(session["name"],"send_promo",promo["id"],
             f"title:{promo['title']} sent:{sent}", request.remote_addr)
    return jsonify({"ok":True,"sent":sent,"promo_id":promo["id"]})

@app.route("/api/dono/add_points", methods=["POST"])
@login_required
@owner_required
def api_add_points():
    data = request.json or {}
    uid  = data.get("user_id","")
    val  = data.get("value", 0)
    try: val = float(val)
    except: return jsonify({"ok":False,"msg":"Valor inválido"}), 400

    store  = db_get_store()
    ppr    = int(store.get("points_per_real","1"))
    pts    = int(val * ppr)
    if pts <= 0:
        return jsonify({"ok":False,"msg":"Valor deve ser maior que zero"}), 400

    u = db_get_user(uid)
    if not u:
        return jsonify({"ok":False,"msg":"Cliente não encontrado"}), 404

    u["points"] = u.get("points",0) + pts
    db_save_user(u)

    db_save_transaction({"id":str(uuid.uuid4()),"user_id":uid,
        "type":"purchase","points":pts,
        "description":f"Compra R${val:.2f} — {store.get('name','')}",
        "date":datetime.now().strftime("%Y-%m-%d %H:%M"),
        "created_by":session["name"]})

    db_audit(session["name"],"add_points",uid,
             f"R${val:.2f} → +{pts}pts", request.remote_addr)

    new_pts = u["points"]
    tier    = get_tier(new_pts)
    disc    = get_discount(new_pts)

    if u.get("phone"):
        msg = (f"🏪 {store.get('name','São Luis')}\n"
               f"✅ Compra registrada! R${val:.2f}\n"
               f"➕ +{pts} pontos adicionados\n"
               f"⭐ Total: {new_pts} pontos ({tier})\n"
               f"💰 Desconto atual: {disc}%\n"
               f"A sua escolha Feliz! 🎉")
        send_whatsapp(u["phone"], msg)

    return jsonify({"ok":True,"new_points":new_pts,"tier":tier,"discount":disc})

@app.route("/api/dono/store", methods=["GET","POST"])
@login_required
@owner_required
def api_store():
    if request.method == "GET":
        return jsonify(db_get_store())
    data = request.json or {}
    store = db_get_store()
    store.update(data)
    db_save_store(store)
    db_audit(session["name"],"update_store","store","configurações salvas",request.remote_addr)
    return jsonify({"ok":True})

@app.route("/api/dono/audit")
@login_required
@owner_required
def api_audit():
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("SELECT actor,action,target,detail,ip,ts FROM audit_log ORDER BY ts DESC LIMIT 50")
        rows = cur.fetchall(); cur.close()
        cols=["actor","action","target","detail","ip","ts"]
        return jsonify([dict(zip(cols,r)) for r in rows])
    conn = get_sqlite()
    rows = conn.execute("SELECT actor,action,target,detail,ip,ts FROM audit_log ORDER BY ts DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── DONO: CADASTRAR E EXCLUIR CLIENTES ───────────────────────────────────────
@app.route("/api/dono/cadastrar_cliente", methods=["POST"])
@login_required
@owner_required
def api_cadastrar_cliente():
    data = request.json or {}
    name  = data.get("name","").strip()
    phone = data.get("phone","").strip()
    pw    = data.get("password","").strip()
    if not name:
        return jsonify({"ok":False, "msg":"Nome é obrigatório"}), 400
    if not phone:
        return jsonify({"ok":False, "msg":"WhatsApp é obrigatório"}), 400
    u = db_cadastro_by_owner(name, phone, pw or phone[-4:])
    store = db_get_store()
    loja_nome = store.get("name", "São Luis")
    senha_prov = pw or phone[-4:]
    card_num   = u["card_number"]
    linhas = [
        "🏪 Bem-vindo ao " + loja_nome + "!",
        "✅ Seu cartão foi criado!",
        "💳 Cartão: " + card_num,
        "🔑 Senha provisória: " + senha_prov,
        "⭐ Acumule pontos e ganhe até 10% de desconto!",
        "A sua escolha Feliz! 🎉"
    ]
    msg = "\n".join(linhas)
    if phone:
        send_whatsapp(phone, msg)
    db_audit(session["name"], "cadastrar_cliente", u["id"],
             f"nome:{name} phone:{phone}", request.remote_addr)
    return jsonify({"ok":True, "card": u["card_number"], "id": u["id"],
                    "senha": pw or phone[-4:]})

@app.route("/api/dono/excluir_cliente", methods=["POST"])
@login_required
@owner_required
def api_excluir_cliente():
    data = request.json or {}
    uid  = data.get("user_id","")
    if not uid:
        return jsonify({"ok":False, "msg":"ID do cliente não informado"}), 400
    if uid in ("owner_1", session.get("user_id")):
        return jsonify({"ok":False, "msg":"Não é possível excluir este usuário"}), 400
    deleted = db_delete_user(uid)
    if not deleted:
        return jsonify({"ok":False, "msg":"Cliente não encontrado"}), 404
    db_audit(session["name"], "excluir_cliente", uid,
             "cliente excluído", request.remote_addr)
    return jsonify({"ok":True})

# ── QR SCAN ───────────────────────────────────────────────────────────────────
@app.route("/qr/<card_number>/<token>")
def qr_scan(card_number, token):
    expected = make_card_qr_token(card_number)
    if not hmac.compare_digest(expected, token):
        abort(403)
    customers = db_all_customers()
    u = next((c for c in customers if c.get("card_number")==card_number), None)
    if not u:
        abort(404)
    pts  = u.get("points",0)
    return render_template("qr_scan.html", user=u,
                           tier=get_tier(pts), discount=get_discount(pts))

# ── PWA MANIFEST & SERVICE WORKER ────────────────────────────────────────────
@app.route("/manifest.json")
def manifest():
    r = make_response(json.dumps({
        "name": "São Luis Fidelidade",
        "short_name": "São Luis",
        "description": "Cartão digital de fidelidade",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0D1B3E",
        "theme_color": "#1A52C8",
        "orientation": "portrait",
        "icons": [
            {"src":"/static/icons/icon-192.png","sizes":"192x192","type":"image/png"},
            {"src":"/static/icons/icon-512.png","sizes":"512x512","type":"image/png"}
        ]
    }))
    r.headers["Content-Type"] = "application/json"
    return r

@app.route("/sw.js")
def service_worker():
    sw = """
const CACHE = 'saoluis-v1';
const ASSETS = ['/', '/login', '/static/css/main.css', '/offline'];
self.addEventListener('install', e => e.waitUntil(
  caches.open(CACHE).then(c => c.addAll(ASSETS)).catch(()=>{})
));
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request).then(r => r || caches.match('/offline')))
  );
});
"""
    r = make_response(sw)
    r.headers["Content-Type"] = "application/javascript"
    r.headers["Service-Worker-Allowed"] = "/"
    return r

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    seed()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

# ── TERMINAL DE AUTOATENDIMENTO ───────────────────────────────────────────────
@app.route('/terminal')
def terminal_page():
    store = db_get_store()
    return render_template('terminal.html', store=store)

@app.route('/api/terminal/pontuar', methods=['POST'])
@limiter.limit('10 per minute')
def api_terminal_pontuar():
    data = request.json or {}
    phone = data.get('phone','').strip().replace(' ','').replace('-','').replace('(','').replace(')','')
    valor_str = str(data.get('value','')).strip().replace(',','.')
    ip = request.remote_addr

    if not phone or len(phone) < 8:
        return jsonify({'ok':False,'msg':'Telefone invalido. Digite com DDD.'}), 400

    try:
        valor = float(valor_str)
    except:
        return jsonify({'ok':False,'msg':'Valor invalido. Ex: 85.50'}), 400

    if valor <= 0 or valor > 9999:
        return jsonify({'ok':False,'msg':'Valor fora do limite permitido.'}), 400

    store = db_get_store()
    limite_dia = float(store.get('limite_dia_terminal','500'))

    today = datetime.now().strftime('%Y-%m-%d')
    all_txs = load_json(TRANSACTIONS_FILE, []) if not USE_PG else db_get_all_transactions_today(today)
    total_hoje = sum(float(t.get('value',0)) for t in all_txs
                     if t.get('source')=='terminal' and
                     _get_user_phone_from_tx(t) == phone and
                     str(t.get('date','')).startswith(today))

    if total_hoje + valor > limite_dia:
        restante = max(0, limite_dia - total_hoje)
        return jsonify({'ok':False,'msg':'Limite diario atingido. Restam R$ {:.2f} para hoje.'.format(restante)}), 400

    u = db_get_user_by_email(phone)
    novo = False
    if not u:
        uid = 'c_' + str(uuid.uuid4())[:8]
        card = 'SL-{}-{}-DF'.format(str(uuid.uuid4())[:4].upper(), str(uuid.uuid4())[:4].upper())
        u = {'id':uid,'name':'Cliente '+phone[-4:],'email':uid+'@saoluis.local',
             'password':hash_pw(phone[-4:]),'role':'customer','phone':phone,
             'points':0,'member_since':datetime.now().strftime('%Y-%m-%d'),
             'card_number':card,'failed_attempts':0}
        db_save_user(u)
        novo = True

    store_ppr = int(store.get('points_per_real','1'))
    pts = max(1, int(valor * store_ppr))
    u['points'] = u.get('points',0) + pts
    db_save_user(u)

    tx = {'id':str(uuid.uuid4()),'user_id':u['id'],'type':'purchase',
          'points':pts,'value':valor,'source':'terminal',
          'description':'Compra R${:.2f} - Terminal'.format(valor),
          'date':datetime.now().strftime('%Y-%m-%d %H:%M'),'created_by':'terminal'}
    db_save_transaction(tx)

    new_pts = u['points']
    tier = get_tier(new_pts)
    disc = get_discount(new_pts)
    loja = store.get('name','Sao Luis')

    if novo:
        msg = ('🏪 Bem-vindo ao {}!\n'
               '✅ Cadastro realizado!\n'
               '💳 Cartao: {}\n'
               '➕ +{} pontos!\n'
               '💰 Desconto: {}%\n'
               'A sua escolha Feliz! 🎉').format(loja, u['card_number'], pts, disc)
    else:
        msg = ('🏪 {}\n'
               '✅ Compra: R${:.2f}\n'
               '➕ +{} pontos\n'
               '⭐ Total: {} pts ({})\n'
               '💰 Desconto: {}%\n'
               'A sua escolha Feliz! 🎉').format(loja, valor, pts, new_pts, tier, disc)

    send_whatsapp(phone, msg)

    owner_phone = store.get('owner_phone','')
    alerta = float(store.get('alerta_valor','300'))
    if valor >= alerta and owner_phone:
        alert_msg = ('⚠️ ALERTA Terminal Sao Luis\n'
                     'Valor: R${:.2f}\n'
                     'Fone: {}\n'
                     'Pts: +{}\n'
                     'Hora: {}').format(valor, phone, pts, datetime.now().strftime('%d/%m %H:%M'))
        send_whatsapp(owner_phone, alert_msg)

    db_audit('terminal','pontuar',u['id'],'phone:{} valor:{:.2f} pts:{}'.format(phone,valor,pts), ip)

    return jsonify({'ok':True,'novo':novo,'points_added':pts,'total_points':new_pts,
                    'tier':tier,'discount':disc,'card':u.get('card_number',''),'name':u['name']})

def db_get_all_transactions_today(today):
    if USE_PG:
        conn = get_pg(); cur = conn.cursor()
        cur.execute("SELECT id,user_id,type,points,description,date,created_by FROM transactions WHERE date LIKE %s", (today+'%',))
        rows = cur.fetchall(); cur.close()
        cols = ["id","user_id","type","points","description","date","created_by"]
        return [dict(zip(cols,r)) for r in rows]
    return load_json(TRANSACTIONS_FILE, [])

def _get_user_phone_from_tx(tx):
    u = db_get_user(tx.get('user_id',''))
    return u.get('phone','') if u else ''
