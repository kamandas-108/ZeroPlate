"""ZeroPlate - surplus food redistribution platform (Flask + Neon PostgreSQL + Gemini)."""
import os, math, hashlib, datetime as dt
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv
import psycopg2, psycopg2.extras

load_dotenv()
BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

DB_URL = os.getenv("NEON_DB_STRING", "")
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "")
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
SECRET = os.getenv("SECRET_KEY") or (hashlib.sha256(("zp" + DB_URL).encode()).hexdigest() if DB_URL else "dev-secret")
ser = URLSafeTimedSerializer(SECRET)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('provider','recipient')), org_name TEXT NOT NULL,
  lat DOUBLE PRECISION, lng DOUBLE PRECISION, capacity INT DEFAULT 50, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS listings(
  id SERIAL PRIMARY KEY, provider_id INT REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL,
  food_type TEXT NOT NULL, quantity INT NOT NULL, notes TEXT DEFAULT '', address TEXT DEFAULT '',
  lat DOUBLE PRECISION NOT NULL, lng DOUBLE PRECISION NOT NULL, deadline TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'available', claimed_by INT REFERENCES users(id), created_at TIMESTAMPTZ DEFAULT now());
"""
_ready = False


def run(sql, args=(), fetch="all"):
    if not DB_URL:
        raise RuntimeError("NEON_DB_STRING is not set on the server.")
    conn = psycopg2.connect(DB_URL, connect_timeout=10)
    try:
        with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, args)
            if fetch == "all": return [clean(r) for r in cur.fetchall()]
            if fetch == "one":
                r = cur.fetchone()
                return clean(r) if r else None
    finally:
        conn.close()


def clean(r):
    return {k: (v.isoformat() if isinstance(v, (dt.datetime, dt.date)) else v) for k, v in r.items()}


def now(): return dt.datetime.now(dt.timezone.utc)


def err(msg, code=400): return jsonify(error=msg), code


@app.before_request
def boot():
    global _ready
    if request.path.startswith("/api") and not _ready and DB_URL:
        try:
            run(SCHEMA, fetch=None); _ready = True
        except Exception as e:
            print("DB init failed:", e)


def current_user():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "): return None
    try:
        uid = ser.loads(h[7:], max_age=7 * 86400)
    except (BadSignature, SignatureExpired):
        return None
    return run("SELECT id,name,email,role,org_name,lat,lng,capacity FROM users WHERE id=%s", (uid,), "one")


def need_user(role=None):
    u = current_user()
    if not u: return None, err("Please sign in first.", 401)
    if role and u["role"] != role: return None, err(f"Only {role}s can do this.", 403)
    return u, None


def km(a, b, c, d):
    p = math.pi / 180
    x = math.sin((c - a) * p / 2) ** 2 + math.cos(a * p) * math.cos(c * p) * math.sin((d - b) * p / 2) ** 2
    return 12742 * math.asin(math.sqrt(x))


def mins_left(l):
    return round((dt.datetime.fromisoformat(l["deadline"]) - now()).total_seconds() / 60)


# ---------- pages ----------
@app.route("/")
def home(): return send_from_directory(BASE, "index.html")


@app.route("/healthz")
def health(): return jsonify(ok=True)


@app.errorhandler(404)
def nf(e):
    if request.path.startswith("/api"): return err("Not found", 404)
    return send_from_directory(BASE, "index.html")


# ---------- auth ----------
@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    name, email, pw = (d.get("name") or "").strip(), (d.get("email") or "").strip().lower(), d.get("password") or ""
    role, org = d.get("role"), (d.get("org_name") or "").strip()
    if not (name and "@" in email and org) or role not in ("provider", "recipient"): return err("Fill in all fields.")
    if len(pw) < 6: return err("Password must be at least 6 characters.")
    try:
        if run("SELECT 1 FROM users WHERE email=%s", (email,), "one"): return err("Email already registered.", 409)
        u = run("INSERT INTO users(name,email,password_hash,role,org_name,lat,lng,capacity) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) "
                "RETURNING id,name,email,role,org_name,lat,lng,capacity",
                (name, email, generate_password_hash(pw), role, org, float(d.get("lat") or 20.2961),
                 float(d.get("lng") or 85.8245), int(d.get("capacity") or 50)), "one")
    except Exception as e:
        return err(str(e), 500)
    return jsonify(token=ser.dumps(u["id"]), user=u)


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    try:
        u = run("SELECT * FROM users WHERE email=%s", ((d.get("email") or "").strip().lower(),), "one")
    except Exception as e:
        return err(str(e), 500)
    if not u or not check_password_hash(u["password_hash"], d.get("password") or ""): return err("Wrong email or password.", 401)
    u.pop("password_hash")
    return jsonify(token=ser.dumps(u["id"]), user=u)


@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(user=u) if u else err("Not signed in", 401)


# ---------- listings ----------
def fetch_listings():
    run("UPDATE listings SET status='expired' WHERE status='available' AND deadline<now()", fetch=None)
    rows = run("SELECT l.*, u.org_name AS provider FROM listings l JOIN users u ON u.id=l.provider_id "
               "WHERE l.status IN ('available','claimed') ORDER BY l.deadline LIMIT 200")
    for r in rows: r["minutes_left"] = mins_left(r)
    return rows


@app.get("/api/listings")
def listings():
    try: return jsonify(listings=fetch_listings())
    except Exception as e: return err(str(e), 500)


@app.post("/api/listings")
def add_listing():
    u, e = need_user("provider")
    if e: return e
    d = request.get_json(silent=True) or {}
    try:
        qty = int(d.get("quantity")); deadline = dt.datetime.fromisoformat(d["deadline"].replace("Z", "+00:00"))
        lat, lng = float(d["lat"]), float(d["lng"])
    except Exception:
        return err("Check quantity, deadline and location.")
    if not (d.get("title") or "").strip() or qty < 1: return err("Add a title and quantity.")
    if deadline <= now(): return err("Pickup deadline must be in the future.")
    row = run("INSERT INTO listings(provider_id,title,food_type,quantity,notes,address,lat,lng,deadline) "
              "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
              (u["id"], d["title"].strip()[:120], (d.get("food_type") or "Cooked meals")[:40], qty,
               (d.get("notes") or "")[:500], (d.get("address") or "")[:200], lat, lng, deadline), "one")
    return jsonify(id=row["id"])


@app.post("/api/listings/<int:lid>/claim")
def claim(lid):
    u, e = need_user("recipient")
    if e: return e
    r = run("UPDATE listings SET status='claimed', claimed_by=%s WHERE id=%s AND status='available' AND deadline>now() RETURNING id",
            (u["id"], lid), "one")
    return jsonify(ok=True) if r else err("Already claimed or expired.", 409)


@app.post("/api/listings/<int:lid>/complete")
def complete(lid):
    u, e = need_user()
    if e: return e
    r = run("UPDATE listings SET status='completed' WHERE id=%s AND status='claimed' AND (provider_id=%s OR claimed_by=%s) RETURNING id",
            (lid, u["id"], u["id"]), "one")
    return jsonify(ok=True) if r else err("Cannot complete this listing.", 409)


@app.get("/api/recipients")
def recipients():
    try:
        return jsonify(recipients=run("SELECT id,org_name,lat,lng,capacity FROM users WHERE role='recipient' AND lat IS NOT NULL"))
    except Exception as e: return err(str(e), 500)


@app.get("/api/stats")
def stats():
    try:
        run("UPDATE listings SET status='expired' WHERE status='available' AND deadline<now()", fetch=None)
        s = run("SELECT COALESCE(SUM(quantity) FILTER (WHERE status='completed'),0) AS meals,"
                "COUNT(*) FILTER (WHERE status='completed') AS donations,"
                "COALESCE(SUM(quantity) FILTER (WHERE status IN ('available','claimed')),0) AS active,"
                "COALESCE(SUM(quantity) FILTER (WHERE status='expired'),0) AS wasted FROM listings", fetch="one")
        week = run("SELECT created_at::date AS d, SUM(quantity) AS meals FROM listings WHERE status='completed' "
                   "AND created_at>now()-interval '7 days' GROUP BY 1 ORDER BY 1")
        meals = int(s["meals"])
        return jsonify(meals=meals, donations=int(s["donations"]), active=int(s["active"]), wasted=int(s["wasted"]),
                       waste_kg=round(meals * 0.4, 1), co2_kg=round(meals * 0.4 * 2.5, 1), people=meals, week=week)
    except Exception as e: return err(str(e), 500)


# ---------- matching + AI ----------
def rank(l, recs):
    left, out = max(mins_left(l), 1), []
    for r in recs:
        d = km(l["lat"], l["lng"], r["lat"], r["lng"])
        travel = d / 25 * 60 + 10
        feasible = travel <= left
        cap = min(1, (r["capacity"] or 50) / max(l["quantity"], 1))
        score = 0.5 * (1 - min(d / 15, 1)) + 0.3 * (min(1, (left - travel) / max(left, 1)) if feasible else 0) + 0.2 * cap
        out.append(dict(id=r["id"], name=r["org_name"], distance_km=round(d, 1), travel_min=round(travel),
                        capacity=r["capacity"], feasible=feasible, score=round(score * 100)))
    return sorted(out, key=lambda x: -x["score"])[:5]


def gemini(prompt, as_json=False):
    if not GEMINI_KEY: return None
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_KEY)
        cfg = {"temperature": 0.3}
        if as_json: cfg["response_mime_type"] = "application/json"
        return genai.GenerativeModel(MODEL, generation_config=cfg).generate_content(prompt).text
    except Exception as e:
        print("Gemini error:", e); return None


@app.post("/api/ai/recommend")
def recommend():
    u, e = need_user()
    if e: return e
    lid = (request.get_json(silent=True) or {}).get("listing_id")
    try:
        l = next((x for x in fetch_listings() if x["id"] == lid), None)
        if not l: return err("Listing not found or no longer active.", 404)
        recs = run("SELECT id,org_name,lat,lng,capacity FROM users WHERE role='recipient' AND lat IS NOT NULL")
    except Exception as ex: return err(str(ex), 500)
    top = rank(l, recs)
    urgent = l["minutes_left"] <= 60
    advice = None
    if top:
        import json
        advice = gemini(
            "You are a food-rescue dispatcher. Given this surplus listing and ranked nearby recipients, write 3 short sentences: "
            "who should receive it first and why, a safety/packing tip for this food type, and an urgency note. Plain text, no markdown.\n"
            + json.dumps({"listing": {k: l[k] for k in ("title", "food_type", "quantity", "minutes_left", "notes")}, "ranked": top}))
    if not advice:
        advice = (f"{top[0]['name']} is the best match ({top[0]['distance_km']} km away). " if top else "No recipients registered nearby yet. ") + \
                 ("Pickup is urgent - contact them now. " if urgent else "") + "Keep hot food above 60C and pack cold food on ice."
    return jsonify(listing=l["title"], urgent=urgent, minutes_left=l["minutes_left"], matches=top, advice=advice)


@app.post("/api/ai/ask")
def ask():
    u, e = need_user()
    if e: return e
    q = ((request.get_json(silent=True) or {}).get("question") or "").strip()[:500]
    if not q: return err("Ask a question first.")
    try: ls = fetch_listings()[:25]
    except Exception as ex: return err(str(ex), 500)
    ctx = "\n".join(f"#{x['id']} {x['title']} ({x['quantity']} meals, {x['food_type']}) by {x['provider']}, {x['minutes_left']} min left, {x['status']}" for x in ls)
    a = gemini(f"You are ZeroPlate's food redistribution assistant. User role: {u['role']}. Live listings:\n{ctx or 'none'}\n\n"
               f"Question: {q}\nAnswer briefly in plain text, prioritising listings with the least time left.")
    return jsonify(answer=a or "AI is unavailable right now. Check GEMINI_API_KEY on the server.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
