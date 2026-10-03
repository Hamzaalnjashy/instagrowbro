import os, time, base64, hashlib, sqlite3, secrets, requests
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, g, request, session, redirect, flash, abort, render_template_string
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.getenv("PROD") == "1")
PASSWORD = os.environ["PANEL_PASSWORD"]
DB = os.getenv("DB_PATH", "panel.db")
FINAL = ("Completed", "Canceled", "Partial", "Refunded")
F = Fernet(base64.urlsafe_b64encode(hashlib.sha256(app.secret_key.encode()).digest()))
FAILS = {}

SCHEMA = """
create table if not exists providers(id integer primary key, name text, url text, key text);
create table if not exists services(id integer primary key, provider_id int, pid text, name text, category text, rate real, min int, max int, unique(provider_id,pid));
create table if not exists orders(id integer primary key, provider_id int, pname text, sname text, link text, qty int, cost real, provider_order text, status text default 'Pending', created text default current_timestamp);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

with app.app_context():
    db().executescript(SCHEMA)

def get_p(pid):
    p = db().execute("select * from providers where id=?", (pid,)).fetchone()
    if not p: abort(404)
    return p

def pcall(p, **data):
    r = requests.post(p["url"], data={"key": F.decrypt(p["key"].encode()).decode(), **data}, timeout=30)
    r.raise_for_status()
    return r.json()

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("ok"): return redirect("/login")
        return f(*a, **k)
    return w

@app.before_request
def csrf_check():
    if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
        abort(400)

BASE = """<!doctype html><html dir=rtl lang=ar><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>{{t}}</title>
<style>body{font-family:system-ui;max-width:900px;margin:2rem auto;padding:0 1rem}
input,select,button{padding:.5rem;margin:.2rem 0;width:100%;box-sizing:border-box}
table{width:100%;border-collapse:collapse;font-size:.9rem}td,th{border-bottom:1px solid #ddd;padding:.3rem;text-align:right}
.m{background:#fff3cd;padding:.5rem;margin:.5rem 0}.c{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}nav a{margin-left:1rem}</style>
{% if ok %}<nav><a href=/>المزوّدون</a><a href=/orders>الطلبات</a><a href=/logout>خروج</a></nav>{% endif %}
{% for m in get_flashed_messages() %}<div class=m>{{m}}</div>{% endfor %}{{body|safe}}</html>"""

def page(t, body, **c):
    tok = session.setdefault("csrf", secrets.token_hex(16))
    c["ci"] = Markup(f'<input type=hidden name=csrf value="{tok}">')
    return render_template_string(BASE, t=t, ok=session.get("ok"), body=render_template_string(body, **c))

@app.route("/login", methods=["GET", "POST"])
def login():
    ip, now = request.remote_addr, time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 600]
    if request.method == "POST":
        if len(FAILS[ip]) >= 5:
            flash("محاولات كثيرة، حاول بعد 10 دقائق")
        elif secrets.compare_digest(request.form.get("pw", ""), PASSWORD):
            session.clear(); session["ok"] = True
            return redirect("/")
        else:
            FAILS[ip].append(now); flash("كلمة المرور غير صحيحة")
    return page("دخول", """<h2>دخول</h2><form method=post>{{ci}}
<input name=pw type=password placeholder="كلمة المرور" required><button>دخول</button></form>""")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

HOME = """<div class=c><h3>إضافة مزوّد جديد</h3><form method=post action=/providers/add>{{ci}}
<input name=name placeholder="اسم المزوّد" required>
<input name=url placeholder="رابط API مثل https://site.com/api/v2" required>
<input name=key type=password autocomplete=off placeholder="مفتاح API" required><button>إضافة وربط</button></form></div>
{% for p,b in ps %}<div class=c><h3>{{p.name}}</h3><p>رصيدك: <b>{{b}}</b> | عدد الخدمات: {{p.n}}</p>
<a href="/p/{{p.id}}">عرض الخدمات وتنفيذ طلب</a>
<form method=post action="/p/{{p.id}}/sync">{{ci}}<button>مزامنة الخدمات</button></form>
<details><summary>تعديل / حذف</summary>
<form method=post action="/p/{{p.id}}/save">{{ci}}<input name=url value="{{p.url}}">
<input name=key type=password autocomplete=off placeholder="مفتاح جديد (فارغ = إبقاء الحالي)"><button>حفظ</button></form>
<form method=post action="/p/{{p.id}}/delete" onsubmit="return confirm('حذف المزوّد؟')">{{ci}}<button>حذف المزوّد</button></form></details></div>
{% else %}<p>لا يوجد مزوّدون بعد. أضف أول مزوّد من النموذج أعلاه.</p>{% endfor %}"""

@app.route("/")
@login_required
def home():
    ps = db().execute("select p.*, (select count(*) from services s where s.provider_id=p.id) n from providers p order by id").fetchall()
    def bal(p):
        try:
            r = pcall(p, action="balance"); return f"{r.get('balance')} {r.get('currency', '')}"
        except Exception: return "تعذّر الجلب"
    with ThreadPoolExecutor(8) as ex: bals = list(ex.map(bal, ps))
    return page("المزوّدون", HOME, ps=list(zip(ps, bals)))

@app.post("/providers/add")
@login_required
def add_provider():
    name, url, key = (request.form.get(k, "").strip() for k in ("name", "url", "key"))
    if not (name and key and url.startswith("http")):
        flash("بيانات غير صحيحة"); return redirect("/")
    db().execute("insert into providers(name,url,key) values(?,?,?)", (name, url, F.encrypt(key.encode()).decode()))
    db().commit(); flash("تمت الإضافة. اضغط مزامنة الخدمات")
    return redirect("/")

@app.post("/p/<int:pid>/save")
@login_required
def save_provider(pid):
    p = get_p(pid); url = request.form.get("url", "").strip(); key = request.form.get("key", "").strip()
    if url.startswith("http"):
        db().execute("update providers set url=?, key=? where id=?",
                     (url, F.encrypt(key.encode()).decode() if key else p["key"], pid))
        db().commit(); flash("تم الحفظ")
    return redirect("/")

@app.post("/p/<int:pid>/delete")
@login_required
def delete_provider(pid):
    get_p(pid); d = db()
    d.execute("delete from services where provider_id=?", (pid,)); d.execute("delete from providers where id=?", (pid,))
    d.commit(); flash("تم الحذف")
    return redirect("/")

@app.post("/p/<int:pid>/sync")
@login_required
def sync(pid):
    p, d, n = get_p(pid), db(), 0
    try: items = pcall(p, action="services")
    except Exception as e:
        flash(f"فشلت المزامنة: {e}"); return redirect("/")
    for i in items:
        d.execute("""insert into services(provider_id,pid,name,category,rate,min,max) values(?,?,?,?,?,?,?)
            on conflict(provider_id,pid) do update set name=excluded.name,category=excluded.category,
            rate=excluded.rate,min=excluded.min,max=excluded.max""",
            (pid, str(i["service"]), i["name"], i.get("category", ""), float(i["rate"]), int(i["min"]), int(i["max"])))
        n += 1
    d.commit(); flash(f"تمت مزامنة {n} خدمة من {p['name']}")
    return redirect(f"/p/{pid}")

PROV = """<h2>{{p.name}}</h2><p>رصيدك: <b>{{bal}}</b></p>
<form method=get><input name=q value="{{q}}" placeholder="بحث في الخدمات (مثال: instagram followers)"><button>بحث</button></form>
<div class=c><h3>تنفيذ طلب</h3><form method=post action=/order>{{ci}}
<select name=service required>{% for s in rows %}<option value="{{s.id}}">#{{s.pid}} | {{s.name}} | {{s.rate}}/1000 ({{s.min}}-{{s.max}})</option>{% endfor %}</select>
<input name=link placeholder="الرابط https://..." required><input name=qty type=number placeholder="الكمية" required>
<button>إرسال الطلب</button></form></div>
<table><tr><th>ID</th><th>الفئة</th><th>الخدمة</th><th>السعر/1000</th><th>الحد</th></tr>
{% for s in rows %}<tr><td>{{s.pid}}</td><td>{{s.category}}</td><td>{{s.name}}</td><td>{{s.rate}}</td><td>{{s.min}}-{{s.max}}</td></tr>{% endfor %}</table>
<p>يُعرض أول 500 نتيجة، استخدم البحث للتضييق.</p>"""

@app.route("/p/<int:pid>")
@login_required
def provider(pid):
    p, q = get_p(pid), request.args.get("q", "").strip()
    rows = db().execute("select * from services where provider_id=? and (name like ? or category like ?) order by category,name limit 500",
                        (pid, f"%{q}%", f"%{q}%")).fetchall()
    try:
        r = pcall(p, action="balance"); bal = f"{r.get('balance')} {r.get('currency', '')}"
    except Exception: bal = "تعذّر الجلب"
    return page(p["name"], PROV, p=p, rows=rows, q=q, bal=bal)

@app.post("/order")
@login_required
def order():
    d = db()
    s = d.execute("select * from services where id=?", (request.form.get("service"),)).fetchone()
    if not s: abort(400)
    p, back = get_p(s["provider_id"]), f"/p/{s['provider_id']}"
    link = request.form.get("link", "").strip()
    try: qty = int(request.form.get("qty", 0))
    except ValueError: qty = 0
    if not link.startswith("http") or not s["min"] <= qty <= s["max"]:
        flash("رابط غير صحيح أو كمية خارج الحدود"); return redirect(back)
    try: po = pcall(p, action="add", service=s["pid"], link=link, quantity=qty)
    except Exception as e:
        flash(f"تعذّر إرسال الطلب: {e}"); return redirect(back)
    if "order" not in po:
        flash(f"رفض المزوّد الطلب: {po.get('error', po)}"); return redirect(back)
    d.execute("insert into orders(provider_id,pname,sname,link,qty,cost,provider_order) values(?,?,?,?,?,?,?)",
              (p["id"], p["name"], s["name"], link, qty, round(s["rate"] * qty / 1000, 4), str(po["order"])))
    d.commit(); flash("تم إرسال الطلب بنجاح")
    return redirect("/orders")

ORDERS = """<h2>الطلبات</h2><table><tr><th>#</th><th>المزوّد</th><th>الخدمة</th><th>الرابط</th><th>الكمية</th><th>التكلفة</th><th>الحالة</th></tr>
{% for o in orders %}<tr><td>{{o.id}}</td><td>{{o.pname}}</td><td>{{o.sname}}</td><td>{{o.link}}</td><td>{{o.qty}}</td><td>{{o.cost}}</td><td>{{o.status}}</td></tr>{% endfor %}</table>"""

@app.route("/orders")
@login_required
def orders():
    d = db()
    for o in d.execute("select * from orders order by id desc limit 50").fetchall():
        if o["status"] in FINAL: continue
        p = d.execute("select * from providers where id=?", (o["provider_id"],)).fetchone()
        if not p: continue
        try: st = pcall(p, action="status", order=o["provider_order"]).get("status", o["status"])
        except Exception: continue
        d.execute("update orders set status=? where id=?", (st, o["id"]))
    d.commit()
    return page("الطلبات", ORDERS, orders=d.execute("select * from orders order by id desc limit 50").fetchall())

if __name__ == "__main__":
    app.run(debug=False)
