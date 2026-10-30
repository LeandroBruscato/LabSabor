import os, re, json, sqlite3, hashlib, secrets, time, threading, datetime, tempfile, glob
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

DB  = os.environ.get("DB_PATH", "/data/vendas.db")
BK  = os.environ.get("BACKUP_DIR", "/backups")
FL  = ["Amendoim","Banana","Banana com canela","Banana com canela e açúcar","Banana com açaí",
       "Banana com açaí e açúcar","Cacau","Cacau com pimenta","Cacau sem açúcar",
       "Cacau com pimenta sem açúcar","Goiaba","Goiaba sem açúcar","Cebola",
       "Cebola com orégano e pimenta","Batata doce","Batata doce com lemon pepper",
       "Grão de bico com alecrim","Grão de bico com pimenta","Morango","Morango com orégano"]

class Err(Exception): pass

def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c

def hp(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 200000).hex()

def cfg(c):
    r = c.execute("SELECT * FROM config WHERE id=1").fetchone()
    return {"pu": r["pu"], "pb": r["pb"], "min": r["min_qty"], "prazo": r["prazo"]}

def init():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    os.makedirs(BK, exist_ok=True)
    c = db()
    c.executescript("""
CREATE TABLE IF NOT EXISTS config(
  id INTEGER PRIMARY KEY CHECK(id=1),
  pu REAL DEFAULT 18.0, pb REAL DEFAULT 16.5,
  min_qty INTEGER DEFAULT 35, prazo INTEGER DEFAULT 30);
INSERT OR IGNORE INTO config(id) VALUES(1);
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, pw TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS sessions(tok TEXT PRIMARY KEY, name TEXT, exp REAL);
CREATE TABLE IF NOT EXISTS clients(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT, type TEXT, phone TEXT, city TEXT,
  cnpj TEXT, prazo INTEGER, obs TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS sales(
  id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, type TEXT,
  cli TEXT, cli_id INTEGER, st TEXT, fr REAL,
  venc TEXT, paid_on TEXT, created_by TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS items(
  sale INTEGER REFERENCES sales(id), p TEXT, q INTEGER, pu REAL);""")
    for u in os.environ.get("USERS","").split(";"):
        p = u.split(":")
        if len(p) == 3:
            c.execute("INSERT OR REPLACE INTO users VALUES(?,?,?)",
                      (p[0].strip(), hp(p[1]), p[2].strip()))
    c.commit(); c.close()

def backup(path):
    s = db(); d = sqlite3.connect(path)
    s.backup(d); d.close(); s.close()

def loop():
    while True:
        try:
            backup(f"{BK}/vendas-{datetime.date.today()}.db")
            for f in sorted(glob.glob(BK+"/vendas-*.db"))[:-14]:
                os.remove(f)
        except Exception as e: print("backup:", e)
        time.sleep(86400)

def ser_sale(c, r):
    it = [dict(p=i["p"],q=i["q"],pu=i["pu"])
          for i in c.execute("SELECT * FROM items WHERE sale=?", (r["id"],))]
    u   = sum(i["q"] for i in it)
    sub = sum(i["q"]*i["pu"] for i in it)
    return dict(id=str(r["id"]), date=r["date"], type=r["type"],
                cli=r["cli"], cli_id=r["cli_id"],
                items=it, u=u, sub=sub, fr=r["fr"],
                total=sub+r["fr"], st=r["st"],
                venc=r["venc"], paidOn=r["paid_on"])

def ser_client(r):
    return dict(id=str(r["id"]), name=r["name"], type=r["type"],
                phone=r["phone"] or "", city=r["city"] or "",
                cnpj=r["cnpj"] or "", prazo=r["prazo"],
                obs=r["obs"] or "", active=r["active"])

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def out(s, code, data, ct="application/json", extra=()):
        b = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
        s.send_response(code)
        s.send_header("Content-Type", ct)
        s.send_header("Content-Length", str(len(b)))
        for k,v in extra: s.send_header(k,v)
        s.end_headers(); s.wfile.write(b)

    def me(s):
        ck  = s.headers.get("Cookie") or ""
        tok = next((x.split("=",1)[1] for x in ck.split("; ") if x.startswith("tok=")), "")
        c   = db()
        r   = c.execute("SELECT u.name,u.role FROM sessions s JOIN users u ON u.name=s.name "
                        "WHERE s.tok=? AND s.exp>?", (tok, time.time())).fetchone()
        c.close()
        return dict(r) if r else None

    def body(s):
        return json.loads(s.rfile.read(int(s.headers.get("Content-Length") or 0)) or b"{}")

    def do_GET(s):
        p = s.path.split("?")[0]
        if p == "/":
            return s.out(200, open("index.html","rb").read(), "text/html; charset=utf-8")
        u = s.me()
        if not u: return s.out(401, {"erro":"login"})
        c = db()
        if p == "/api/me":
            cf = cfg(c); c.close()
            return s.out(200, {**u, **cf})
        if p == "/api/clients":
            r = [ser_client(x) for x in c.execute("SELECT * FROM clients ORDER BY name")]
            c.close(); return s.out(200, r)
        if u["role"] != "admin":
            c.close(); return s.out(403, {"erro":"sem permissão"})
        if p == "/api/sales":
            r = [ser_sale(c,x) for x in c.execute("SELECT * FROM sales ORDER BY id")]
            c.close(); return s.out(200, r)
        if p == "/api/config":
            r = cfg(c); c.close(); return s.out(200, r)
        if p == "/api/backup":
            c.close()
            f = tempfile.mktemp(); backup(f)
            d = open(f,"rb").read(); os.remove(f)
            return s.out(200, d, "application/octet-stream",
                         [("Content-Disposition",
                           f'attachment; filename="vendas-{datetime.date.today()}.db"')])
        c.close(); s.out(404, {"erro":"não encontrado"})

    def do_POST(s):
        p = s.path
        try: b = s.body()
        except: return s.out(400, {"erro":"Dados inválidos."})

        if p == "/api/login":
            c = db()
            r = c.execute("SELECT * FROM users WHERE name=?", (str(b.get("u")),)).fetchone()
            if not r or hp(str(b.get("p")), r["pw"].split("$")[0]) != r["pw"]:
                c.close(); time.sleep(1); return s.out(401, {"erro":"login"})
            tok = secrets.token_hex(24)
            c.execute("INSERT INTO sessions VALUES(?,?,?)", (tok, r["name"], time.time()+30*86400))
            c.commit(); c.close()
            sec = "; Secure" if s.headers.get("X-Forwarded-Proto")=="https" else ""
            return s.out(200, {"ok":1},
                         extra=[("Set-Cookie",
                                 f"tok={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{sec}")])

        u = s.me()
        if not u: return s.out(401, {"erro":"login"})

        if p == "/api/sales":   return s.new_sale(u, b)
        if p == "/api/clients": return s.new_client(u, b)

        m = re.match(r"/api/sales/(\d+)/(pay|cancel)$", p)
        if m and u["role"]=="admin":
            c = db()
            if m[2]=="pay":
                c.execute("UPDATE sales SET st='pago',paid_on=? WHERE id=? AND st='pendente'",
                          (str(datetime.date.today()), m[1]))
            else:
                c.execute("UPDATE sales SET st='cancelada' WHERE id=?", (m[1],))
            c.commit(); c.close(); return s.out(200, {"ok":1})

        m2 = re.match(r"/api/clients/(\d+)$", p)
        if m2 and u["role"]=="admin": return s.edit_client(m2[1], b)

        m3 = re.match(r"/api/clients/(\d+)/deactivate$", p)
        if m3 and u["role"]=="admin":
            c = db()
            c.execute("UPDATE clients SET active=0 WHERE id=?", (m3[1],))
            c.commit(); c.close(); return s.out(200, {"ok":1})

        m4 = re.match(r"/api/clients/(\d+)/activate$", p)
        if m4 and u["role"]=="admin":
            c = db()
            c.execute("UPDATE clients SET active=1 WHERE id=?", (m4[1],))
            c.commit(); c.close(); return s.out(200, {"ok":1})

        if p == "/api/config" and u["role"]=="admin":
            c = db()
            try:
                pu = float(b["pu"]); pb = float(b["pb"])
                mn = int(b["min"]); pr = int(b["prazo"])
                assert pu>0 and pb>0 and mn>0 and pr>0
            except: c.close(); return s.out(400, {"erro":"Valores inválidos."})
            c.execute("UPDATE config SET pu=?,pb=?,min_qty=?,prazo=? WHERE id=1",(pu,pb,mn,pr))
            c.commit(); c.close(); return s.out(200, {"ok":1})

        s.out(403, {"erro":"sem permissão"})

    def new_sale(s, u, b):
        c = db(); cf = cfg(c)
        try:
            t  = b.get("type")
            dt = datetime.date.fromisoformat(b.get("date"))
            q  = {}
            for i in b.get("items",[]):
                n = int(i["q"])
                if n > 0:
                    if i["p"] not in FL: raise Err("Sabor inválido.")
                    q[i["p"]] = q.get(i["p"],0) + n
            total_u = sum(q.values())
            if t not in ("final","b2b"): raise Err("Tipo inválido.")
            if not total_u: raise Err("Escolha ao menos um sabor.")
            pu  = cf["pb"] if total_u >= cf["min"] else cf["pu"]
            st  = "pendente" if t=="b2b" and b.get("st")=="pendente" else "pago"
            fr  = max(0.0, float(b.get("fr") or 0)) if t=="b2b" else 0.0
            venc= None
            if st == "pendente":
                raw = b.get("venc")
                venc= raw if raw else str(dt+datetime.timedelta(days=cf["prazo"]))
                datetime.date.fromisoformat(venc)
            cli_id = b.get("cli_id") or None
            cli    = str(b.get("cli") or "")[:80]
            if cli_id:
                cr = c.execute("SELECT name FROM clients WHERE id=?", (cli_id,)).fetchone()
                if cr: cli = cr["name"]
        except Err as e: c.close(); return s.out(400, {"erro":str(e)})
        except: c.close(); return s.out(400, {"erro":"Dados inválidos."})
        cur = c.execute(
            "INSERT INTO sales(date,type,cli,cli_id,st,fr,venc,created_by,at) VALUES(?,?,?,?,?,?,?,?,?)",
            (str(dt),t,cli,cli_id,st,fr,venc,u["name"],datetime.datetime.now().isoformat()))
        c.executemany("INSERT INTO items VALUES(?,?,?,?)",
                      [(cur.lastrowid, p, v, pu) for p,v in q.items()])
        c.commit(); c.close(); return s.out(200, {"ok":1})

    def new_client(s, u, b):
        c = db()
        try:
            name = str(b.get("name","")).strip()[:80]
            if not name: raise Err("Nome obrigatório.")
            tp   = b.get("type","final")
            if tp not in ("final","b2b"): raise Err("Tipo inválido.")
            raw  = b.get("prazo","")
            pr   = int(raw) if str(raw).strip() else None
        except Err as e: c.close(); return s.out(400,{"erro":str(e)})
        c.execute("INSERT INTO clients(name,type,phone,city,cnpj,prazo,obs) VALUES(?,?,?,?,?,?,?)",
                  (name, tp, str(b.get("phone",""))[:20], str(b.get("city",""))[:60],
                   str(b.get("cnpj",""))[:20], pr, str(b.get("obs",""))[:200]))
        c.commit(); rid = c.lastrowid
        r = ser_client(c.execute("SELECT * FROM clients WHERE id=?", (rid,)).fetchone())
        c.close(); return s.out(200, r)

    def edit_client(s, cid, b):
        c = db()
        try:
            name = str(b.get("name","")).strip()[:80]
            if not name: raise Err("Nome obrigatório.")
            tp   = b.get("type","final")
            if tp not in ("final","b2b"): raise Err("Tipo inválido.")
            raw  = b.get("prazo","")
            pr   = int(raw) if str(raw).strip() else None
        except Err as e: c.close(); return s.out(400,{"erro":str(e)})
        c.execute("UPDATE clients SET name=?,type=?,phone=?,city=?,cnpj=?,prazo=?,obs=? WHERE id=?",
                  (name, tp, str(b.get("phone",""))[:20], str(b.get("city",""))[:60],
                   str(b.get("cnpj",""))[:20], pr, str(b.get("obs",""))[:200], cid))
        c.commit()
        r = ser_client(c.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone())
        c.close(); return s.out(200, r)

if __name__ == "__main__":
    init()
    threading.Thread(target=loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
