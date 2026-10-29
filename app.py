import os, re, json, sqlite3, hashlib, secrets, time, threading, datetime, tempfile, glob
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

DB = os.environ.get("DB_PATH", "/data/vendas.db")
BK = os.environ.get("BACKUP_DIR", "/backups")
PF, PB, MIN, PRAZO = 18.0, 16.5, 35, 30  # preço final, preço B2B, mínimo B2B, prazo (dias)
FL = ["Amendoim", "Banana", "Banana com canela", "Banana com canela e açúcar", "Banana com açaí",
      "Banana com açaí e açúcar", "Cacau", "Cacau com pimenta", "Cacau sem açúcar",
      "Cacau com pimenta sem açúcar", "Goiaba", "Goiaba sem açúcar", "Cebola",
      "Cebola com orégano e pimenta", "Batata doce", "Batata doce com lemon pepper",
      "Grão de bico com alecrim", "Grão de bico com pimenta", "Morango", "Morango com orégano"]


class Err(Exception):
    pass


def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def hp(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 200000).hex()


def init():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    os.makedirs(BK, exist_ok=True)
    c = db()
    c.executescript("""
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, pw TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS sessions(tok TEXT PRIMARY KEY, name TEXT, exp REAL);
CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, type TEXT, cli TEXT,
  st TEXT, fr REAL, venc TEXT, paid_on TEXT, created_by TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS items(sale INTEGER REFERENCES sales(id), p TEXT, q INTEGER, pu REAL);""")
    for u in os.environ.get("USERS", "").split(";"):  # formato: nome:senha:admin;nome2:senha:op
        p = u.split(":")
        if len(p) == 3:
            c.execute("INSERT OR REPLACE INTO users VALUES(?,?,?)", (p[0].strip(), hp(p[1]), p[2].strip()))
    c.commit()
    c.close()


def backup(path):
    s = db()
    d = sqlite3.connect(path)
    s.backup(d)
    d.close()
    s.close()


def loop():
    while True:
        try:
            backup(f"{BK}/vendas-{datetime.date.today()}.db")
            for f in sorted(glob.glob(BK + "/vendas-*.db"))[:-14]:
                os.remove(f)
        except Exception as e:
            print("backup:", e)
        time.sleep(86400)


def ser(c, r):
    it = [dict(p=i["p"], q=i["q"], pu=i["pu"]) for i in c.execute("SELECT * FROM items WHERE sale=?", (r["id"],))]
    u = sum(i["q"] for i in it)
    sub = sum(i["q"] * i["pu"] for i in it)
    return dict(id=str(r["id"]), date=r["date"], type=r["type"], cli=r["cli"], items=it, u=u, sub=sub,
                fr=r["fr"], total=sub + r["fr"], st=r["st"], venc=r["venc"], paidOn=r["paid_on"])


class H(BaseHTTPRequestHandler):
    def out(s, code, data, ct="application/json", extra=()):
        b = data if isinstance(data, bytes) else json.dumps(data).encode()
        s.send_response(code)
        s.send_header("Content-Type", ct)
        s.send_header("Content-Length", str(len(b)))
        for k, v in extra:
            s.send_header(k, v)
        s.end_headers()
        s.wfile.write(b)

    def me(s):
        ck = s.headers.get("Cookie") or ""
        tok = next((x.split("=", 1)[1] for x in ck.split("; ") if x.startswith("tok=")), "")
        c = db()
        r = c.execute("SELECT u.name,u.role FROM sessions s JOIN users u ON u.name=s.name "
                      "WHERE s.tok=? AND s.exp>?", (tok, time.time())).fetchone()
        c.close()
        return dict(r) if r else None

    def body(s):
        return json.loads(s.rfile.read(int(s.headers.get("Content-Length") or 0)) or b"{}")

    def do_GET(s):
        p = s.path.split("?")[0]
        if p == "/":
            return s.out(200, open("index.html", "rb").read(), "text/html; charset=utf-8")
        u = s.me()
        if not u:
            return s.out(401, {"erro": "login"})
        if p == "/api/me":
            return s.out(200, u)
        if u["role"] != "admin":
            return s.out(403, {"erro": "sem permissão"})
        if p == "/api/sales":
            c = db()
            r = [ser(c, x) for x in c.execute("SELECT * FROM sales ORDER BY id")]
            c.close()
            return s.out(200, r)
        if p == "/api/backup":
            f = tempfile.mktemp()
            backup(f)
            d = open(f, "rb").read()
            os.remove(f)
            return s.out(200, d, "application/octet-stream",
                         [("Content-Disposition", f'attachment; filename="vendas-{datetime.date.today()}.db"')])
        s.out(404, {"erro": "não encontrado"})

    def do_POST(s):
        p = s.path
        try:
            b = s.body()
        except ValueError:
            return s.out(400, {"erro": "Dados inválidos."})
        if p == "/api/login":
            c = db()
            r = c.execute("SELECT * FROM users WHERE name=?", (str(b.get("u")),)).fetchone()
            if not r or hp(str(b.get("p")), r["pw"].split("$")[0]) != r["pw"]:
                c.close()
                time.sleep(1)
                return s.out(401, {"erro": "login"})
            tok = secrets.token_hex(24)
            c.execute("INSERT INTO sessions VALUES(?,?,?)", (tok, r["name"], time.time() + 30 * 86400))
            c.commit()
            c.close()
            sec = "; Secure" if s.headers.get("X-Forwarded-Proto") == "https" else ""
            return s.out(200, {"ok": 1}, extra=[("Set-Cookie",
                         f"tok={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{sec}")])
        u = s.me()
        if not u:
            return s.out(401, {"erro": "login"})
        if p == "/api/sales":
            return s.new_sale(u, b)
        m = re.match(r"/api/sales/(\d+)/(pay|cancel)$", p)
        if m and u["role"] == "admin":
            c = db()
            if m[2] == "pay":
                c.execute("UPDATE sales SET st='pago', paid_on=? WHERE id=? AND st='pendente'",
                          (str(datetime.date.today()), m[1]))
            else:
                c.execute("UPDATE sales SET st='cancelada' WHERE id=?", (m[1],))
            c.commit()
            c.close()
            return s.out(200, {"ok": 1})
        s.out(403, {"erro": "sem permissão"})

    def new_sale(s, u, b):
        try:
            t = b.get("type")
            dt = datetime.date.fromisoformat(b.get("date"))
            q = {}
            for i in b.get("items", []):
                n = int(i["q"])
                if n > 0:
                    if i["p"] not in FL:
                        raise Err("Sabor inválido.")
                    q[i["p"]] = q.get(i["p"], 0) + n
            n = sum(q.values())
            if t not in ("final", "b2b"):
                raise Err("Tipo inválido.")
            if not n:
                raise Err("Escolha ao menos um sabor.")
            if t == "b2b" and n < MIN:
                raise Err(f"Venda B2B exige no mínimo {MIN} unidades.")
            st = "pendente" if t == "b2b" and b.get("st") == "pendente" else "pago"
            fr = max(0.0, float(b.get("fr") or 0)) if t == "b2b" else 0.0
            venc = (b.get("venc") or str(dt + datetime.timedelta(days=PRAZO))) if st == "pendente" else None
            if venc:
                datetime.date.fromisoformat(venc)
        except Err as e:
            return s.out(400, {"erro": str(e)})
        except Exception:
            return s.out(400, {"erro": "Dados inválidos."})
        pu = PB if t == "b2b" else PF
        c = db()
        cur = c.execute("INSERT INTO sales(date,type,cli,st,fr,venc,created_by,at) VALUES(?,?,?,?,?,?,?,?)",
                        (str(dt), t, str(b.get("cli") or "")[:80], st, fr, venc, u["name"],
                         datetime.datetime.now().isoformat()))
        c.executemany("INSERT INTO items VALUES(?,?,?,?)", [(cur.lastrowid, p, v, pu) for p, v in q.items()])
        c.commit()
        c.close()
        s.out(200, {"ok": 1})


if __name__ == "__main__":
    init()
    threading.Thread(target=loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
