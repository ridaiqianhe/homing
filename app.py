#!/usr/bin/env python3
# 自建 DDNS 服务：登录面板 + 自定义主机 + dyndns2 协议 + Cloudflare 后端
import os, json, ipaddress, secrets, hmac, threading, time, base64, subprocess, calendar
import urllib.request, urllib.error
from functools import wraps
from flask import (Flask, request, redirect, url_for, session,
                   render_template, Response, jsonify, send_file)

CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "").strip()
DEFAULT_ZONE = os.environ.get("CF_ZONE_NAME", "").strip()
SITE_NAME    = os.environ.get("SITE_NAME", "Homing")
ADMIN_USER   = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS   = os.environ.get("ADMIN_PASS", "")
DATA_FILE    = os.environ.get("DATA_FILE", "/app/data/data.json")
CF_API = "https://api.cloudflare.com/client/v4"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

_lock = threading.Lock()
_zone_cache = {}

@app.context_processor
def inject_globals():
    return {"site_name": SITE_NAME}

@app.after_request
def no_cache(resp):
    # 面板含内联JS，禁止缓存以免客户端拿到旧脚本
    if resp.mimetype == "text/html":
        resp.headers["Cache-Control"] = "no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
    return resp

# ---------- 存储 ----------
def load():
    try:
        with open(DATA_FILE) as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.setdefault("hosts", {})
    d.setdefault("tokens", [])
    d.setdefault("certs", {})
    return d

def save(d):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DATA_FILE)
    try: os.chmod(DATA_FILE, 0o600)
    except Exception: pass

# ---------- Cloudflare ----------
def cf(method, path, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CF_API + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try: return json.loads(e.read().decode())
        except Exception: return {"success": False, "errors": [{"message": f"HTTP {e.code}"}]}
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def token_zones(token):
    """返回该 token 可管理的 zone 列表 [{'name','id'}...]，token 无效返回 None"""
    d = cf("GET", "/zones?per_page=50", token)
    if not d.get("success"):
        return None
    return [{"name": z["name"], "id": z["id"]} for z in (d.get("result") or [])]

def known_zones(d):
    """所有已配置 token 覆盖的 zone -> token 映射 {zone_name: (token, zone_id)}"""
    m = {}
    for t in d.get("tokens", []):
        for z in t.get("zones", []):
            m.setdefault(z["name"], (t["token"], z["id"]))
    return m

def zone_of(host, zmap):
    """在已知 zone 里做最长后缀匹配（支持 co.uk 等），否则退回末两段"""
    best = None
    for zname in zmap:
        if host == zname or host.endswith("." + zname):
            if best is None or len(zname) > len(best):
                best = zname
    if best:
        return best
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def is_ip(s):
    try:
        ipaddress.IPv4Address(s); return True
    except Exception:
        return False

def cf_upsert(host, ip, proxied, ttl):
    d = load()
    zmap = known_zones(d)
    zone = zone_of(host, zmap)
    if zone not in zmap:
        return False, f"no-token-for-{zone}", None
    token, zid = zmap[zone]
    r = (cf("GET", f"/zones/{zid}/dns_records?type=A&name={host}", token).get("result")) or []
    payload = {"type": "A", "name": host, "content": ip, "ttl": int(ttl), "proxied": bool(proxied)}
    if r:
        if r[0]["content"] == ip and r[0].get("proxied") == bool(proxied):
            return True, "nochg", ip
        res = cf("PUT", f"/zones/{zid}/dns_records/{r[0]['id']}", token, payload)
    else:
        res = cf("POST", f"/zones/{zid}/dns_records", token, payload)
    if res.get("success"):
        return True, "good", ip
    return False, json.dumps(res.get("errors"), ensure_ascii=False), None

def cf_delete(host):
    d = load()
    zmap = known_zones(d)
    zone = zone_of(host, zmap)
    if zone not in zmap:
        return
    token, zid = zmap[zone]
    recs = (cf("GET", f"/zones/{zid}/dns_records?type=A&name={host}", token).get("result")) or []
    for rec in recs:
        cf("DELETE", f"/zones/{zid}/dns_records/{rec['id']}", token)

# ---------- 证书（acme.sh + DNS-01 通配符）----------
ACME = "/root/.acme.sh/acme.sh"
ACME_CONF = "/app/data/acme"
CERT_DIR = "/app/data/certs"

def run_acme(args, token, zone_id, timeout=200):
    env = dict(os.environ)
    env["CF_Token"] = token
    env["CF_Zone_ID"] = zone_id
    cmd = ["bash", ACME, "--config-home", ACME_CONF] + args
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)

def cert_paths(zone):
    d = os.path.join(CERT_DIR, zone)
    return os.path.join(d, "fullchain.pem"), os.path.join(d, "key.pem")

def cert_expiry(fullchain):
    try:
        r = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", fullchain],
                           capture_output=True, text=True, timeout=10)
        s = r.stdout.strip().split("=", 1)[1]           # notAfter=Jun  1 12:00:00 2026 GMT
        return int(calendar.timegm(time.strptime(s, "%b %d %H:%M:%S %Y %Z")))
    except Exception:
        return None

def issue_wildcard(zone):
    d = load()
    zmap = known_zones(d)
    if zone not in zmap:
        return False, f"没有覆盖 {zone} 的 Token"
    token, zid = zmap[zone]
    os.makedirs(os.path.join(CERT_DIR, zone), exist_ok=True)
    os.makedirs(ACME_CONF, exist_ok=True)
    r = run_acme(["--issue", "--dns", "dns_cf", "-d", f"*.{zone}", "-d", zone,
                  "--server", "letsencrypt", "--keylength", "2048"], token, zid)
    out = r.stdout + r.stderr
    if ("Cert success" not in out and "Cert manually" not in out
            and "Domains not changed" not in out and "Skipping" not in out
            and "already" not in out.lower()):
        return False, out.strip()[-500:]
    fc, key = cert_paths(zone)
    run_acme(["--install-cert", "-d", f"*.{zone}",
              "--fullchain-file", fc, "--key-file", key, "--reloadcmd", "true"], token, zid)
    with _lock:
        d = load()
        d.setdefault("certs", {})[zone] = {
            "domains": [f"*.{zone}", zone], "issued_at": int(time.time()),
            "expires_at": cert_expiry(fc),
        }
        save(d)
    return True, "ok"

# ---- 流式任务（后台跑 acme.sh，前端轮询增量输出）----
JOBS = {}
_jobs_lock = threading.Lock()

def _new_job(title):
    jid = secrets.token_hex(6)
    with _jobs_lock:
        # 只保留最近 20 个任务
        for old in list(JOBS)[:-19]:
            JOBS.pop(old, None)
        JOBS[jid] = {"title": title, "lines": [], "done": False, "ok": False, "status": "running"}
    return jid

def _job_log(jid, line):
    with _jobs_lock:
        if jid in JOBS:
            JOBS[jid]["lines"].append(line.rstrip("\n"))

def _job_finish(jid, ok):
    with _jobs_lock:
        if jid in JOBS:
            JOBS[jid]["done"] = True
            JOBS[jid]["ok"] = ok
            JOBS[jid]["status"] = "done" if ok else "error"

def run_acme_stream(jid, args, token, zone_id, timeout=220):
    env = dict(os.environ)
    env["CF_Token"] = token
    env["CF_Zone_ID"] = zone_id
    _job_log(jid, "$ acme.sh " + " ".join(args))
    p = subprocess.Popen(["bash", ACME, "--config-home", ACME_CONF] + args,
                         env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1)
    start = time.time()
    for line in iter(p.stdout.readline, ""):
        _job_log(jid, line.rstrip("\n"))
        if time.time() - start > timeout:
            p.kill()
            _job_log(jid, "[超时，已终止]")
            break
    p.wait()
    return p.returncode

def issue_job(jid, zone):
    try:
        d = load(); zmap = known_zones(d)
        if zone not in zmap:
            _job_log(jid, f"✖ 没有覆盖 {zone} 的 Cloudflare Token")
            _job_finish(jid, False); return
        token, zid = zmap[zone]
        os.makedirs(os.path.join(CERT_DIR, zone), exist_ok=True)
        os.makedirs(ACME_CONF, exist_ok=True)
        _job_log(jid, f"▶ 为 *.{zone} 申请/续期通配符证书（Let's Encrypt · DNS-01）")
        _job_log(jid, "  正在向 Cloudflare 写入 _acme-challenge TXT 记录并等待验证…")
        run_acme_stream(jid, ["--issue", "--dns", "dns_cf", "-d", f"*.{zone}", "-d", zone,
                              "--server", "letsencrypt", "--keylength", "2048"], token, zid)
        fc, key = cert_paths(zone)
        _job_log(jid, "▶ 安装证书到服务器本地…")
        run_acme_stream(jid, ["--install-cert", "-d", f"*.{zone}",
                              "--fullchain-file", fc, "--key-file", key, "--reloadcmd", "true"], token, zid)
        ok = os.path.exists(fc)
        if ok:
            exp = cert_expiry(fc)
            with _lock:
                d = load()
                d.setdefault("certs", {})[zone] = {
                    "domains": [f"*.{zone}", zone], "issued_at": int(time.time()), "expires_at": exp}
                save(d)
            when = time.strftime("%Y-%m-%d", time.gmtime(exp)) if exp else "?"
            _job_log(jid, f"✔ 完成！证书有效期至 {when}，客户端下次拉取会自动同步")
        else:
            _job_log(jid, "✖ 未生成证书文件，请检查上方日志（多为 Token 权限或 DNS 未生效）")
        _job_finish(jid, ok)
    except Exception as e:
        _job_log(jid, f"✖ 异常：{e}")
        _job_finish(jid, False)

def renew_all():
    d = load()
    zmap = known_zones(d)
    for zone in list(d.get("certs", {})):
        if zone in zmap:
            token, zid = zmap[zone]
            run_acme(["--cron"], token, zid, timeout=200)
            fc, _ = cert_paths(zone)
            exp = cert_expiry(fc)
            with _lock:
                dd = load()
                if zone in dd.get("certs", {}):
                    dd["certs"][zone]["expires_at"] = exp
                    save(dd)

def _renew_loop():
    while True:
        time.sleep(43200)  # 每 12h 检查一次；acme.sh 只在 <60 天时真正续期
        try: renew_all()
        except Exception as e: log("续期检查异常:", e)

def certs_view(d):
    now = int(time.time())
    out = []
    for zone, c in sorted(d.get("certs", {}).items()):
        exp = c.get("expires_at")
        days = int((exp - now) / 86400) if exp else None
        fc, _ = cert_paths(zone)
        out.append({
            "zone": zone, "domains": c.get("domains", []),
            "days": days, "exp": exp, "exists": os.path.exists(fc),
            "status": "ok" if (days is not None and days > 20) else ("warn" if days is not None else "none"),
        })
    return out

def host_for_key(d, key):
    for hn, h in d.get("hosts", {}).items():
        if key and hmac.compare_digest(key, h["key"]):
            return hn
    return None

def client_ip():
    # 来访真实客户端IP（可能 v4 或 v6）。黄云下 CF-Connecting-IP 最权威；
    # 绝不用 X-Real-IP（那是 Cloudflare 边缘IP，会污染记录）。
    cf = request.headers.get("CF-Connecting-IP")
    if cf and cf.strip():
        return cf.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff and xff.split(",")[0].strip():
        return xff.split(",")[0].strip()
    return request.remote_addr

# ---------- 登录 ----------
def logged_in():
    return session.get("u") == ADMIN_USER

def require_login(f):
    @wraps(f)
    def w(*a, **k):
        if not logged_in():
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w

@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if (hmac.compare_digest(u, ADMIN_USER) and ADMIN_PASS
                and hmac.compare_digest(p, ADMIN_PASS)):
            session["u"] = ADMIN_USER
            return redirect(request.args.get("next") or url_for("index"))
        err = "账号或密码错误"
    return render_template("login.html", err=err)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- 面板 ----------
def humanize(sec):
    if sec < 60: return "刚刚"
    if sec < 3600: return f"{sec // 60} 分钟前"
    if sec < 86400: return f"{sec // 3600} 小时前"
    return f"{sec // 86400} 天前"

def view_rows(d):
    now = int(time.time())
    rows = []
    for hn, h in sorted(d["hosts"].items()):
        lu = h.get("last_update")
        if not lu:
            status, ago = "pending", "从未更新"
        else:
            age = now - lu
            ago = humanize(age)
            status = "good" if age <= 1800 else "warn"
        sub, _, rest = hn.partition(".")
        rows.append({
            "host": hn, "sub": sub, "zsuffix": "." + rest if rest else "",
            "label": h.get("label", ""), "key": h["key"],
            "proxied": h.get("proxied", False), "ttl": h.get("ttl", 120),
            "ip": h.get("last_ip"), "ago": ago, "status": status,
        })
    return rows

@app.route("/")
@require_login
def index():
    d = load()
    rows = view_rows(d)
    zmap = known_zones(d)
    tokens_view = []
    for t in d.get("tokens", []):
        tv = t["token"]
        tokens_view.append({
            "id": t["id"], "label": t.get("label", ""),
            "mask": (tv[:4] + "…" + tv[-4:]) if len(tv) > 8 else "…",
            "zones": [z["name"] for z in t.get("zones", [])],
        })
    stats = {
        "total": len(rows),
        "good": sum(1 for r in rows if r["status"] == "good"),
        "stale": sum(1 for r in rows if r["status"] == "warn"),
        "proxied": sum(1 for r in rows if r["proxied"]),
        "tokens": len(tokens_view),
        "zones": sorted(zmap.keys()),
    }
    err_map = {"token-invalid": "Token 无效或缺少 Zone.DNS 权限，未添加",
               "token-empty": "Token 不能为空"}
    return render_template("panel.html", rows=rows, stats=stats,
                           tokens=tokens_view, zones=sorted(zmap.keys()),
                           certs=certs_view(d),
                           err=err_map.get(request.args.get("err", "")),
                           endpoint=request.host)


# ---------- 证书路由 ----------
@app.route("/certs/<zone>/issue", methods=["POST"])
@require_login
def cert_issue(zone):
    jid = _new_job(f"申请/续期 *.{zone}")
    threading.Thread(target=issue_job, args=(jid, zone), daemon=True).start()
    return jsonify(job=jid)

@app.route("/certs/job/<jid>")
@require_login
def cert_job(jid):
    frm = int(request.args.get("from", 0))
    with _jobs_lock:
        j = JOBS.get(jid)
        if not j:
            return jsonify(error="任务不存在"), 404
        return jsonify(title=j["title"], lines=j["lines"][frm:], next=len(j["lines"]),
                       done=j["done"], ok=j["ok"], status=j["status"])

@app.route("/certs/<zone>/delete", methods=["POST"])
@require_login
def cert_delete(zone):
    with _lock:
        d = load()
        d.get("certs", {}).pop(zone, None)
        save(d)
    return redirect(url_for("index"))

def _serve_cert(part):
    """凭 host key 下载对应 zone 的通配符证书"""
    key = request.args.get("key", "") or request.headers.get("X-Api-Key", "")
    d = load()
    host = host_for_key(d, key)
    if not host:
        return Response("invalid key\n", status=403, mimetype="text/plain")
    zone = zone_of(host, known_zones(d))
    fc, k = cert_paths(zone)
    path = fc if part == "fullchain" else k
    if not os.path.exists(path):
        return Response("no cert issued\n", status=404, mimetype="text/plain")
    return send_file(path, mimetype="application/x-pem-file")

@app.route("/cert/fullchain")
def cert_fullchain():
    return _serve_cert("fullchain")

@app.route("/cert/key")
def cert_key():
    return _serve_cert("key")

@app.route("/cert")
def cert_bundle():
    key = request.args.get("key", "")
    d = load()
    host = host_for_key(d, key)
    if not host:
        return jsonify(ok=False, error="invalid key"), 403
    zone = zone_of(host, known_zones(d))
    fc, k = cert_paths(zone)
    if not os.path.exists(fc):
        return jsonify(ok=False, error="no cert issued", zone=zone), 404
    c = load().get("certs", {}).get(zone, {})
    return jsonify(ok=True, zone=zone, expires_at=c.get("expires_at"),
                   fullchain=open(fc).read(), key=open(k).read())

@app.route("/get-cert.sh")
def get_cert_script():
    return send_file("/app/get-cert.sh", mimetype="text/x-shellscript")


@app.route("/tokens", methods=["POST"])
@require_login
def add_token():
    label = request.form.get("label", "").strip()
    token = request.form.get("token", "").strip()
    if not token:
        return redirect(url_for("index", err="token-empty"))
    zones = token_zones(token)
    if zones is None:
        return redirect(url_for("index", err="token-invalid"))
    with _lock:
        d = load()
        d["tokens"].append({
            "id": secrets.token_hex(4), "label": label or (zones[0]["name"] if zones else "token"),
            "token": token, "zones": zones, "added": int(time.time()),
        })
        save(d)
    return redirect(url_for("index"))


@app.route("/tokens/<tid>/delete", methods=["POST"])
@require_login
def delete_token(tid):
    with _lock:
        d = load()
        d["tokens"] = [t for t in d["tokens"] if t["id"] != tid]
        save(d)
    return redirect(url_for("index"))


@app.route("/tokens/<tid>/verify")
@require_login
def verify_token_api(tid):
    d = load()
    t = next((x for x in d["tokens"] if x["id"] == tid), None)
    if not t:
        return jsonify(ok=False, error="不存在"), 404
    vr = cf("GET", "/user/tokens/verify", t["token"])
    if vr.get("success"):
        status = (vr.get("result") or {}).get("status", "unknown")
        z = token_zones(t["token"]) or []
        return jsonify(ok=True, status=status, zones=[x["name"] for x in z])
    msg = "无效或已撤销"
    errs = vr.get("errors") or []
    if errs:
        msg = errs[0].get("message", msg)
    return jsonify(ok=False, error=msg)


@app.route("/hosts/<path:host>/test")
@require_login
def test_host(host):
    """只读检查：该主机在 Cloudflare 上当前解析到什么（验证 token 能否触达）"""
    d = load()
    if host not in d["hosts"]:
        return jsonify(ok=False, error="主机不存在"), 404
    zmap = known_zones(d)
    zone = zone_of(host, zmap)
    if zone not in zmap:
        return jsonify(ok=False, error=f"没有覆盖 {zone} 的 Token")
    token, zid = zmap[zone]
    r = cf("GET", f"/zones/{zid}/dns_records?type=A&name={host}", token)
    if not r.get("success"):
        return jsonify(ok=False, error="Cloudflare 查询失败")
    recs = r.get("result") or []
    if recs:
        return jsonify(ok=True, live_ip=recs[0]["content"], proxied=recs[0].get("proxied", False))
    return jsonify(ok=True, live_ip=None)


@app.route("/tokens/<tid>/refresh", methods=["POST"])
@require_login
def refresh_token(tid):
    with _lock:
        d = load()
        for t in d["tokens"]:
            if t["id"] == tid:
                z = token_zones(t["token"])
                if z is not None:
                    t["zones"] = z
                break
        save(d)
    return redirect(url_for("index"))

@app.route("/hosts", methods=["POST"])
@require_login
def add_host():
    host = request.form.get("hostname", "").strip().lower().rstrip(".")
    label = request.form.get("label", "").strip()
    proxied = request.form.get("proxied") == "on"
    try: ttl = int(request.form.get("ttl") or 120)
    except Exception: ttl = 120
    if host and "." in host:
        with _lock:
            d = load()
            if host not in d["hosts"]:
                d["hosts"][host] = {
                    "label": label, "key": secrets.token_urlsafe(24),
                    "proxied": proxied, "ttl": ttl,
                    "last_ip": None, "last_update": None, "created": int(time.time()),
                }
                save(d)
    return redirect(url_for("index"))

@app.route("/hosts/<path:host>/rotate", methods=["POST"])
@require_login
def rotate(host):
    with _lock:
        d = load()
        if host in d["hosts"]:
            d["hosts"][host]["key"] = secrets.token_urlsafe(24)
            save(d)
    return redirect(url_for("index"))

@app.route("/hosts/<path:host>/edit", methods=["POST"])
@require_login
def edit(host):
    with _lock:
        d = load()
        if host in d["hosts"]:
            d["hosts"][host]["label"] = request.form.get("label", "").strip()
            d["hosts"][host]["proxied"] = request.form.get("proxied") == "on"
            try: d["hosts"][host]["ttl"] = int(request.form.get("ttl") or 120)
            except Exception: pass
            save(d)
    return redirect(url_for("index"))

@app.route("/hosts/<path:host>/delete", methods=["POST"])
@require_login
def delete(host):
    also_dns = request.form.get("dns") == "on"
    with _lock:
        d = load()
        if host in d["hosts"]:
            del d["hosts"][host]
            save(d)
    if also_dns:
        cf_delete(host)
    return redirect(url_for("index"))

# ---------- dyndns2 协议 ----------
def parse_basic():
    a = request.headers.get("Authorization", "")
    if a.startswith("Basic "):
        try:
            u, p = base64.b64decode(a[6:]).decode().split(":", 1)
            return u, p
        except Exception:
            return None, None
    return None, None

@app.route("/nic/update")
@app.route("/v3/update")
def nic_update():
    u, p = parse_basic()
    host = (request.args.get("hostname") or u or "").strip().lower()
    key = p or request.args.get("key", "")
    d = load()
    h = d["hosts"].get(host)
    if not h:
        return Response("nohost", mimetype="text/plain")
    if not key or not hmac.compare_digest(key, h["key"]):
        return Response("badauth", mimetype="text/plain")
    myip = request.args.get("myip", "").strip() or client_ip()
    if not is_ip(myip):
        return Response("dnserr", mimetype="text/plain")
    ok, res, ip = cf_upsert(host, myip, h["proxied"], h["ttl"])
    if ok:
        with _lock:
            d = load()
            if host in d["hosts"]:
                d["hosts"][host]["last_ip"] = myip
                d["hosts"][host]["last_update"] = int(time.time())
                save(d)
        return Response(f"{res} {myip}", mimetype="text/plain")
    return Response("911", mimetype="text/plain")

# ---------- 友好 JSON API（给我们自己的脚本，如 boil 换IP后带 ?ip= 即时更新）----------
@app.route("/api/update")
def api_update():
    key = request.args.get("key", "")
    d = load()
    host, hobj = None, None
    for hn, h in d["hosts"].items():
        if key and hmac.compare_digest(key, h["key"]):
            host, hobj = hn, h
            break
    if not host:
        return jsonify(ok=False, error="invalid key"), 403
    myip = request.args.get("ip", "").strip() or client_ip()
    if not is_ip(myip):
        return jsonify(ok=False, error="bad ip"), 400
    ok, res, ip = cf_upsert(host, myip, hobj["proxied"], hobj["ttl"])
    if ok:
        with _lock:
            d = load()
            d["hosts"][host]["last_ip"] = myip
            d["hosts"][host]["last_update"] = int(time.time())
            save(d)
        return jsonify(ok=True, host=host, ip=myip, result=res)
    return jsonify(ok=False, host=host, error=res), 502

@app.route("/ip")
def ip():
    return jsonify(
        your_ip=client_ip(),
        cf_connecting_ip=request.headers.get("CF-Connecting-IP"),
        x_real_ip=request.headers.get("X-Real-IP"),
        x_forwarded_for=request.headers.get("X-Forwarded-For"),
        remote_addr=request.remote_addr,
    )

@app.route("/health")
def health():
    return jsonify(ok=True)

# 启动后台续期线程（waitress 导入即运行一次）
threading.Thread(target=_renew_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8787")))
