#!/usr/bin/env python3
# 自建 DDNS 服务：登录面板 + 自定义主机 + dyndns2 协议 + Cloudflare 后端
import os, json, ipaddress, secrets, hmac, threading, time, base64, subprocess, calendar, re
import urllib.request, urllib.error
import urllib.parse
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import (Flask, request, redirect, url_for, session,
                   render_template, Response, jsonify, send_file)
from i18n import TR
from dns_slots import (new_slot, find_slot, find_slot_by_key, migrate_hosts,
                       normalize_ip_for_slot, upsert_slot, delete_slot_record,
                       SlotConflict, SlotNotFound, ProviderError)
from certificates import (new_certificate, migrate_certificate_data,
                          rotate_download_token, revoke_download_token,
                          authenticate_certificate, certificate_paths,
                          acme_state_path, acme_issue_args, acme_install_args,
                          migrate_legacy_certificate_files, CertificateError)

CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "").strip()
DEFAULT_ZONE = os.environ.get("CF_ZONE_NAME", "").strip()
SITE_NAME    = os.environ.get("SITE_NAME", "Homing")
ADMIN_USER   = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS   = os.environ.get("ADMIN_PASS", "")
DATA_FILE    = os.environ.get("DATA_FILE", "/app/data/data.json")
CF_API = "https://api.cloudflare.com/client/v4"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=True)

LOGIN_WINDOW = 15 * 60
LOGIN_MAX_FAILURES = int(os.environ.get("LOGIN_MAX_FAILURES", "8"))
ALLOW_LEGACY_CERT_KEY = os.environ.get("ALLOW_LEGACY_CERT_KEY", "").lower() in ("1", "true", "yes")
LEGACY_CERT_QUERY_AUTH = os.environ.get("LEGACY_CERT_QUERY_AUTH", "").lower() in ("1", "true", "yes")
ALLOW_LEGACY_UPDATE_QUERY = os.environ.get("ALLOW_LEGACY_UPDATE_QUERY", "").lower() in ("1", "true", "yes")
_login_failures = {}
_login_lock = threading.Lock()
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

_lock = threading.RLock()
_zone_cache = {}

def _lang():
    try:
        return "zh" if request.cookies.get("lang") == "zh" else "en"
    except Exception:
        return "en"

def tr(key, lang=None, **kw):
    lang = lang or _lang()
    pair = TR.get(key, (key, key))
    s = pair[1] if lang == "zh" else pair[0]
    return s.format(**kw) if kw else s

@app.context_processor
def inject_globals():
    lang = _lang()
    js = {k: (v[1] if lang == "zh" else v[0]) for k, v in TR.items() if k.startswith("js_")}
    all_i18n = {
        "en": {k: v[0] for k, v in TR.items()},
        "zh": {k: v[1] for k, v in TR.items()},
    }
    return {"site_name": SITE_NAME, "lang": lang, "js_i18n": js, "all_i18n": all_i18n,
            "csrf_token": _csrf_token(),
            "t": lambda key, **kw: tr(key, lang, **kw)}

def _csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

def _same_origin():
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if not source:
        return False
    try:
        src = urllib.parse.urlsplit(source)
        return src.scheme == request.scheme and src.netloc == request.host
    except Exception:
        return False

@app.before_request
def csrf_protect():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    expected = session.get("csrf")
    if expected and supplied and hmac.compare_digest(supplied, expected):
        return None
    return jsonify(ok=False, error="csrf validation failed"), 403

@app.route("/lang/<code>", methods=["GET", "POST"])
def set_lang(code):
    if request.method == "POST":
        resp = jsonify(ok=code in ("en", "zh"), lang=code if code in ("en", "zh") else _lang())
    else:
        resp = redirect(url_for("index"))
    if request.method == "POST" and code in ("en", "zh"):
        resp.set_cookie("lang", code, max_age=31536000, samesite="Lax", secure=True)
    return resp

@app.after_request
def no_cache(resp):
    # 面板含内联JS，禁止缓存以免客户端拿到旧脚本
    if resp.mimetype == "text/html" or request.path.startswith(("/cert", "/client/", "/api/", "/nic/", "/v3/")):
        resp.headers["Cache-Control"] = "no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
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
    d, _ = migrate_hosts(d)
    migrate_certificate_data(d)
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

def valid_dns_name(value, allow_apex=True):
    if not value or len(value) > 253 or value != value.lower() or value.endswith("."):
        return False
    labels = value.split(".")
    return (allow_apex or len(labels) >= 2) and len(labels) >= 2 and all(_HOST_LABEL.fullmatch(x) for x in labels)

def valid_zone(zone, zmap):
    return valid_dns_name(zone) and zone in zmap

def valid_ttl(value, proxied=False):
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        return None
    if proxied:
        return 1
    return ttl if ttl == 1 or 60 <= ttl <= 86400 else None

def is_ip(s):
    try:
        ipaddress.ip_address(s); return True
    except Exception:
        return False

def cf_update_slot(d, host, slot, ip):
    zmap = known_zones(d)
    zone = zone_of(host, zmap)
    if zone not in zmap:
        raise ProviderError(f"no token for {zone}")
    token, zid = zmap[zone]
    reserved = {s.get("record_id") for h in d.get("hosts", {}).values() for s in h.get("slots", [])
                if s is not slot and s.get("record_id")}
    return upsert_slot(cf, zid, token, host, slot, ip, reserved_record_ids=reserved)

def cf_delete_slot(d, host, slot):
    zmap = known_zones(d)
    zone = zone_of(host, zmap)
    if zone not in zmap:
        raise ProviderError(f"no token for {zone}")
    token, zid = zmap[zone]
    return delete_slot_record(cf, zid, token, slot)

# ---------- 证书（acme.sh + DNS-01，单域名或通配符）----------
ACME = "/root/.acme.sh/acme.sh"
ACME_CONF = "/app/data/acme"
CERT_DIR = "/app/data/certs"

def run_acme(args, token, zone_id, config_home, timeout=200):
    env = dict(os.environ)
    env["CF_Token"] = token
    env["CF_Zone_ID"] = zone_id
    os.makedirs(config_home, exist_ok=True)
    cmd = ["bash", ACME, "--config-home", config_home] + args
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)

def cert_expiry(fullchain):
    try:
        r = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", fullchain],
                           capture_output=True, text=True, timeout=10)
        s = r.stdout.strip().split("=", 1)[1]           # notAfter=Jun  1 12:00:00 2026 GMT
        return int(calendar.timegm(time.strptime(s, "%b %d %H:%M:%S %Y %Z")))
    except Exception:
        return None

def cert_zone(cert, zmap):
    target = cert["target"]
    zone = target if cert["scope"] == "wildcard" else zone_of(target, zmap)
    return zone if zone in zmap else None

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

def run_acme_stream(jid, args, token, zone_id, config_home, timeout=220):
    env = dict(os.environ)
    env["CF_Token"] = token
    env["CF_Zone_ID"] = zone_id
    _job_log(jid, "$ acme.sh " + " ".join(args))
    os.makedirs(config_home, exist_ok=True)
    p = subprocess.Popen(["bash", ACME, "--config-home", config_home] + args,
                         env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1)
    start = time.time()
    for line in iter(p.stdout.readline, ""):
        _job_log(jid, line.rstrip("\n"))
        if time.time() - start > timeout:
            p.kill()
            _job_log(jid, "[timeout, killed]")
            break
    p.wait()
    return p.returncode

def issue_job(jid, cert_id):
    try:
        d = load(); zmap = known_zones(d); cert = d.get("certs", {}).get(cert_id)
        if not cert:
            _job_log(jid, "Certificate not found")
            _job_finish(jid, False); return
        zone = cert_zone(cert, zmap)
        if not zone:
            _job_log(jid, f"No Cloudflare token covers {cert['target']}")
            _job_finish(jid, False); return
        token, zid = zmap[zone]
        paths = certificate_paths(cert, CERT_DIR)
        state = acme_state_path(cert, ACME_CONF)
        os.makedirs(paths["directory"], exist_ok=True)
        _job_log(jid, f"Issuing/renewing {cert['scope']} certificate for {cert['target']} (Let's Encrypt / DNS-01)")
        _job_log(jid, "  Writing _acme-challenge TXT to Cloudflare and waiting for validation…")
        run_acme_stream(jid, acme_issue_args(cert), token, zid, state)
        _job_log(jid, "Installing certificate locally…")
        run_acme_stream(jid, acme_install_args(cert, CERT_DIR), token, zid, state)
        ok = os.path.exists(paths["fullchain"])
        if ok:
            exp = cert_expiry(paths["fullchain"])
            with _lock:
                d = load()
                if cert_id in d.get("certs", {}):
                    d["certs"][cert_id]["issued_at"] = int(time.time())
                    d["certs"][cert_id]["expires_at"] = exp
                    save(d)
            when = time.strftime("%Y-%m-%d", time.gmtime(exp)) if exp else "?"
            _job_log(jid, f"✔ Done! Valid until {when}. Clients auto-sync on next pull.")
        else:
            _job_log(jid, "✖ No cert file produced — check the log above (usually token perms or DNS).")
        _job_finish(jid, ok)
    except Exception as e:
        _job_log(jid, f"✖ Error: {e}")
        _job_finish(jid, False)

def renew_all():
    d = load()
    zmap = known_zones(d)
    for cert_id, cert in list(d.get("certs", {}).items()):
        zone = cert_zone(cert, zmap)
        if zone:
            token, zid = zmap[zone]
            state = acme_state_path(cert, ACME_CONF)
            run_acme(["--cron"], token, zid, state, timeout=200)
            paths = certificate_paths(cert, CERT_DIR)
            exp = cert_expiry(paths["fullchain"])
            with _lock:
                dd = load()
                if cert_id in dd.get("certs", {}):
                    dd["certs"][cert_id]["expires_at"] = exp
                    save(dd)

def _renew_loop():
    while True:
        time.sleep(43200)  # 每 12h 检查一次；acme.sh 只在 <60 天时真正续期
        try: renew_all()
        except Exception as e: app.logger.warning("certificate renewal check failed: %s", e)

def certs_view(d):
    now = int(time.time())
    out = []
    for cert_id, c in sorted(d.get("certs", {}).items()):
        try:
            migrate_legacy_certificate_files(c, CERT_DIR)
        except CertificateError:
            pass
        exp = c.get("expires_at")
        days = int((exp - now) / 86400) if exp else None
        paths = certificate_paths(c, CERT_DIR)
        out.append({
            "id": cert_id, "scope": c["scope"], "target": c["target"], "domains": c.get("domains", []),
            "days": days, "exp": exp, "exists": os.path.exists(paths["fullchain"]),
            "status": "ok" if (days is not None and days > 20) else ("warn" if days is not None else "none"),
        })
    return out

def host_for_key(d, key):
    try:
        return find_slot_by_key(d, key)[0]
    except SlotNotFound:
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

def _safe_next(target):
    if not target:
        return None
    p = urllib.parse.urlsplit(target)
    return target if not p.scheme and not p.netloc and target.startswith("/") and not target.startswith("//") else None

def _login_identity():
    return (client_ip() or "unknown")[:128]

def _login_limited(identity):
    now = time.time()
    with _login_lock:
        recent = [x for x in _login_failures.get(identity, []) if now - x < LOGIN_WINDOW]
        _login_failures[identity] = recent
        return len(recent) >= LOGIN_MAX_FAILURES

def _record_login_failure(identity, username):
    with _login_lock:
        _login_failures.setdefault(identity, []).append(time.time())
    app.logger.warning("login failed ip=%s user=%r", identity, username[:64])

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
        ident = _login_identity()
        if _login_limited(ident):
            app.logger.warning("login rate limited ip=%s", ident)
            return render_template("login.html", err=tr("bad_login")), 429
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if (hmac.compare_digest(u, ADMIN_USER) and ADMIN_PASS
                and hmac.compare_digest(p, ADMIN_PASS)):
            session.clear()
            session["u"] = ADMIN_USER
            session["csrf"] = secrets.token_urlsafe(32)
            with _login_lock:
                _login_failures.pop(ident, None)
            app.logger.info("login succeeded ip=%s", ident)
            return redirect(_safe_next(request.args.get("next")) or url_for("index"))
        _record_login_failure(ident, u)
        err = tr("bad_login")
    return render_template("login.html", err=err)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- 面板 ----------
def humanize(sec, lang="en"):
    if sec < 60: return tr("just_now", lang)
    if sec < 3600: return tr("min_ago", lang, n=sec // 60)
    if sec < 86400: return tr("hr_ago", lang, n=sec // 3600)
    return tr("day_ago", lang, n=sec // 86400)

def view_rows(d, lang="en"):
    now = int(time.time())
    rows = []
    for hn, h in sorted(d["hosts"].items()):
        for slot in h.get("slots", []):
            lu = slot.get("last_update")
            if not lu:
                status, ago = "pending", tr("never", lang)
            else:
                age = now - lu
                ago = humanize(age, lang)
                status = "good" if age <= 1800 else "warn"
            sub, _, rest = hn.partition(".")
            rows.append({
                "host": hn, "sub": sub, "zsuffix": "." + rest if rest else "",
                "slot_id": slot["id"], "type": slot["type"],
                "label": slot.get("label", ""), "key": slot["key"],
                "record_id": slot.get("record_id"),
                "proxied": slot.get("proxied", False), "ttl": slot.get("ttl", 120),
                "ip": slot.get("last_ip"), "ago": ago, "status": status,
            })
    return rows

@app.route("/")
@require_login
def index():
    lang = _lang()
    d = load()
    rows = view_rows(d, lang)
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
        "hosts": len(d.get("hosts", {})),
        "good": sum(1 for r in rows if r["status"] == "good"),
        "stale": sum(1 for r in rows if r["status"] == "warn"),
        "proxied": sum(1 for r in rows if r["proxied"]),
        "tokens": len(tokens_view),
        "zones": sorted(zmap.keys()),
    }
    ecode = request.args.get("err", "")
    err = None
    if ecode == "token-invalid": err = tr("err_token_invalid", lang)
    elif ecode == "token-empty": err = tr("err_token_empty", lang)
    return render_template("panel.html", rows=rows, stats=stats,
                           tokens=tokens_view, zones=sorted(zmap.keys()),
                           certs=certs_view(d), hostnames=sorted(d.get("hosts", {})), err=err,
                           endpoint=request.host)


# ---------- 证书路由 ----------
@app.route("/certificates", methods=["POST"])
@require_login
def cert_create():
    scope = request.form.get("scope", "")
    target = request.form.get("target", "").strip().lower()
    with _lock:
        d = load()
        try:
            cert = new_certificate(scope, target,
                managed_hosts=d.get("hosts", {}).keys(), managed_zones=known_zones(d).keys())
        except CertificateError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        d["certs"].setdefault(cert["id"], cert)
        save(d)
    return jsonify(ok=True, certificate=cert["id"])

@app.route("/certs/<cert_id>/issue", methods=["POST"])
@require_login
def cert_issue(cert_id):
    d = load()
    cert = d.get("certs", {}).get(cert_id)
    if not cert:
        return jsonify(ok=False, error="certificate not found"), 404
    jid = _new_job(f"Issue/renew {cert['target']}")
    threading.Thread(target=issue_job, args=(jid, cert_id), daemon=True).start()
    return jsonify(job=jid)

@app.route("/certs/job/<jid>")
@require_login
def cert_job(jid):
    frm = int(request.args.get("from", 0))
    with _jobs_lock:
        j = JOBS.get(jid)
        if not j:
            return jsonify(error="job not found"), 404
        return jsonify(title=j["title"], lines=j["lines"][frm:], next=len(j["lines"]),
                       done=j["done"], ok=j["ok"], status=j["status"])

@app.route("/certs/<cert_id>/delete", methods=["POST"])
@require_login
def cert_delete(cert_id):
    with _lock:
        d = load()
        d.get("certs", {}).pop(cert_id, None)
        save(d)
    return redirect(url_for("index"))

def _cert_auth(d, cert_hint=None):
    """Certificate tokens are independent from DDNS update credentials."""
    key = request.headers.get("X-Cert-Token", "") or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not key and LEGACY_CERT_QUERY_AUTH and request.args.get("key"):
        # Query-string secrets leak through proxy logs. Legacy mode is opt-in only.
        key = request.args.get("key", "")
    cert = authenticate_certificate(d.get("certs", {}), key)
    if cert and (not cert_hint or cert["id"] == cert_hint):
        return cert
    if ALLOW_LEGACY_CERT_KEY:
        host = host_for_key(d, key)
        if host:
            zone = zone_of(host, known_zones(d))
            candidate = next((c for c in d.get("certs", {}).values()
                              if c.get("scope") == "wildcard" and c.get("target") == zone), None)
            app.logger.warning("legacy DDNS key used for certificate download zone=%s", zone)
            return candidate if candidate and (not cert_hint or candidate["id"] == cert_hint) else None
    return None

def _serve_cert(part):
    cert_hint = request.headers.get("X-Cert-Id", "").strip() or None
    d = load()
    cert = _cert_auth(d, cert_hint)
    if not cert:
        return Response("invalid certificate token\n", status=403, mimetype="text/plain")
    migrate_legacy_certificate_files(cert, CERT_DIR)
    paths = certificate_paths(cert, CERT_DIR)
    path = paths["fullchain"] if part == "fullchain" else paths["key"]
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
    d = load()
    cert = _cert_auth(d, request.headers.get("X-Cert-Id", "").strip() or None)
    if not cert:
        return jsonify(ok=False, error="invalid certificate token"), 403
    migrate_legacy_certificate_files(cert, CERT_DIR)
    paths = certificate_paths(cert, CERT_DIR)
    if not os.path.exists(paths["fullchain"]):
        return jsonify(ok=False, error="no cert issued", certificate=cert["id"]), 404
    return jsonify(ok=True, certificate=cert["id"], scope=cert["scope"], target=cert["target"],
                   expires_at=cert.get("expires_at"), fullchain=open(paths["fullchain"]).read(),
                   key=open(paths["key"]).read())

@app.route("/certs/<cert_id>/token", methods=["POST"])
@require_login
def rotate_cert_token(cert_id):
    with _lock:
        d = load()
        cert = d.get("certs", {}).get(cert_id)
        if not cert:
            return jsonify(ok=False, error="certificate not found"), 404
        token = rotate_download_token(cert)
        save(d)
    return jsonify(ok=True, certificate=cert_id, token=token)

@app.route("/certs/<cert_id>/token", methods=["DELETE"])
@require_login
def revoke_cert_token(cert_id):
    with _lock:
        d = load()
        cert = d.get("certs", {}).get(cert_id)
        if cert is None:
            return jsonify(ok=False, error="certificate not found"), 404
        revoke_download_token(cert)
        save(d)
    return jsonify(ok=True, certificate=cert_id)

@app.route("/get-cert.sh")
def get_cert_script():
    return send_file("/app/get-cert.sh", mimetype="text/x-shellscript")

@app.route("/client/<name>")
def native_client_script(name):
    if name not in {"install.sh", "ddns-update.sh", "cert-sync.sh"}:
        return Response("not found\n", status=404, mimetype="text/plain")
    return send_file(os.path.join(BASE_DIR, "client", name), mimetype="text/x-shellscript")


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
        return jsonify(ok=False, error="not found"), 404
    vr = cf("GET", "/user/tokens/verify", t["token"])
    if vr.get("success"):
        status = (vr.get("result") or {}).get("status", "unknown")
        z = token_zones(t["token"]) or []
        return jsonify(ok=True, status=status, zones=[x["name"] for x in z])
    return jsonify(ok=False, error="invalid or revoked")


@app.route("/hosts/<path:host>/slots/<slot_id>/test")
@require_login
def test_host(host, slot_id):
    d = load()
    try:
        slot = find_slot(d, host, slot_id)
    except SlotNotFound:
        return jsonify(ok=False, error="record slot not found"), 404
    zmap = known_zones(d)
    zone = zone_of(host, zmap)
    if zone not in zmap:
        return jsonify(ok=False, error=f"no token covers {zone}")
    token, zid = zmap[zone]
    if slot.get("record_id"):
        r = cf("GET", f"/zones/{zid}/dns_records/{slot['record_id']}", token)
        recs = [r.get("result")] if r.get("result") else []
    else:
        query = urllib.parse.urlencode({"type": slot["type"], "name": host})
        r = cf("GET", f"/zones/{zid}/dns_records?{query}", token)
        recs = r.get("result") or []
    if not r.get("success"):
        return jsonify(ok=False, error="Cloudflare query failed")
    if len(recs) > 1:
        return jsonify(ok=False, error="multiple records found; update once with a bound record ID"), 409
    if recs:
        return jsonify(ok=True, live_ip=recs[0]["content"], type=slot["type"], proxied=recs[0].get("proxied", False))
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
    record_type = request.form.get("record_type", "A").upper()
    proxied = request.form.get("proxied") == "on"
    ttl = valid_ttl(request.form.get("ttl") or 120, proxied)
    d = load()
    zone = zone_of(host, known_zones(d)) if valid_dns_name(host, allow_apex=False) else None
    if ttl is not None and zone in known_zones(d) and host != zone:
        with _lock:
            d = load()
            try:
                slot = new_slot(record_type, label, proxied=proxied, ttl=ttl)
            except ValueError:
                return jsonify(ok=False, error="invalid record type or TTL"), 400
            d["hosts"].setdefault(host, {"created": int(time.time()), "slots": []})
            d["hosts"][host].setdefault("slots", []).append(slot)
            save(d)
    return redirect(url_for("index"))

@app.route("/hosts/<path:host>/slots", methods=["POST"])
@require_login
def add_slot(host):
    if not valid_dns_name(host):
        return jsonify(ok=False, error="invalid hostname"), 400
    record_type = request.form.get("record_type", "A").upper()
    proxied = request.form.get("proxied") == "on"
    ttl = valid_ttl(request.form.get("ttl") or 120, proxied)
    if ttl is None:
        return jsonify(ok=False, error="invalid TTL"), 400
    with _lock:
        d = load()
        if host not in d.get("hosts", {}):
            return jsonify(ok=False, error="host not found"), 404
        try:
            d["hosts"][host]["slots"].append(new_slot(record_type, request.form.get("label", ""), proxied=proxied, ttl=ttl))
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        save(d)
    return redirect(url_for("index"))

@app.route("/hosts/<path:host>/slots/<slot_id>/rotate", methods=["POST"])
@require_login
def rotate(host, slot_id):
    if not valid_dns_name(host):
        return jsonify(ok=False, error="invalid hostname"), 400
    with _lock:
        d = load()
        try:
            find_slot(d, host, slot_id)["key"] = secrets.token_urlsafe(24)
            save(d)
        except SlotNotFound:
            return jsonify(ok=False, error="record slot not found"), 404
    return redirect(url_for("index"))

@app.route("/hosts/<path:host>/slots/<slot_id>/edit", methods=["POST"])
@require_login
def edit(host, slot_id):
    if not valid_dns_name(host):
        return jsonify(ok=False, error="invalid hostname"), 400
    with _lock:
        d = load()
        try:
            slot = find_slot(d, host, slot_id)
            slot["label"] = request.form.get("label", "").strip()
            slot["proxied"] = request.form.get("proxied") == "on"
            ttl = valid_ttl(request.form.get("ttl") or 120, slot["proxied"])
            if ttl is not None:
                slot["ttl"] = ttl
            save(d)
        except SlotNotFound:
            return jsonify(ok=False, error="record slot not found"), 404
    return redirect(url_for("index"))

@app.route("/hosts/<path:host>/slots/<slot_id>/delete", methods=["POST"])
@require_login
def delete(host, slot_id):
    if not valid_dns_name(host):
        return jsonify(ok=False, error="invalid hostname"), 400
    also_dns = request.form.get("dns") == "on"
    with _lock:
        d = load()
        try:
            slot = find_slot(d, host, slot_id)
            if also_dns and slot.get("record_id"):
                cf_delete_slot(d, host, slot)
            slots = d["hosts"][host]["slots"]
            d["hosts"][host]["slots"] = [s for s in slots if s.get("id") != slot_id]
            if not d["hosts"][host]["slots"]:
                del d["hosts"][host]
            save(d)
        except SlotNotFound:
            return jsonify(ok=False, error="record slot not found"), 404
        except ProviderError:
            return jsonify(ok=False, error="Cloudflare delete failed"), 502
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
    if not valid_dns_name(host) or host not in d.get("hosts", {}):
        return Response("nohost", mimetype="text/plain")
    try:
        _, slot = find_slot_by_key(d, key, host)
    except SlotNotFound:
        return Response("badauth", mimetype="text/plain")
    myip = request.args.get("myip", "").strip() or client_ip()
    try:
        myip = normalize_ip_for_slot(slot, myip)
    except ValueError:
        return Response("dnserr", mimetype="text/plain")
    try:
        with _lock:
            result = cf_update_slot(d, host, slot, myip)
            save(d)
        return Response(f"{result.status} {myip}", mimetype="text/plain")
    except SlotConflict:
        return Response("conflict", status=409, mimetype="text/plain")
    except ProviderError:
        return Response("911", status=502, mimetype="text/plain")

# ---------- 友好 JSON API（给我们自己的脚本，如 boil 换IP后带 ?ip= 即时更新）----------
@app.route("/api/update")
def api_update():
    auth = request.headers.get("Authorization", "")
    key = request.headers.get("X-Api-Key", "") or (auth[7:].strip() if auth.startswith("Bearer ") else "")
    if not key and ALLOW_LEGACY_UPDATE_QUERY:
        key = request.args.get("key", "")
    d = load()
    try:
        host, slot = find_slot_by_key(d, key)
    except SlotNotFound:
        return jsonify(ok=False, error="invalid key"), 403
    myip = request.args.get("ip", "").strip() or client_ip()
    try:
        myip = normalize_ip_for_slot(slot, myip)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    try:
        with _lock:
            result = cf_update_slot(d, host, slot, myip)
            save(d)
        return jsonify(ok=True, host=host, slot=slot["id"], type=slot["type"], ip=myip, result=result.status)
    except SlotConflict as exc:
        return jsonify(ok=False, host=host, slot=slot["id"], error=str(exc)), 409
    except ProviderError:
        app.logger.warning("Cloudflare DNS update failed for host=%s slot=%s", host, slot.get("id"))
        return jsonify(ok=False, host=host, error="provider-error"), 502

@app.route("/ip")
def ip():
    return jsonify(your_ip=client_ip())

@app.route("/health")
def health():
    return jsonify(ok=True)

# 启动后台续期线程（waitress 导入即运行一次）
threading.Thread(target=_renew_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8787")))
