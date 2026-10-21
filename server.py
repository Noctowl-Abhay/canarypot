#!/usr/bin/env python3
"""CanaryPot Web -- a from-scratch HTTP honeypot that deploys for FREE
with NO credit card on Render's free tier (works anywhere Python 3 runs).

Pure standard library. Zero dependencies.

Deploy alongside an empty requirements.txt with start command:
    python server.py

Decoy surface (everything an attacker loves to find):
  /                company portal login      (captures posted credentials)
  /wp-login.php    fake WordPress login      (POST "succeeds" -> /wp-admin/)
  /wp-admin/       fake WordPress dashboard
  /.env            fake leaked env file      (the #1 thing scanners hunt for)
  /.git/HEAD       fake exposed git repo
  /robots.txt      "sensitive" paths listed as bait
  anything else    plausible nginx 404       (directory brute-force decoy)

Every request is logged as JSON to stdout (Render dashboard -> Logs).
Live stats page at the admin path (default /canary-report).

Optional instant push notification for every attacker hit via ntfy.sh
(free, no account): set NTFY_TOPIC=<your-secret-topic>, then subscribe
to https://ntfy.sh/<topic> in the ntfy app or any browser.
"""

import html as _html
import json
import os
import threading
import urllib.parse
import urllib.request
from collections import Counter, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "10000"))
ADMIN_PATH = "/" + os.environ.get("ADMIN_PATH", "canary-report").strip("/")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()

# --------------------------------------------------------------------------
# Fake content (all credentials and keys below are FAKE bait, on purpose)
# --------------------------------------------------------------------------

FAKE_ENV = (
    "APP_NAME=CanaryPortal\n"
    "APP_ENV=production\n"
    "APP_KEY=base64:FAKEKEYNOTAREALSECRET0000000000000000=\n"
    "DB_HOST=10.0.1.15\n"
    "DB_DATABASE=canary_portal\n"
    "DB_USERNAME=portal_admin\n"
    "DB_PASSWORD=S3cr3t-FAKE-Not-Real\n"
    "SMTP_HOST=smtp.internal.local\n"
    "AWS_ACCESS_KEY_ID=AKIAFAKE00000000NOTREAL\n"
)

FAKE_GIT_HEAD = b"ref: refs/heads/main\n"

FAKE_GIT_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "[remote \"origin\"]\n"
    "\turl = https://internal-git.canarycorp.local/portal.git\n"
)

ROBOTS = (
    "User-agent: *\n"
    "Disallow: /wp-admin/\n"
    "Disallow: /admin\n"
    "Disallow: /.env\n"
    "Disallow: /.git\n"
)

PORTAL_PAGE = (
    b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
    b"<title>CanaryPortal</title>"
    b"<style>body{font-family:Arial,sans-serif;background:#f5f6f8}"
    b".box{max-width:360px;margin:90px auto;background:#fff;"
    b"padding:28px;border:1px solid #ddd;border-radius:8px}"
    b"input{width:100%;margin:8px 0;padding:10px;box-sizing:border-box}"
    b"button{width:100%;padding:10px;background:#2563eb;color:#fff;"
    b"border:0;border-radius:6px}</style></head><body>"
    b"<div class='box'><h2 style='margin-top:0'>CanaryPortal</h2>"
    b"<p style='color:#666'>Employee &amp; Partner Portal</p>"
    b"<form method='POST' action='/api/login'>"
    b"<input name='email' type='email' placeholder='Email' required>"
    b"<input name='password' type='password' placeholder='Password' required>"
    b"<button type='submit'>Sign in</button></form>"
    b"<p style='color:#999;font-size:12px'>v2.4.1 &copy; CanaryCorp</p>"
    b"</div></body></html>"
)

WP_LOGIN_PAGE = (
    b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
    b"<title>Log In &lsaquo; CanaryCorp</title>"
    b"<style>body{font-family:-apple-system,sans-serif;background:#f0f0f1;"
    b"font-size:14px}.wrap{max-width:320px;margin:80px auto;}"
    b"input{width:100%;margin:6px 0;padding:5px 8px;font-size:14px}"
    b"button{background:#2271b1;color:#fff;border:0;border-radius:3px;"
    b"padding:5px 12px}</style></head><body>"
    b"<div class='wrap'><h1><a href='/' style='text-decoration:none'"
    b">CanaryCorp</a></h1>"
    b"<form method='POST' action='/wp-login.php'>"
    b"<p><label>Username<br><input type='text' name='log'></label></p>"
    b"<p><label>Password<br><input type='password' name='pwd'></label></p>"
    b"<p><button type='submit'>Log In</button></p></form>"
    b"<p><a href='/wp-login.php'>Lost your password?</a></p>"
    b"</div></body></html>"
)

WP_ADMIN_PAGE = (
    b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
    b"<title>Dashboard &lsaquo; CanaryCorp</title>"
    b"<style>body{font-family:-apple-system,sans-serif;"
    b"font-size:13px;color:#32373c;background:#f0f0f1}"
    b"#menu{background:#23282d;color:#fff;padding:12px 16px}"
    b".cards{max-width:800px;margin:20px auto}"
    b".card{background:#fff;border:1px solid #ddd;padding:16px;"
    b"margin-bottom:14px}</style></head><body>"
    b"<div id='menu'>&#9632; CanaryCorp &nbsp; Dashboard | Posts | "
    b"Media | Pages | Users | Settings</div>"
    b"<div class='cards'>"
    b"<div class='card'><h3>Welcome to your dashboard!</h3>"
    b"<p>You are logged in as <strong>admin</strong>.</p></div>"
    b"<div class='card'><h3>Activity</h3><p>Last login: yesterday</p>"
    b"<p>Posts: 12 | Comments: 3</p></div>"
    b"</div></body></html>"
)

NGINX_404 = (
    b"<html>\r\n<head><title>404 Not Found</title></head>\r\n"
    b"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
    b"<hr><center>nginx/1.24.0 (Ubuntu)</center>\r\n"
    b"</body>\r\n</html>\r\n"
)

# --------------------------------------------------------------------------
# In-memory stats (Render's filesystem is ephemeral; stdout is the durable log)
# --------------------------------------------------------------------------

_lock = threading.Lock()
_stats = {
    "total": 0,
    "ips": Counter(),
    "paths": Counter(),
    "uas": Counter(),
    "creds": [],
    "recent": deque(maxlen=300),
    "first_seen": None,
    "last_seen": None,
}
_last_alert = [0.0]
_alert_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_line(record):
    print(json.dumps(record, ensure_ascii=False, default=str), flush=True)


def record_request(ip, method, path, query, ua, body):
    rec = {
        "ts": now(),
        "type": "http.request",
        "ip": ip,
        "method": method,
        "path": path,
        "query": query[:256],
        "user_agent": ua[:512],
        "body": body.decode("utf-8", "backslashreplace")[:1024],
    }
    with _lock:
        _stats["total"] += 1
        if _stats["first_seen"] is None:
            _stats["first_seen"] = rec["ts"]
        _stats["last_seen"] = rec["ts"]
        _stats["ips"][ip] += 1
        _stats["paths"][path] += 1
        _stats["uas"][ua[:120]] += 1
        _stats["recent"].appendleft(rec)
    log_line(rec)
    return rec


def record_creds(ip, method, path, form):
    rec = {
        "ts": now(),
        "type": "http.credentials",
        "ip": ip,
        "method": method,
        "path": path,
        "credentials": form,
    }
    with _lock:
        _stats["creds"].append(rec)
        if len(_stats["creds"]) > 500:
            _stats["creds"].pop(0)
    log_line(rec)


def notify(title, message):
    """Push an alert to ntfy.sh (free, no account) -- rate limited."""
    if not NTFY_TOPIC:
        return

    def _send():
        try:
            req = urllib.request.Request(
                "https://ntfy.sh/" + urllib.parse.quote(NTFY_TOPIC, safe=""),
                data=(title + "\n" + message).encode("utf-8"),
                headers={"Title": "CanaryPot alert", "Priority": "high",
                         "Tags": "bee,rotating_light"})
            urllib.request.urlopen(req, timeout=6)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


def should_alert(rec, new_ip):
    if "uptimerobot" in rec["user_agent"].lower():
        return False
    if new_ip:
        return True
    return rec["path"] in ("/.env", "/wp-login.php", "/wp-admin/",
                           "/.git/HEAD", "/.git/config", "/api/login")


def report_page():
    with _lock:
        total = _stats["total"]
        ips = _stats["ips"].most_common(25)
        paths = _stats["paths"].most_common(25)
        recent = list(_stats["recent"])[:40]
        creds = list(_stats["creds"])[-40:]
        first, last = _stats["first_seen"], _stats["last_seen"]

    def esc(x):
        return _html.escape(str(x))

    rows_recent = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (esc(r["ts"]), esc(r["ip"]), esc(r["method"]),
           esc(r["path"] + ("?" + r["query"] if r["query"] else "")),
           esc(r["user_agent"][:70]))
        for r in recent)
    rows_ips = "".join(
        "<tr><td>%s</td><td>%d</td></tr>" % (esc(k), v) for k, v in ips)
    rows_paths = "".join(
        "<tr><td>%s</td><td>%d</td></tr>" % (esc(k), v) for k, v in paths)
    rows_creds = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (esc(c["ts"]), esc(c["ip"]), esc(json.dumps(c["credentials"],
                                                      ensure_ascii=False)))
        for c in creds) or "<tr><td colspan=3>none yet</td></tr>"

    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>CanaryPot report</title>"
        "<style>body{font-family:monospace;background:#0f172a;color:#e2e8f0;"
        "margin:24px}h1{color:#fbbf24}table{border-collapse:collapse;"
        "margin-bottom:32px;width:100%%;max-width:900px}"
        "td,th{border:1px solid #334155;padding:4px 8px;font-size:12px}"
        "th{background:#1e293b;text-align:left;color:#94a3b8}</style></head>"
        "<body><h1>&#128038; CanaryPot report</h1>"
        "<p>window: %s &rarr; %s | total requests: %d | unique IPs: %d</p>"
        "<h2>recent requests</h2><table><tr><th>time</th><th>ip</th>"
        "<th>method</th><th>path</th><th>user-agent</th></tr>%s</table>"
        "<h2>top attacker IPs</h2><table><tr><th>ip</th><th>hits</th>"
        "</tr>%s</table>"
        "<h2>top paths probed</h2><table><tr><th>path</th><th>hits</th>"
        "</tr>%s</table>"
        "<h2>credentials tried</h2><table><tr><th>time</th><th>ip</th>"
        "<th>credentials</th></tr>%s</table>"
        "<p style='color:#64748b'>stats are in-memory and reset on restart;"
        " full history lives in the Render Logs tab.</p>"
        "</body></html>"
        % (esc(first), esc(last), total, len(ips), rows_recent,
           rows_ips, rows_paths, rows_creds)
    ).encode("utf-8")


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------


class HoneypotHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self):
        return "nginx/1.24.0 (Ubuntu)"

    def log_message(self, fmt, *args):
        pass  # we do our own JSON logging

    def _ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _respond(self, code, body=b"", ctype="text/html; charset=UTF-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._handle("GET", b"")

    def do_HEAD(self):
        self._handle("HEAD", b"")

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        n = min(max(n, 0), 8192)
        body = self.rfile.read(n) if n else b""
        self._handle("POST", body)

    def _handle(self, method, body):
        ip = self._ip()
        path, _, query = self.path.partition("?")
        ua = self.headers.get("User-Agent", "")

        # secret report page -- not logged as attacker traffic
        if path == ADMIN_PATH:
            self._respond(200, report_page())
            return

        if path == "/robots.txt":
            self._respond(200, ROBOTS.encode(), "text/plain")
            return

        rec = record_request(ip, method, path, query, ua, body)
        with _lock:
            new_ip = _stats["ips"][ip] == 1
        if should_alert(rec, new_ip):
            with _alert_lock:
                now_s = datetime.now(timezone.utc).timestamp()
                allowed = now_s - _last_alert[0] > 15
                if allowed:
                    _last_alert[0] = now_s
            if allowed:
                notify("%s probed %s" % (ip, path),
                       "method=%s path=%s ua=%s" % (method, path, ua[:200]))

        if method == "POST":
            form = {}
            if "urlencoded" in self.headers.get("Content-Type", ""):
                try:
                    form = {k: v[0] for k, v in
                            urllib.parse.parse_qs(
                                body.decode("utf-8", "replace")).items()}
                except Exception:
                    form = {}
            if not form:
                form = {"raw": body.decode("utf-8", "replace")[:500]}
            record_creds(ip, method, path, form)
            notify("credentials captured from " + ip,
                   "%s %s -> %s" % (method, path,
                                   json.dumps(form, ensure_ascii=False)))
            # pretend the login worked -> attacker digs deeper, all logged
            self._redirect("/wp-admin/" if "wp" in path else "/")
            return

        if path in ("/", "/index.html", "/index.php"):
            self._respond(200, PORTAL_PAGE)
        elif path == "/wp-login.php":
            self._respond(200, WP_LOGIN_PAGE)
        elif path == "/wp-admin":
            self._redirect("/wp-admin/")
        elif path == "/wp-admin/":
            self._respond(200, WP_ADMIN_PAGE)
        elif path == "/.env":
            self._respond(200, FAKE_ENV.encode(), "text/plain; charset=UTF-8")
        elif path == "/.git/HEAD":
            self._respond(200, FAKE_GIT_HEAD, "text/plain")
        elif path == "/.git/config":
            self._respond(200, FAKE_GIT_CONFIG.encode(), "text/plain")
        else:
            self._respond(404, NGINX_404)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), HoneypotHandler)
    server.daemon_threads = True
    print("[canarypot] listening on 0.0.0.0:%d" % PORT, flush=True)
    print("[canarypot] report page: %s" % ADMIN_PATH, flush=True)
    if NTFY_TOPIC:
        print("[canarypot] ntfy push enabled, topic=%s" % NTFY_TOPIC,
              flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
