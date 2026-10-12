"""Proxmox Temp Monitor: monitors host temperatures over SSH (lm-sensors)."""
import hmac
import json
import logging
import math
import os
import re
import shlex
import socket
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import paramiko
from cryptography.fernet import Fernet
from flask import Flask, Response, jsonify, request, send_from_directory

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "tempmon.db")
KEY_PATH = os.path.join(DATA_DIR, "secret.key")
AUTH_USER = os.environ.get("AUTH_USER")
AUTH_PASS = os.environ.get("AUTH_PASS", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tempmon")

app = Flask(__name__, static_folder="static", static_url_path="/static")

DEFAULTS = {"poll_interval": 30, "retention_days": 30}
LIMITS = {"poll_interval": (5, 86400), "retention_days": (1, 3650)}

_fernet = None
_lock = threading.Lock()
_state = {}        # host_id -> {"last_poll": float}
_inflight = set()


# --------------------------------------------------------------------------- util
class ApiError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


@app.errorhandler(ApiError)
def _api_error(e):
    return jsonify(error=e.code, message=e.message), e.status


@app.before_request
def _auth():
    if not AUTH_USER:
        return None
    a = request.authorization
    if (not a or not hmac.compare_digest(a.username or "", AUTH_USER)
            or not hmac.compare_digest(a.password or "", AUTH_PASS)):
        return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="TempMon"'})
    return None


def get_fernet():
    global _fernet
    if _fernet:
        return _fernet
    key = os.environ.get("SECRET_KEY")
    if not key:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(KEY_PATH):
            key = open(KEY_PATH, "rb").read().strip()
        else:
            key = Fernet.generate_key()
            fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
    _fernet = Fernet(key)
    return _fernet


def db():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def q(sql, args=()):
    with closing(db()) as c:
        return c.execute(sql, args).fetchall()


def ex(sql, args=()):
    with closing(db()) as c:
        cur = c.execute(sql, args)
        c.commit()
        return cur.lastrowid


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    get_fernet()
    with closing(db()) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS hosts(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, ip TEXT NOT NULL,
          port INTEGER NOT NULL DEFAULT 22, username TEXT NOT NULL,
          password_enc TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS latest(
          host_id INTEGER PRIMARY KEY, ts INTEGER, ok INTEGER, error TEXT, data TEXT);
        CREATE TABLE IF NOT EXISTS history(
          id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INTEGER NOT NULL,
          ts INTEGER NOT NULL, data TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_hist ON history(host_id, ts);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        """)
        c.commit()


def get_settings():
    s = dict(DEFAULTS)
    for r in q("SELECT key, value FROM settings"):
        if r["key"] in s:
            try:
                s[r["key"]] = int(r["value"])
            except ValueError:
                pass
    return s


# --------------------------------------------------------------------------- SSH
def ssh_connect(ip, port, user, pw, timeout=10):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, port=port, username=user, password=pw, timeout=timeout,
              banner_timeout=timeout, auth_timeout=timeout,
              look_for_keys=False, allow_agent=False)
    return c


def connect_or_raise(ip, port, user, pw):
    try:
        return ssh_connect(ip, port, user, pw)
    except paramiko.AuthenticationException:
        raise ApiError("auth", "Incorrect username or password", 422)
    except (socket.timeout, TimeoutError):
        raise ApiError("timeout", f"Timed out connecting to {ip}:{port}", 422)
    except (paramiko.SSHException, OSError) as e:
        raise ApiError("connect", f"Could not connect to {ip}:{port}: {e}", 422)


def run(c, cmd, timeout=30, sudo_pw=None):
    if sudo_pw is not None:
        cmd = "sudo -S -p '' sh -c " + shlex.quote(cmd)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    if sudo_pw is not None:
        stdin.write(sudo_pw + "\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return out, err, stdout.channel.recv_exit_status()


def sensors_installed(c):
    out, _, _ = run(c, "command -v sensors >/dev/null 2>&1 && echo yes || echo no")
    return out.strip() == "yes"


# --------------------------------------------------------------------------- parser
CHIP_LABELS = [("coretemp", "CPU"), ("k10temp", "CPU"), ("zenpower", "CPU"),
               ("nouveau", "GPU"), ("amdgpu", "GPU"), ("nvidia", "GPU"),
               ("nvme", "NVMe"), ("acpitz", "ACPI"), ("pch", "Chipset"),
               ("iwlwifi", "WiFi"), ("drivetemp", "Disco")]
MAIN_PRIORITY = ["Package id 0", "Tctl", "Tdie", "Composite", "temp1"]
TEMP_RE = re.compile(r"^(?P<label>[^:]+?):\s+(?P<val>[+-]?\d+(?:\.\d+)?)\s*°?\s*C\b(?P<rest>.*)$")
NUM = r"([+-]?\d+(?:\.\d+)?)"


def _valid(v, lo=-40, hi=150):
    return v is not None and lo < v < hi


def _thresholds(text, target):
    for key in ("high", "crit"):
        m = re.search(rf"\b{key}\s*=\s*{NUM}\s*°?\s*C", text)
        if m:
            v = float(m.group(1))
            if _valid(v, 0, 200):
                target[key] = v


def parse_sensors(text):
    """Turn `sensors` output into a list of chips with their temperatures.
    Drops N/A and absurd readings (e.g. the -263.2 °C from acpitz)."""
    chips = []
    for block in re.split(r"\n\s*\n", text.strip()):
        lines = block.splitlines()
        if not lines:
            continue
        chip_name = lines[0].strip()
        sensors, last = [], None
        for line in lines[1:]:
            if line.startswith(" ") and line.strip().startswith("(") and last is not None:
                _thresholds(line, last)      # continuation lines (crit/emerg)
                continue
            m = TEMP_RE.match(line.strip())
            if not m:
                last = None
                continue
            v = float(m.group("val"))
            if not _valid(v):
                last = None
                continue
            last = {"label": m.group("label").strip(), "value": v}
            _thresholds(m.group("rest"), last)
            sensors.append(last)
        if not sensors:
            continue
        main = None
        for p in MAIN_PRIORITY:
            main = next((s for s in sensors if s["label"] == p), None)
            if main:
                break
        main = main or sensors[0]
        label = next((nice for prefix, nice in CHIP_LABELS if chip_name.startswith(prefix)), chip_name)
        chips.append({"chip": chip_name, "label": label, "main": main["value"], "sensors": sensors})
    # disambiguate repeated labels (e.g. two NVMe drives)
    counts = {}
    for c in chips:
        counts[c["label"]] = counts.get(c["label"], 0) + 1
    for c in chips:
        if counts[c["label"]] > 1:
            c["label"] = f'{c["label"]} ({c["chip"].split("-")[-1]})'
    return chips


def collect(ip, port, user, pw):
    c = ssh_connect(ip, port, user, pw)
    try:
        out, err, code = run(c, "LC_ALL=C sensors 2>&1")
    finally:
        c.close()
    if code != 0 and not out.strip():
        raise RuntimeError(err.strip() or f"sensors exited with code {code}")
    chips = parse_sensors(out)
    if not chips:
        raise RuntimeError("sensors returned no temperatures (you may need to run sensors-detect)")
    return chips


# --------------------------------------------------------------------------- polling
def store_reading(hid, chips, now):
    """Save the reading as the latest value and as a history point."""
    ex("INSERT OR REPLACE INTO latest(host_id, ts, ok, error, data) VALUES(?,?,?,?,?)",
       (hid, now, 1, None, json.dumps(chips)))
    data = {c["chip"]: c["main"] for c in chips}
    ex("INSERT INTO history(host_id, ts, data) VALUES(?,?,?)", (hid, now, json.dumps(data)))


def poll_host(hid):
    try:
        rows = q("SELECT * FROM hosts WHERE id=?", (hid,))
        if not rows:
            return
        h = rows[0]
        now = int(time.time())
        try:
            pw = get_fernet().decrypt(h["password_enc"].encode()).decode()
            chips = collect(h["ip"], h["port"], h["username"], pw)
            store_reading(hid, chips, now)
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to query %s: %s", h["name"], e)
            ex("INSERT OR REPLACE INTO latest(host_id, ts, ok, error, data) VALUES(?,?,?,?,?)",
               (hid, now, 0, str(e)[:300], (q("SELECT data FROM latest WHERE host_id=?", (hid,)) or [{"data": None}])[0]["data"]))
    finally:
        with _lock:
            _inflight.discard(hid)


def scheduler():
    pool = ThreadPoolExecutor(max_workers=8)
    last_cleanup = 0
    while True:
        try:
            s = get_settings()
            now = time.time()
            for h in q("SELECT id FROM hosts"):
                hid = h["id"]
                with _lock:
                    st = _state.setdefault(hid, {"last_poll": 0})
                    if hid in _inflight or now - st["last_poll"] < s["poll_interval"]:
                        continue
                    st["last_poll"] = now
                    _inflight.add(hid)
                pool.submit(poll_host, hid)
            if now - last_cleanup > 3600:
                last_cleanup = now
                cutoff = int(now - s["retention_days"] * 86400)
                ex("DELETE FROM history WHERE ts < ?", (cutoff,))
        except Exception:  # noqa: BLE001
            log.exception("Scheduler error")
        time.sleep(1)


# --------------------------------------------------------------------------- API
def parse_creds(d, need_name=False):
    d = d or {}
    name = (d.get("name") or "").strip()
    ip = (d.get("ip") or "").strip()
    user = (d.get("username") or "").strip()
    pw = d.get("password") or ""
    try:
        port = int(d.get("port") or 22)
    except (TypeError, ValueError):
        raise ApiError("invalid", "Invalid port")
    if not 1 <= port <= 65535:
        raise ApiError("invalid", "Port out of range")
    if need_name and not name:
        raise ApiError("invalid", "Missing friendly name")
    if not ip or not user or not pw:
        raise ApiError("invalid", "IP, username and password are required")
    return name, ip, port, user, pw


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/settings")
def api_get_settings():
    return jsonify(get_settings())


@app.put("/api/settings")
def api_put_settings():
    d = request.get_json(silent=True) or {}
    s = get_settings()
    for k, (lo, hi) in LIMITS.items():
        if k in d:
            try:
                v = int(d[k])
            except (TypeError, ValueError):
                raise ApiError("invalid", f"Invalid value for {k}")
            if not lo <= v <= hi:
                raise ApiError("invalid", f"{k} must be between {lo} and {hi}")
            s[k] = v
    for k, v in s.items():
        ex("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (k, str(v)))
    return jsonify(s)


@app.get("/api/hosts")
def api_hosts():
    out = []
    for h in q("SELECT * FROM hosts ORDER BY name COLLATE NOCASE"):
        l = q("SELECT * FROM latest WHERE host_id=?", (h["id"],))
        latest = None
        if l:
            latest = {"ts": l[0]["ts"], "ok": bool(l[0]["ok"]), "error": l[0]["error"],
                      "chips": json.loads(l[0]["data"]) if l[0]["data"] else []}
        out.append({"id": h["id"], "name": h["name"], "ip": h["ip"], "port": h["port"],
                    "username": h["username"], "latest": latest})
    return jsonify(out)


@app.post("/api/hosts/test")
def api_test():
    _, ip, port, user, pw = parse_creds(request.get_json(silent=True))
    c = connect_or_raise(ip, port, user, pw)
    try:
        installed = sensors_installed(c)
    finally:
        c.close()
    return jsonify(ok=True, sensors_installed=installed)


@app.post("/api/hosts/install-sensors")
def api_install():
    _, ip, port, user, pw = parse_creds(request.get_json(silent=True))
    c = connect_or_raise(ip, port, user, pw)
    try:
        cmd = ("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; "
               "apt-get install -y lm-sensors; sensors-detect --auto >/dev/null 2>&1; true")
        out, err, _ = run(c, cmd, timeout=300, sudo_pw=None if user == "root" else pw)
        ok = sensors_installed(c)
    finally:
        c.close()
    log_tail = "\n".join((out + "\n" + err).strip().splitlines()[-15:])
    if not ok:
        raise ApiError("install_failed", "Could not install lm-sensors.\n" + log_tail, 500)
    return jsonify(ok=True, log=log_tail)


@app.post("/api/hosts")
def api_add():
    name, ip, port, user, pw = parse_creds(request.get_json(silent=True), need_name=True)
    if q("SELECT 1 FROM hosts WHERE ip=? AND port=? AND username=?", (ip, port, user)):
        raise ApiError("duplicate", "That host has already been added", 409)
    c = connect_or_raise(ip, port, user, pw)
    try:
        if not sensors_installed(c):
            raise ApiError("sensors_missing", "lm-sensors is not installed on the host", 409)
    finally:
        c.close()
    try:
        chips = collect(ip, port, user, pw)
    except Exception as e:  # noqa: BLE001
        raise ApiError("no_readings", str(e), 422)
    hid = ex("INSERT INTO hosts(name, ip, port, username, password_enc, created_at) VALUES(?,?,?,?,?,?)",
             (name, ip, port, user, get_fernet().encrypt(pw.encode()).decode(), int(time.time())))
    now = int(time.time())
    with _lock:
        _state[hid] = {"last_poll": now}
    store_reading(hid, chips, now)
    return jsonify(id=hid), 201


@app.delete("/api/hosts/<int:hid>")
def api_delete(hid):
    ex("DELETE FROM history WHERE host_id=?", (hid,))
    ex("DELETE FROM latest WHERE host_id=?", (hid,))
    ex("DELETE FROM hosts WHERE id=?", (hid,))
    with _lock:
        _state.pop(hid, None)
    return jsonify(ok=True)


@app.post("/api/hosts/<int:hid>/poll")
def api_poll(hid):
    if not q("SELECT 1 FROM hosts WHERE id=?", (hid,)):
        raise ApiError("not_found", "Host not found", 404)
    with _lock:
        if hid in _inflight:
            return jsonify(ok=True, busy=True)
        _inflight.add(hid)
        _state.setdefault(hid, {"last_poll": 0})["last_poll"] = time.time()
    poll_host(hid)
    return jsonify(ok=True)


@app.get("/api/hosts/<int:hid>/history")
def api_history(hid):
    try:
        hours = float(request.args.get("hours", 24))
    except ValueError:
        hours = 24
    since = int(time.time() - hours * 3600)
    rows = q("SELECT ts, data FROM history WHERE host_id=? AND ts>=? ORDER BY ts", (hid, since))
    stride = max(1, math.ceil(len(rows) / 1200))
    points = [{"t": r["ts"], "v": json.loads(r["data"])} for r in rows[::stride]]
    l = q("SELECT data FROM latest WHERE host_id=?", (hid,))
    chips = {}
    if l and l[0]["data"]:
        chips = {c["chip"]: c["label"] for c in json.loads(l[0]["data"])}
    return jsonify(chips=chips, points=points)


_started = False


def start():
    global _started
    if _started:
        return
    _started = True
    init_db()
    if os.environ.get("TEMPMON_NO_SCHED") != "1":
        threading.Thread(target=scheduler, daemon=True, name="scheduler").start()


start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
