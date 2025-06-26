#!/usr/bin/env python3
# AIONET – edge traffic controller with dynamic HTB shaping
# ---------------------------------------------------------

from flask import Flask, render_template, request, jsonify
import threading, time, subprocess, sqlite3, json, os, socket
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, send, Packet, ShortField, StrFixedLenField
import numpy as np
import psutil

app  = Flask(__name__)
lock = threading.Lock()

DB_FILE      = "aionet1.db"
CONFIG_FILE  = "aionet_priorities.json"
STATS_WINDOW = 20          # packets to keep for rate calc
ACTIVE_WINDOW = 20         # seconds before a flow is “stale”

application_cpu = {}       # {process_name: cpu%}
port_to_app     = {}       # {port: process_name}
flow_stats      = defaultdict(lambda: {
    "pkt_count": 0,
    "total_size": 0,
    "first_seen": None,
    "last_seen":  None,
    "analyzer":   None
})

# ─────────────────────────────────────────  custom packet  ──
class MyPacket(Packet):
    name = "MyPacket"
    fields_desc = [
        ShortField("field1", 0),
        StrFixedLenField("field2", b"", length=16),
        StrFixedLenField("field3", b"", length=12),
        StrFixedLenField("field4", b"", length=17),
        StrFixedLenField("data",   b"", length=83)
    ]

# ──────────────────────────────────────────  config helper  ──
class PriorityConfig:
    def __init__(self):
        self.app_bonuses = {}
        self.port_rules  = {}
        self.load()
    def load(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
                self.app_bonuses = cfg.get("application_bonuses", {})
                self.port_rules  = cfg.get("port_rules", {})
        else:                               # sensible defaults
            self.app_bonuses = {"zoom": 0.5, "teams": 0.5, "chrome": 0.2}
            self.port_rules  = {"8801": {"priority": "high"},
                                "3478": {"priority": "high"}}

priority_config = PriorityConfig()

# ──────────────────────────────────────────  flow analyser  ──
class FlowAnalyzer:
    def __init__(self):
        self.packet_sizes = deque(maxlen=STATS_WINDOW)
        self.packet_times = deque(maxlen=STATS_WINDOW)
        self.protocols     = set()
    def add_packet(self, pkt):
        now = time.time()
        self.packet_sizes.append(len(pkt))
        self.packet_times.append(now)
        if TCP in pkt and pkt[TCP].dport in (443, 8443):
            self.protocols.add("encrypted")
    @property
    def avg_bandwidth(self):                # kbps
        if len(self.packet_times) < 2:
            return 0
        duration = self.packet_times[-1] - self.packet_times[0]
        return 0 if duration <= 0 else (sum(self.packet_sizes)*8)/(duration*1000)
    @property
    def avg_interval(self):
        return np.mean(np.diff(self.packet_times)) if len(self.packet_times) > 1 else 0

# ──────────────────────────────────────────  persistence  ───
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS app_priorities(
              app_name TEXT PRIMARY KEY,
              base_priority TEXT,
              user_override TEXT,
              last_updated DATETIME);
            CREATE TABLE IF NOT EXISTS feedback(
              id INTEGER PRIMARY KEY,
              app_name TEXT,
              current_priority TEXT,
              override_priority TEXT,
              timestamp TEXT);
            CREATE TABLE IF NOT EXISTS unknown_apps(
              id INTEGER PRIMARY KEY,
              app_signature TEXT UNIQUE,
              first_seen DATETIME,
              last_seen DATETIME,
              assigned_priority TEXT);
            CREATE TABLE IF NOT EXISTS app_metrics(
              id INTEGER PRIMARY KEY,
              app_name TEXT,
              cpu_percent REAL,
              bandwidth REAL,
              priority TEXT,
              timestamp TEXT);
        """)
        conn.commit()

# ──────────────────────────────────────────  scoring logic  ─
def compute_priority(app_name: str, flow_data: dict) -> str:
    """Return textual priority high|medium|low (numeric score returned separately)."""
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT user_override FROM app_priorities WHERE app_name=?",(app_name,))
        if (row := cur.fetchone()) and row[0]:
            return row[0]

    stats    = flow_data["stats"]
    analyzer = flow_data["analyzer"]

    cpu  = min(application_cpu.get(app_name, 0)/40,        1)   # 0–1
    bw   = min(stats["bw_kbps"]            /10_000,        1)
    pkts = min(stats["pkt_count"]          /500,           1)
    score = 0.5*cpu + 0.3*bw + 0.2*pkts
    score += priority_config.app_bonuses.get(app_name.lower(), 0)
    if "encrypted" in analyzer.protocols:
        score += 0.2

    priority = "high" if score > 0.75 else ("medium" if score > 0.45 else "low")

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""INSERT INTO app_priorities(app_name,base_priority,last_updated)
                        VALUES(?,?,?)
                        ON CONFLICT(app_name) DO UPDATE
                        SET base_priority=excluded.base_priority,
                            last_updated=excluded.last_updated""",
                     (app_name, priority, datetime.now().isoformat()))
        conn.commit()
    return priority

# Helper to re-compute numeric score the same way
def numeric_score(app_name, pkt_count, bw_kbps, analyzer):
    cpu  = min(application_cpu.get(app_name, 0)/40, 1)
    bw   = min(bw_kbps/10_000, 1)
    pkts = min(pkt_count/500, 1)
    score = 0.5*cpu + 0.3*bw + 0.2*pkts
    score += priority_config.app_bonuses.get(app_name.lower(), 0)
    if "encrypted" in analyzer.protocols:
        score += 0.2
    return score

# ───────────────────────────────────  HTB shaping function  ─
# ─────────────────────────────  HTB shaping helper  ──────────────
_shaping_cache = {}                              # {(app,port): last_bw}
def apply_bw_shaping(app_name: str,
                     score: float,
                     pkt_count: int,
                     iface: str = "ifb0",        # or wlp2s0 if you bound the ifb
                     base_kbps: int = 100,
                     max_kbps: int  = 10_000):
    """
    Dynamic cap:
        bw = min( base_kbps * log1p(pkt_count) * score , max_kbps )
    Creates/updates an HTB class per port used by the app.
    """

    bw_limit = max(64, min(int(base_kbps * np.log1p(pkt_count) * score),
                           max_kbps))

    # root qdisc (idempotent)
    subprocess.run(f"tc qdisc replace dev {iface} root handle 1: htb default 30",
                   shell=True, stderr=subprocess.DEVNULL)

    # ---- take a snapshot of current port map (avoid 'dict changed' error) ----
    with lock:
        app_ports = [p for p, a in port_to_app.items() if a == app_name]

    for port in app_ports:
        cache_key = (app_name, port)
        if _shaping_cache.get(cache_key) == bw_limit:
            continue                     # nothing to update

        _shaping_cache[cache_key] = bw_limit
        cls = f"1:{port}"
        subprocess.run(
            f"tc class replace dev {iface} parent 1: classid {cls} "
            f"htb rate {bw_limit}kbit ceil {bw_limit}kbit",
            shell=True, stderr=subprocess.DEVNULL)
        subprocess.run(
            f"tc filter replace dev {iface} protocol ip parent 1: prio 1 "
            f"u32 match ip sport {port} 0xffff flowid {cls}",
            shell=True, stderr=subprocess.DEVNULL)

    # safe print (list may be empty)
    print(f"[BW SHAPING] {app_name:<20} ports={app_ports or '—'}  cap={bw_limit} kbit")

# ───────────────────────────────────────────  utility logs  ─
def log_unknown_app(pkt, priority):
    sig = f"{pkt[IP].src}:{pkt[IP].dst}:{pkt[IP].proto}"
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""INSERT INTO unknown_apps(app_signature,first_seen,last_seen,assigned_priority)
                        VALUES(?,?,?,?)
                        ON CONFLICT(app_signature) DO UPDATE
                        SET last_seen=excluded.last_seen,
                            assigned_priority=excluded.assigned_priority""",
                     (sig, now, now, priority))
        conn.commit()

# ──────────────────────────────────────────  packet handler  ─
def process_packet(pkt):
    try:
        if IP not in pkt or not (TCP in pkt or UDP in pkt):
            return
        l4       = pkt[TCP] if TCP in pkt else pkt[UDP]
        ip_l     = pkt[IP]
        flow_key = (ip_l.src, ip_l.dst, l4.dport)

        with lock:
            flow = flow_stats[flow_key]
            if not flow["analyzer"]:
                flow["analyzer"]  = FlowAnalyzer()
                flow["first_seen"] = datetime.now()
            flow["analyzer"].add_packet(pkt)
            flow["pkt_count"]  += 1
            flow["total_size"] += len(pkt)
            flow["last_seen"]   = datetime.now()

        app_name = port_to_app.get(l4.dport, "unknown")
        cpu_pct  = application_cpu.get(app_name, 0) if app_name != "unknown" else 0.0
        bw_kbps  = flow["analyzer"].avg_bandwidth

        # derive priority & numeric score
        if app_name == "unknown":
            priority = "high" if flow["analyzer"].avg_interval < 0.01 else "medium"
            log_unknown_app(pkt, priority)
            score = 0.6                         # heuristic fallback
        else:
            flow_data = {"stats": {"bw_kbps": bw_kbps,
                                   "pkt_count": flow["pkt_count"]},
                         "analyzer": flow["analyzer"]}
            priority = compute_priority(app_name, flow_data)
            score    = numeric_score(app_name, flow["pkt_count"], bw_kbps, flow["analyzer"])

        # persist metrics
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("""INSERT INTO app_metrics(app_name,cpu_percent,bandwidth,
                           priority,timestamp) VALUES(?,?,?,?,?)""",
                         (app_name, cpu_pct, bw_kbps, priority,
                          datetime.now().isoformat()))
            conn.commit()

        # enforce shaping
        apply_bw_shaping(app_name, score, flow["pkt_count"])

    except Exception as e:
        print("[ERROR]", e)

# ─────────────────────────────────────  background monitors  ─
def monitor_application_cpu():
    while True:
        try:
            top = subprocess.run(["top", "-b", "-n1"], text=True,
                                 capture_output=True).stdout.splitlines()
            cpu_tmp, parsing = {}, False
            for ln in top:
                if ln.startswith(" PID"):
                    parsing = True
                    continue
                if parsing and ln.strip():
                    parts = ln.split()
                    if len(parts) >= 9:
                        cpu_tmp[parts[-1]] = cpu_tmp.get(parts[-1], 0) + float(parts[8])
            with lock:
                application_cpu.clear()
                application_cpu.update(cpu_tmp)
            time.sleep(2)
        except Exception as e:
            print("[CPU-MON]", e); time.sleep(5)

def update_port_mapping():
    while True:
        try:
            tmp = {}
            for c in psutil.net_connections(kind="inet"):
                if not (c.laddr and c.pid):
                    continue
                if c.type == socket.SOCK_STREAM and c.status != psutil.CONN_ESTABLISHED:
                    continue
                try:
                    proc = psutil.Process(c.pid)
                    tmp[c.laddr.port] = proc.name()
                    if c.raddr:
                        tmp[c.raddr.port] = proc.name()
                except psutil.Error:
                    pass
            with lock:
                port_to_app.clear()
                port_to_app.update(tmp)
            time.sleep(2)
        except Exception as e:
            print("[PORT-MON]", e)

# ──────────────────────────────────────────  Flask routes  ──
@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/metrics")
def metrics():
    try:
        now = time.time()
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("""SELECT m.app_name,m.cpu_percent,m.bandwidth,
                           m.priority,MAX(m.timestamp),p.user_override
                           FROM app_metrics m
                           LEFT JOIN app_priorities p
                           ON m.app_name=p.app_name
                           GROUP BY m.app_name""")
            rows = cur.fetchall()

            metrics = {r[0]: {"cpu": r[1], "bw": r[2],
                              "prio": r[3], "override": r[5] or ""}
                       for r in rows
                       if now - datetime.fromisoformat(r[4]).timestamp() < ACTIVE_WINDOW}

            cur.execute("""SELECT app_signature,last_seen,assigned_priority
                           FROM unknown_apps ORDER BY last_seen DESC LIMIT 10""")
            alerts = [{"sig": r[0], "time": r[1], "prio": r[2]} for r in cur]

        return jsonify({"metrics": metrics, "alerts": alerts})
    except Exception as e:
        print("[/metrics]", e); return jsonify(metrics={}, alerts=[])

@app.route("/override", methods=["POST"])
def override():
    app_name = request.form["app_name"]
    new_prio = request.form["override_priority"].lower()
    now      = datetime.now().isoformat()
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""INSERT INTO feedback(app_name,current_priority,
                        override_priority,timestamp) VALUES(?,?,?,?)""",
                     (app_name, "auto", new_prio, now))
        if new_prio:
            conn.execute("""INSERT INTO app_priorities(app_name,user_override,last_updated)
                            VALUES(?,?,?)
                            ON CONFLICT(app_name) DO UPDATE
                            SET user_override=excluded.user_override,
                                last_updated=excluded.last_updated""",
                         (app_name, new_prio, now))
        else:
            conn.execute("""UPDATE app_priorities
                            SET user_override=NULL,last_updated=?
                            WHERE app_name=?""",
                         (now, app_name))
        conn.commit()
    return jsonify(status="success")

@app.route("/send_custom_packet", methods=["POST"])
def send_custom_packet():
    try:
        dst_ip = request.form.get("dst_ip", "127.0.0.1")
        dport  = int(request.form.get("dport", 9999))
        pkt = IP(dst=dst_ip)/UDP(dport=dport)/MyPacket(
            field1=int(request.form.get("field1", 123)),
            field2=request.form.get("field2", "abcdefghijklmno1").encode().ljust(16)[:16],
            field3=request.form.get("field3", "123456789012").encode().ljust(12)[:12],
            field4=request.form.get("field4", "abcdefghijklmnopq").encode().ljust(17)[:17],
            data=request.form.get("data",  "x"*83).encode().ljust(83)[:83]
        )
        send(pkt, verbose=0)
        return jsonify(status="success",
                       message=f"Sent custom packet to {dst_ip}:{dport}")
    except Exception as e:
        return jsonify(status="error", message=str(e))

# ──────────────────────────────────────────  main entry  ───
if __name__ == "__main__":
    init_db()
    threading.Thread(target=update_port_mapping,   daemon=True).start()
    threading.Thread(target=monitor_application_cpu,daemon=True).start()
    threading.Thread(target=lambda: sniff(prn=process_packet,
                                          filter="ip", store=False),
                     daemon=True).start()
    # run as root so tc works
    app.run(host="0.0.0.0", port=5050, debug=False)

