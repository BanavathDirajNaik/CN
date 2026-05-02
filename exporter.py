#!/usr/bin/env python3
"""
Real-Time Network Data Analyzer — Prometheus Exporter
Monitors per-app RX/TX bytes and TCP connections via ADB on an Android device.
(Non-Root Version using dumpsys + UID Connection Tracking)

Usage:
    pip install -r requirements.txt
    python exporter.py

Metrics served at http://0.0.0.0:8000/metrics
"""

import os
import re
import shutil
import socket
import struct
import subprocess
import time
import logging
from collections import defaultdict
from threading import Thread, Lock
from http.server import BaseHTTPRequestHandler, HTTPServer

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("network_analyzer")

# ── Config (override via environment variables) ───────────────────────────────

EXPORTER_PORT    = int(os.environ.get("EXPORTER_PORT",    8000))
SCRAPE_INTERVAL  = int(os.environ.get("SCRAPE_INTERVAL",  30))   
ADB_TIMEOUT      = int(os.environ.get("ADB_TIMEOUT",      12))

# ── ADB helpers ───────────────────────────────────────────────────────────────

def _adb_path() -> str:
    custom = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "platform-tools", "adb")
    if os.path.exists(custom):
        return custom
    found = shutil.which("adb")
    if found:
        return found
    raise FileNotFoundError(
        "adb not found. Install Android Platform Tools and add to PATH, "
        "or place the platform-tools/ folder next to this script."
    )

def adb_shell(cmd: str, timeout: int = ADB_TIMEOUT) -> str:
    try:
        result = subprocess.run(
            [_adb_path(), "shell"] + cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return result.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        log.warning("ADB command timed out: %s", cmd)
        return ""
    except Exception as exc:
        log.error("ADB error for '%s': %s", cmd, exc)
        return ""

# ── IP / Port utilities ───────────────────────────────────────────────────────

def _hex_to_ip(hex_str: str) -> str:
    try:
        return socket.inet_ntoa(struct.pack("<I", int(hex_str, 16)))
    except Exception:
        return "0.0.0.0"

def _parse_addr(addr_str: str):
    ip_hex, port_hex = addr_str.split(":")
    return _hex_to_ip(ip_hex), int(port_hex, 16)

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}

# ── Process helpers (UID Tracking) ────────────────────────────────────────────

def get_process_maps() -> tuple[dict, dict, dict]:
    """
    Parses Android 'ps -A' command.
    Returns: (pid_app_map, uid_app_map, uid_pid_map)
    """
    for flags in ("ps -A", "ps -e", "ps"):
        raw = adb_shell(flags)
        if len(raw.splitlines()) > 2:
            break

    pid_app = {}
    uid_app = {}
    uid_pid = {}
    
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
            
        user_str = parts[0]
        pid = parts[1]
        app = parts[-1]
        
        pid_app[pid] = app
        
        # Calculate UID from Android user strings (u0_a123, u0_i45, etc.)
        uid = None
        if user_str.isdigit():
            uid = user_str
        else:
            m = re.match(r"u(\d+)_(a|i)(\d+)", user_str)
            if m:
                user_id = int(m.group(1))
                type_char = m.group(2)
                app_id = int(m.group(3))
                
                calc_uid = user_id * 100000
                if type_char == 'a':
                    calc_uid += 10000 + app_id    
                elif type_char == 'i':
                    calc_uid += 90000 + app_id    
                uid = str(calc_uid)
        
        if uid:
            clean_app = app.split(":")[0]
            uid_app[uid] = clean_app
            
            # Map UID back to the main PID
            if uid not in uid_pid:
                uid_pid[uid] = pid
            
    return pid_app, uid_app, uid_pid


def get_uid_package_map() -> dict:
    raw = adb_shell("pm list packages -U")
    uid_map = {}
    for line in raw.splitlines():
        if "package:" in line and "uid:" in line:
            parts = line.split()
            if len(parts) >= 2:
                pkg = parts[0].replace("package:", "")
                uid = parts[1].replace("uid:", "")
                uid_map[uid] = pkg
    return uid_map

# ── RX / TX collection strategies ────────────────────────────────────────────

def get_app_usage_from_dumpsys() -> dict:
    raw = adb_shell("dumpsys netstats --uid")
    stats = defaultdict(lambda: {"rx": 0, "tx": 0})
    
    current_uid = None
    for line in raw.splitlines():
        line = line.strip()
        
        if "uid=" in line:
            match = re.search(r"uid=(\d+)", line)
            if match:
                current_uid = match.group(1)
        
        if current_uid and "rb=" in line and "tb=" in line:
            parts = line.split()
            for p in parts:
                try:
                    if p.startswith("rb="):
                        stats[current_uid]["rx"] += int(p.split("=")[1])
                    elif p.startswith("tb="):
                        stats[current_uid]["tx"] += int(p.split("=")[1])
                except (IndexError, ValueError):
                    pass
                    
    return dict(stats)

# ── Connection tracking (ROOT-FREE via UID) ───────────────────────────────────

def get_connections(final_uid_map: dict, uid_pid_map: dict) -> list:
    """
    Parse /proc/net/tcp (+ tcp6) and map connections using the exact UID.
    Bypasses the need for root /proc/<pid>/fd scanning entirely!
    """
    connections = []

    for proto in ("tcp", "tcp6"):
        raw = adb_shell(f"cat /proc/net/{proto}")
        for line in raw.splitlines()[1:]:
            parts = line.split()
            # Standard Linux tcp file has uid at index 7
            if len(parts) < 10:
                continue
            try:
                local_ip, local_port = _parse_addr(parts[1])
                rem_ip,   rem_port   = _parse_addr(parts[2])
                state_hex            = parts[3].upper()
                uid                  = parts[7]
                
                # Instantly map the connection's UID to App Name and PID
                app   = final_uid_map.get(uid, f"uid_{uid}")
                pid   = uid_pid_map.get(uid, "unknown")
                state = TCP_STATES.get(state_hex, state_hex)
                
                connections.append({
                    "app":        app,
                    "pid":        pid,
                    "proto":      proto,
                    "local_ip":   local_ip,
                    "local_port": str(local_port),
                    "rem_ip":     rem_ip,
                    "rem_port":   str(rem_port),
                    "state":      state,
                })
            except Exception:
                pass
    return connections

# ── Prometheus text format helpers ────────────────────────────────────────────

def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

def _metric(name: str, labels: dict, value, mtype: str = "gauge") -> str:
    label_str = ",".join(f'{k}="{_escape(str(v))}"' for k, v in labels.items())
    return f"{name}{{{label_str}}} {value}"

# ── Core collector ────────────────────────────────────────────────────────────

class NetworkCollector:

    def __init__(self, interval: int = SCRAPE_INTERVAL):
        self.interval = interval
        self._lock          = Lock()
        self._metrics_bytes = b"# Waiting for first collection...\n"
        self._running       = False
        self._collect_count = 0
        self._last_ok_ts    = 0.0

    def _build_metrics(self) -> bytes:
        lines: list[str] = []

        lines += [
            "# HELP app_rx_bytes Total bytes received by the application",
            "# TYPE app_rx_bytes counter",
            "# HELP app_tx_bytes Total bytes transmitted by the application",
            "# TYPE app_tx_bytes counter",
            "# HELP app_connections Active TCP connection",
            "# TYPE app_connections gauge",
            "# HELP network_exporter_last_scrape_timestamp_seconds Unix timestamp of last scrape",
            "# TYPE network_exporter_last_scrape_timestamp_seconds gauge",
            "# HELP network_exporter_active_processes Number of processes discovered",
            "# TYPE network_exporter_active_processes gauge",
        ]

        # 1. Fetch live processes and mappings
        pid_app, active_uid_app, uid_pid_map = get_process_maps()
        lines.append(f"network_exporter_active_processes {len(pid_app)}")

        # 2. Build the master UID dictionary
        final_uid_map = {
            "1000": "android.system",
            "1001": "android.phone",
            "1013": "android.media_server",
            "1041": "android.audio_server",
            "1073": "android.network_stack",
        }
        
        final_uid_map.update(get_uid_package_map())
        
        for uid, app in active_uid_app.items():
            if uid not in final_uid_map:
                final_uid_map[uid] = app

        # 3. Pull network bandwidth stats
        dumpsys_stats = get_app_usage_from_dumpsys()

        if dumpsys_stats:
            sorted_stats = sorted(
                dumpsys_stats.items(), 
                key=lambda item: item[1]["rx"] + item[1]["tx"], 
                reverse=True
            )
            
            seen_uid: set = set()
            for uid, s in sorted_stats:
                if uid in seen_uid:
                    continue
                seen_uid.add(uid)
                
                app = final_uid_map.get(uid)
                if not app:
                    base_uid = int(uid) % 100000
                    if 90000 <= base_uid <= 99999:
                        app = "android.isolated_sandbox"
                    else:
                        app = f"uid_{uid}"

                labels = {"app": app, "uid": uid, "source": "dumpsys"}
                lines.append(_metric("app_rx_bytes", labels, s["rx"]))
                lines.append(_metric("app_tx_bytes", labels, s["tx"]))


        # 4. Pull Active Connections (Using the brilliant UID bypass!)
        connections = get_connections(final_uid_map, uid_pid_map)
        for c in connections:
            labels = {
                "app":        c["app"],
                "pid":        c["pid"],
                "proto":      c["proto"],
                "local_ip":   c["local_ip"],
                "local_port": c["local_port"],
                "rem_ip":     c["rem_ip"],
                "rem_port":   c["rem_port"],
                "state":      c["state"],
            }
            lines.append(_metric("app_connections", labels, 1))

        now = time.time()
        lines.append(f"network_exporter_last_scrape_timestamp_seconds {now:.3f}")

        return ("\n".join(lines) + "\n").encode("utf-8")

    def run_loop(self):
        self._running = True
        log.info("Collection loop started (interval=%ds)", self.interval)
        while self._running:
            t0 = time.time()
            try:
                data = self._build_metrics()
                with self._lock:
                    self._metrics_bytes = data
                    self._last_ok_ts    = time.time()
                    self._collect_count += 1
                elapsed = time.time() - t0
                log.info(
                    "Scrape #%d complete — %d bytes in %.1fs",
                    self._collect_count, len(data), elapsed,
                )
            except Exception as exc:
                log.exception("Collection failed: %s", exc)
            time.sleep(max(0, self.interval - (time.time() - t0)))

    def get_metrics(self) -> bytes:
        with self._lock:
            return self._metrics_bytes

    def stop(self):
        self._running = False

# ── HTTP server ───────────────────────────────────────────────────────────────

_collector = NetworkCollector()

class MetricsHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  

    def do_GET(self):
        if self.path == "/metrics":
            data = _collector.get_metrics()
            self.send_response(200)
            self.send_header("Content-Type",
                             "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/health":
            age = time.time() - _collector._last_ok_ts
            ok  = age < _collector.interval * 3
            self.send_response(200 if ok else 503)
            self.end_headers()
            self.wfile.write(b"OK\n" if ok else b"STALE\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found\n")

def main():
    try:
        adb_path = _adb_path()
        log.info("Using adb: %s", adb_path)
    except FileNotFoundError as exc:
        log.critical(str(exc))
        raise SystemExit(1)

    check = subprocess.run(
        [adb_path, "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    log.info("ADB devices:\n%s", check.stdout.decode().strip())

    t = Thread(target=_collector.run_loop, daemon=True, name="collector")
    t.start()

    log.info("Waiting for first collection (up to %ds)…", SCRAPE_INTERVAL)
    deadline = time.time() + SCRAPE_INTERVAL + 5
    while _collector._last_ok_ts == 0 and time.time() < deadline:
        time.sleep(0.5)

    server = HTTPServer(("0.0.0.0", EXPORTER_PORT), MetricsHandler)
    log.info("Exporter ready → http://0.0.0.0:%d/metrics", EXPORTER_PORT)
    log.info("Health check  → http://0.0.0.0:%d/health",   EXPORTER_PORT)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down…")
        _collector.stop()

if __name__ == "__main__":
    main()