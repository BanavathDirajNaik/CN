# 📡 Real-Time Network Data Analyzer

Per-app network monitoring for Android devices, visualised in Grafana.

```
Android Device (ADB)
      ↓
exporter.py  ← collects RX/TX + TCP connections every 15 s
      ↓  :8000/metrics
Prometheus   ← scrapes & stores time-series
      ↓
Grafana      ← beautiful real-time dashboards
```

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Python ≥ 3.10 | Run the exporter |
| Android Platform Tools (`adb`) | Talk to the device |
| Docker + Docker Compose | Run Prometheus & Grafana |

---

## Quick Start

### 1 — Enable ADB on your Android phone
Settings → Developer Options → USB Debugging → ON  
Plug in via USB (or use wireless ADB).

```bash
adb devices          # verify the device shows up
```

### 2 — Start the Python exporter (on your PC/laptop)

```bash
# clone / unzip this project, then:
pip install -r requirements.txt
python exporter.py
```

You should see:
```
12:00:00  INFO     Using adb: /usr/bin/adb
12:00:00  INFO     Collection loop started (interval=15s)
12:00:15  INFO     Scrape #1 complete — 42 kB in 9.3s
12:00:15  INFO     Exporter ready → http://0.0.0.0:8000/metrics
```

Test it:
```bash
curl http://localhost:8000/metrics | head -30
```

### 3 — Start Prometheus + Grafana

```bash
docker compose up -d
```

| Service    | URL                      | Credentials |
|------------|--------------------------|-------------|
| Grafana    | http://localhost:3000    | admin / admin |
| Prometheus | http://localhost:9090    | — |

### 4 — Open the Dashboard

Grafana → Dashboards → **📡 Real-Time Network Data Analyzer**

The dashboard auto-provisions on first launch.  
Set the refresh to **15s** (top-right) if not already active.

---

## Dashboard Panels

| Panel | What it shows |
|-------|--------------|
| **Total Download / Upload Rate** | Device-wide bandwidth (bytes/s) |
| **Active TCP Connections** | Count of current connections |
| **Download Rate by App** | Time-series, top 8 apps |
| **Upload Rate by App** | Time-series, top 8 apps |
| **Combined Traffic (Stacked)** | RX + TX stacked bar chart |
| **Top 10 by Download / Upload** | Bar gauges, current snapshot |
| **RX / TX Share Donuts** | Proportional traffic breakdown |
| **TCP States Distribution** | Pie: ESTABLISHED / TIME_WAIT / … |
| **ESTABLISHED Connections** | Per-app connection count over time |
| **All Active Connections** | Filterable table with full detail |
| **Top Destination IPs** | Which servers get the most connections |
| **Connections by Port** | 443 / 80 / 5222 / … breakdown |

---

## Key Prometheus Queries

```promql
# Download rate for a specific app
irate(app_rx_bytes{app="com.android.chrome"}[2m])

# Top 5 uploaders right now
topk(5, sum by (app) (irate(app_tx_bytes[2m])))

# All ESTABLISHED connections
app_connections{state="ESTABLISHED"}

# Connections going to port 443
app_connections{rem_port="443"}

# Total device bandwidth
sum(irate(app_rx_bytes[2m])) + sum(irate(app_tx_bytes[2m]))
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EXPORTER_PORT` | `8000` | HTTP port for `/metrics` |
| `SCRAPE_INTERVAL` | `15` | How often to poll the device (seconds) |
| `ADB_TIMEOUT` | `12` | Per-command ADB timeout (seconds) |
| `MAX_FD_SCAN_PIDS` | `60` | How many PIDs to scan for inode→PID mapping |

---

## Data Sources (in priority order)

1. **`/proc/net/xt_qtaguid/stats`** — Android's per-UID traffic counters (most accurate, requires root or system permissions).
2. **`/proc/uid_stat/<uid>/tcp_rcv|tcp_snd`** — UID-level TCP byte counters (no root needed on most devices).
3. **`/proc/<pid>/net/dev`** — Interface-level stats (device-wide, used as last resort).

---

## Project Structure

```
network_analyzer/
├── exporter.py                            ← Python Prometheus exporter
├── prometheus.yml                         ← Prometheus scrape config
├── docker-compose.yml                     ← Prometheus + Grafana stack
├── requirements.txt
├── README.md
└── grafana/
    └── provisioning/
        ├── datasources/prometheus.yml     ← auto-add Prometheus datasource
        └── dashboards/
            ├── dashboard.yml              ← dashboard loader config
            └── network_analyzer.json      ← the dashboard itself
```

---

## Troubleshooting

**No metrics / empty graphs**
- Run `adb devices` — device must be listed as `device` (not `unauthorized`).
- Accept the "Allow USB debugging" prompt on the phone.
- Check `curl http://localhost:8000/health` returns `OK`.

**All apps show the same RX/TX value**
- Your device doesn't support `xt_qtaguid` without root.  
  The exporter falls back to `/proc/<pid>/net/dev` which is device-wide.  
  Grant root to ADB (`adb root`) for accurate per-app data.

**Grafana shows "No data"**
- Verify Prometheus is scraping: http://localhost:9090/targets  
  The `android_network` target should be green.
- Check the time range in Grafana (top-right) — set to **Last 15 minutes**.

**Slow scrapes / timeouts**
- Reduce `MAX_FD_SCAN_PIDS` (e.g. `export MAX_FD_SCAN_PIDS=20`).
- Increase `ADB_TIMEOUT` if the device is over Wi-Fi.
