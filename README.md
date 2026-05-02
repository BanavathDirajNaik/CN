# 📡 Real-Time Network Data Analyzer

Per-app network monitoring for Android devices — **no root required** — visualised live in Grafana.

```
Android Device (ADB)
      ↓  dumpsys netstats + /proc/net/tcp + pm list packages + ps -A
exporter.py  ←  collects RX/TX + TCP connections every 30 s
      ↓  :8000/metrics  (Prometheus text format)
Prometheus   ←  scrapes & stores time-series
      ↓
Grafana      ←  real-time dashboards, auto-provisioned
```

---

## Project Structure

```
network_analyzer/
├── exporter.py                                   ← Python Prometheus exporter
├── prometheus.yml                                ← Prometheus scrape config
├── docker-compose.yml                            ← Prometheus + Grafana stack
├── requirements.txt
├── README.md
├── platform-tools/
│   └── adb                                       ← bundled Android Platform Tools
└── grafana/
    ├── provisioning/
    │   └── datasources/prometheus.yml            ← auto-adds Prometheus datasource
    └── dashboards/
        ├── dashboard.yml                         ← dashboard loader config
        └── network_analyzer.json                 ← the full dashboard
```

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Python ≥ 3.10 | Run the exporter |
| Android device with USB Debugging ON | Data source |
| Docker + Docker Compose | Run Prometheus & Grafana |

`adb` is bundled in `platform-tools/` — no separate install needed.

---

## Quick Start

### 1 — Enable USB Debugging on your phone

Settings → Developer Options → USB Debugging → **ON**  
Plug in via USB and accept the "Allow USB debugging" prompt.

```bash
./platform-tools/adb devices
# Should show:  <serial>   device
```

### 2 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3 — Start the exporter

```bash
python exporter.py
```

Expected output:
```
12:00:00  INFO     Using adb: ./platform-tools/adb
12:00:00  INFO     ADB devices:
                   List of devices attached
                   ZY322XXXXX   device
12:00:00  INFO     Collection loop started (interval=30s)
12:00:30  INFO     Scrape #1 complete — 58 kB in 14.2s
12:00:30  INFO     Exporter ready → http://0.0.0.0:8000/metrics
12:00:30  INFO     Health check  → http://0.0.0.0:8000/health
```

Verify metrics are being served:
```bash
curl http://localhost:8000/metrics | head -40
```

### 4 — Start Prometheus + Grafana

```bash
docker compose up -d
```

| Service    | URL                   | Credentials |
|------------|-----------------------|-------------|
| Grafana    | http://localhost:3000 | admin / admin |
| Prometheus | http://localhost:9090 | — |

### 5 — Open the Dashboard

Grafana → Dashboards → **📡 Real-Time Network Data Analyzer**

The dashboard auto-provisions on first launch. Set the time range to **Last 15 minutes** and the refresh to **15s** (top-right corner).

---

## How the Exporter Works

The exporter runs a background thread that fires four ADB commands every 30 seconds, then caches the result. The HTTP server just returns the cached text instantly on every `/metrics` request.

### Step 1 — Process & UID discovery (`ps -A`)

```python
def get_process_maps() -> tuple[dict, dict, dict]:
```

Runs `adb shell ps -A` and parses three maps out of a single pass:

- `pid_app` — `{pid: app_name}` for every running process
- `uid_app` — `{uid: app_name}` by converting Android user strings to numeric UIDs
- `uid_pid` — `{uid: pid}` mapping a UID to its representative PID

Android user strings like `u0_a123` encode the UID using the formula:

```
u<user>_a<id>  →  uid = user*100000 + 10000 + id   (regular apps)
u<user>_i<id>  →  uid = user*100000 + 90000 + id   (isolated sandboxes)
```

So `u0_a89` → UID `10089`, which is exactly what Android uses internally.

### Step 2 — Package name lookup (`pm list packages -U`)

```python
def get_uid_package_map() -> dict:
```

Runs `adb shell pm list packages -U` which returns every installed package with its official UID. This gives the most accurate app name (e.g. `com.google.android.youtube` rather than a truncated `ps` name).

A master UID map is then built in priority order:
1. Hardcoded system UIDs (1000 = `android.system`, 1001 = `android.phone`, etc.)
2. `pm list packages -U` results
3. `ps -A` derived UIDs (fills gaps for kernel threads and transient processes)

### Step 3 — Bandwidth stats (`dumpsys netstats --uid`)

```python
def get_app_usage_from_dumpsys() -> dict:
```

Runs `adb shell dumpsys netstats --uid` — Android's built-in per-UID network statistics service. This is the **no-root** replacement for `/proc/net/xt_qtaguid/stats`. It parses `rb=` (received bytes) and `tb=` (transmitted bytes) fields per UID and accumulates them as counters since device boot.

Results are sorted by total traffic (rx + tx) descending before being emitted as metrics, so Prometheus always sees the most active apps first.

### Step 4 — TCP connection mapping (`/proc/net/tcp`)

```python
def get_connections(final_uid_map, uid_pid_map) -> list:
```

Reads `/proc/net/tcp` and `/proc/net/tcp6`. The key insight is that **column index 7 in the tcp file is the UID of the socket owner** — so connection-to-app mapping requires zero root, zero fd scanning, and zero inode lookups. Each connection is resolved instantly:

```
/proc/net/tcp column layout:
  [0] slot  [1] local_addr  [2] rem_addr  [3] state  ...  [7] uid  [9] inode
```

Local and remote addresses are stored as little-endian hex (e.g. `0101A8C0:01BB`) and decoded to dotted-decimal IP + decimal port.

---

## Metrics Reference

All metrics are served at `http://localhost:8000/metrics` in Prometheus text format.

### `app_rx_bytes` (counter)

Cumulative bytes received by each app since device boot, labelled by `app`, `uid`, and `source`.

```
app_rx_bytes{app="com.google.android.youtube",uid="10089",source="dumpsys"} 5878156905
app_rx_bytes{app="com.whatsapp",uid="10201",source="dumpsys"} 2341892
```

### `app_tx_bytes` (counter)

Cumulative bytes transmitted (uploaded) by each app since device boot.

```
app_tx_bytes{app="com.google.android.youtube",uid="10089",source="dumpsys"} 312940
```

### `app_connections` (gauge)

One entry per active TCP connection, value always `1`. Labels carry the full 5-tuple plus app name and state.

```
app_connections{app="com.android.chrome",pid="14760",proto="tcp",local_ip="192.168.1.5",local_port="52234",rem_ip="142.250.80.46",rem_port="443",state="ESTABLISHED"} 1
app_connections{app="com.whatsapp",pid="20752",proto="tcp",local_ip="192.168.1.5",local_port="45242",rem_ip="140.56.108.91",rem_port="5222",state="ESTABLISHED"} 1
```

### `network_exporter_active_processes` (gauge)

Total number of processes found by `ps -A` on the last scrape.

### `network_exporter_last_scrape_timestamp_seconds` (gauge)

Unix timestamp of the last successful collection cycle. Used by the `/health` endpoint and the "Last Scrape Age" dashboard panel.

---

## HTTP Endpoints

| Endpoint | Returns |
|----------|---------|
| `/metrics` | All metrics in Prometheus text format (cached, instant response) |
| `/health` | `200 OK` if last scrape was < 90 s ago, `503 STALE` if the collector has stopped updating |

The health endpoint uses this logic:
```python
age = time.time() - _collector._last_ok_ts
ok  = age < _collector.interval * 3   # 30 * 3 = 90 seconds
```

If `adb` disconnects or the phone is unplugged, `_last_ok_ts` stops updating. After 90 seconds, `/health` returns `503 STALE` to signal that the cached metrics are too old to trust.

---

## Dashboard Panels

The dashboard is organised into five collapsible rows.

### 📡 Overview (3 stat panels)

| Panel | Query | What it shows |
|-------|-------|---------------|
| ⬇ Total Download Rate | `sum(irate(app_rx_bytes[2m]))` | Device-wide RX in bytes/s, colour-coded green → yellow (1 MB/s) → red (10 MB/s) |
| ⬆ Total Upload Rate | `sum(irate(app_tx_bytes[2m]))` | Device-wide TX in bytes/s, colour-coded green → yellow (512 KB/s) → red (5 MB/s) |
| 🖥 Monitored Processes | `network_exporter_active_processes` | Count of all processes found by `ps -A` |

### 📊 Live Traffic (2 time-series + 1 stacked bar)

| Panel | Query | What it shows |
|-------|-------|---------------|
| ⬇ Download Rate by App | `topk(8, sum by (app)(irate(app_rx_bytes[2m])) > 0)` | Smooth line chart of the top 8 downloading apps in real time |
| ⬆ Upload Rate by App | `topk(8, sum by (app)(irate(app_tx_bytes[2m])) > 0)` | Same for upload |
| 📶 Combined RX + TX (Stacked Bars) | Both of the above combined | All traffic in one stacked bar view; makes it easy to see which apps dominate total bandwidth |

### 🏆 Top App Rankings (2 bar gauges + 2 donuts)

| Panel | What it shows |
|-------|---------------|
| ⬇ Top 10 by Download | Horizontal gradient bar gauge; longest bar = highest current download rate |
| ⬆ Top 10 by Upload | Same for upload |
| 🍩 RX Share Donut | Proportional slice per app; shows which app is responsible for what percentage of total download |
| 🍩 TX Share Donut | Same for upload |

### 📱 Popular Apps (6 individual time-series panels)

Dedicated RX + TX line charts for six commonly used apps, one panel each:

- **YouTube** — `com.google.android.youtube`
- **Spotify** — `com.spotify.music`
- **WhatsApp** — `com.whatsapp`
- **Instagram** — `com.instagram.android`
- **Facebook** — `com.facebook.katana`
- **Chrome** — `com.android.chrome*` (regex matches main process + sandboxed subprocesses)

Each panel shows both RX (download, e.g. streaming) and TX (upload, e.g. sending messages) on the same graph. If an app is not installed on the device, its panel simply shows no data.

### 🕵️ Active Connections & Destinations (1 large table)

A fully filterable table of every active TCP connection, with human-readable column names:

| Column | Source |
|--------|--------|
| Application | Resolved from UID via `final_uid_map` |
| PID | From `uid_pid_map` |
| Protocol | `tcp` or `tcp6` |
| Local IP / Local Port | Decoded from `/proc/net/tcp` hex |
| Remote IP / Remote Port | Decoded from `/proc/net/tcp` hex |
| State | Decoded from hex (01 → ESTABLISHED, 06 → TIME_WAIT, etc.) |

The State column has colour-coded backgrounds: green for ESTABLISHED, yellow for TIME_WAIT, orange for CLOSE_WAIT, blue for SYN_SENT, purple for LISTEN. Click any column header to sort. Use the search box to filter by app name or IP.

---

## Key PromQL Queries

```promql
# Current download rate for a specific app
irate(app_rx_bytes{app="com.google.android.youtube"}[2m])

# Top 5 uploaders right now
topk(5, sum by (app) (irate(app_tx_bytes[2m])))

# All ESTABLISHED connections
app_connections{state="ESTABLISHED"}

# All connections to HTTPS
app_connections{rem_port="443"}

# All connections made by WhatsApp
app_connections{app="com.whatsapp"}

# Total device bandwidth (download + upload)
sum(irate(app_rx_bytes[2m])) + sum(irate(app_tx_bytes[2m]))

# Scrape freshness (should stay under 90 s)
time() - network_exporter_last_scrape_timestamp_seconds
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EXPORTER_PORT` | `8000` | HTTP port for `/metrics` and `/health` |
| `SCRAPE_INTERVAL` | `30` | Seconds between device polls |
| `ADB_TIMEOUT` | `12` | Per-ADB-command timeout in seconds |

Example — faster scraping over a fast USB connection:
```bash
SCRAPE_INTERVAL=15 python exporter.py
```

---

## Troubleshooting

**`adb devices` shows `unauthorized`**  
Unlock your phone screen and accept the "Allow USB debugging" dialog.

**No metrics / empty graphs in Grafana**  
Check Prometheus targets: http://localhost:9090/targets — the `android_network` job must show State = UP.  
Also check: `curl http://localhost:8000/health` should return `OK`.
