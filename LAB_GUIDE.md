# Public WiFi Risk Detector — Lab Setup Guide 🧪

This guide covers the full stack: real detection (Live Mode) + educational simulations (Simulation Mode).

---

## 1. Prerequisites

### All Platforms
- Python ≥ 3.9 and Node.js ≥ 18
- Install Python dependencies: `pip install -r backend/requirements.txt`
- Install frontend dependencies: `cd frontend && npm install`

### Windows
- [Npcap](https://npcap.com/) — required for Scapy ARP scanning
- Run backend **as Administrator** for ARP live-sniff (`sniff()`)
  > Without admin rights, the detector falls back to polling-based ARP checks automatically.

### Linux
- `iproute2` / `iw` / `nmcli` (usually pre-installed)
- Run with `sudo` for Scapy ARP sniffing, or grant cap_net_raw: `sudo setcap cap_net_raw+eip $(which python3)`

### macOS
- `airport` utility (included in macOS)
- Run with `sudo` for Scapy sniffing

---

## 2. Running the Project

### Step 1 — Backend

```bash
cd backend
python app.py
```

On first run it will **auto-generate an API token** and print it:
```
Generated new API token: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Saved to backend/.env
Set VITE_API_TOKEN=<token> in frontend/.env
```

### Step 2 — Frontend

Create `frontend/.env` with the token from above:
```
VITE_API_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Then start the dev server:
```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 3. Understanding the Two Modes

| | **Live Detection Mode** | **Simulation Mode** |
|---|---|---|
| **What runs** | Real network checks | Demo overlay only |
| **Alerts** | Actual anomalies found | Educational examples |
| **Risk score** | `live_risk_score` | `sim_risk_score` |
| **UI indicator** | 🟢 Green banner | 🟡 Amber dashed banner |
| **Use case** | Real network monitoring | Teaching / demo |

> **Key difference from the original design:** Real checks and simulations run in **separate layers**. Activating a scenario does NOT disable live detection. Both scores are tracked independently.

---

## 4. Live Detection Checks

### Check 1 — Open Network (+40)
Detects when the connected network has no encryption (Open/None).

**Lab setup**: Set your router/hotspot to Open (no security). The backend will detect it automatically without any simulation.

### Check 2 — Evil Twin (+35)
Passive scan of nearby APs. Flags when multiple BSSIDs advertise the same SSID as your connected network.

**Lab setup** (Kali Linux):
```bash
airgeddon   # or
wifiphisher --essid "YourNetworkSSID"
```
Detection uses `netsh wlan show networks mode=bssid` (Windows) or `nmcli dev wifi list` (Linux/macOS) — **no monitor mode required**.

### Check 3 — ARP Spoofing / MITM (+50)
- **Primary**: Scapy live ARP sniff — tracks every IP→MAC mapping on the wire; flags any MAC change for a known IP.
- **Fallback**: Polling-based gateway MAC comparison every 3 s.

**Lab setup** (Kali Linux):
```bash
sudo arpspoof -i eth0 -t <Host_IP> <Gateway_IP>
sudo arpspoof -i eth0 -t <Gateway_IP> <Host_IP>
```

### Check 4 — DNS Spoofing (+30)
Resolves `google.com` and `cloudflare.com` every ~30 seconds. Compares against known-good IP CIDR ranges (Google AS, Cloudflare AS). Flags IPs outside these ranges.

**Lab setup** (requires control of DNS server):
```bash
# On attacker machine, run dnsspoof or use dnsmasq with spoofed entries
dnsspoof -i eth0 -f /tmp/hosts.txt
```

### Check 5 — SSL Stripping / Captive Portal (+40)
Makes an HTTPS request to Google's `generate_204` endpoint. Flags:
- Redirect to HTTP → SSL stripping
- Non-204 response → captive portal
- TLS error → self-signed cert or MITM

**Lab setup**:
```bash
# Using sslstrip on attacker machine:
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

---

## 5. Simulation Scenarios (Lab Demonstrations)

> [!WARNING]
> Simulation mode injects **educational demo data only**. Alerts tagged `[SIM]` are NOT real detections. The UI shows a clear amber banner while a simulation is active.

Access the **🧪 Lab Simulation Panel** at the bottom of the dashboard.

| Scenario | What it teaches |
|---|---|
| **Open WiFi** | Impact of unencrypted networks |
| **Evil Twin AP** | Rogue AP / BSSID spoofing |
| **ARP Spoof/MITM** | Gateway MAC hijacking |
| **DNS Spoof** | Rogue DNS resolver attack |
| **SSL Strip** | HTTPS downgrade attack |

To trigger programmatically (requires the API token in the `X-API-Token` header):
```bash
curl -X POST http://localhost:5000/api/scenario \
  -H "Content-Type: application/json" \
  -H "X-API-Token: YOUR_TOKEN_HERE" \
  -d '{"scenario": "evil_twin"}'
```

---

## 6. SQLite History & API

Risk events are logged to `backend/risk_history.db` every ~15 seconds.

| Endpoint | Description |
|---|---|
| `GET /api/status` | Live status, check results, sim state |
| `GET /api/history?limit=100` | Last N risk events from SQLite |
| `GET /api/stats` | 24-hour aggregate (max, avg, high-risk count) |
| `GET /api/config` | Current notification / sniff config |
| `POST /api/config` *(token required)* | Update webhook URL, notification interval |
| `POST /api/scenario` *(token required)* | Trigger or reset a simulation scenario |

---

## 7. Real Alerting

### Desktop Notifications
Fires automatically when risk crosses a threshold zone (30, 60, 90) or jumps ≥10 points. Powered by `plyer` — no configuration needed.

### Webhook (Discord / Slack / Custom)
Set your webhook URL via the API:
```bash
curl -X POST http://localhost:5000/api/config \
  -H "X-API-Token: YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://discord.com/api/webhooks/..."}'
```

Or set the environment variable before starting the backend:
```bash
ALERT_WEBHOOK_URL=https://... python app.py
```

---

## 8. Academic Disclaimer

All experiments must be conducted in an **isolated lab environment** using networks and devices you own or have explicit permission to test. Unauthorised network access is illegal and unethical. This tool is built for **detection education and VAPT training** only.
