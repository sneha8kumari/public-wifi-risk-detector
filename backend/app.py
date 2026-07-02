"""
app.py — Flask API server for the Public WiFi Risk Detector.

Endpoints
---------
GET  /api/status      — live status, simulation state, check results
GET  /api/history     — last 100 risk events from SQLite
GET  /api/stats       — 24-hour aggregate statistics
GET  /api/config      — current notification config
POST /api/config      — update webhook URL / alert thresholds
POST /api/scenario    — trigger a simulation scenario (requires X-API-Token)
"""

import os
import uuid
import logging
from functools import wraps
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
import tempfile

from detector import WiFiDetector
from notifier import NotificationManager
from db import init_db, log_event, get_history, get_stats
from capture_analyzer import parse_airodump_csv, parse_pcap

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Load / generate API token ──────────────────────────────────────────────
_env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(_env_path)

API_TOKEN = os.getenv("API_TOKEN", "")
if not API_TOKEN:
    API_TOKEN = str(uuid.uuid4())
    with open(_env_path, "a") as f:
        f.write(f"\nAPI_TOKEN={API_TOKEN}\n")
    logger.info("=" * 60)
    logger.info("Generated new API token: %s", API_TOKEN)
    logger.info("Saved to %s", _env_path)
    logger.info("Set VITE_API_TOKEN=%s in frontend/.env", API_TOKEN)
    logger.info("=" * 60)
else:
    logger.info("Loaded API token from .env")

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)

# Restrict CORS to the Vite dev server and localhost in general.
# In production, replace with your actual frontend origin.
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]}})

# ── Initialise subsystems ──────────────────────────────────────────────────
init_db()

notifier = NotificationManager(webhook_url=os.getenv("ALERT_WEBHOOK_URL", ""))

detector = WiFiDetector()
detector.set_notifier(notifier)
detector.start_monitoring()

# How often (in detector cycles) we log to DB — every 5th poll = ~15 s
_log_counter = 0
_LOG_EVERY = 5

# ── Auth decorator ─────────────────────────────────────────────────────────

def require_token(f):
    """Reject requests that don't supply the correct X-API-Token header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-API-Token", "")
        if token != API_TOKEN:
            logger.warning(
                "Unauthorised /api/scenario attempt from %s",
                request.remote_addr,
            )
            return jsonify({"status": "error", "message": "Unauthorised"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def get_status():
    global _log_counter
    status = detector.get_status()

    # Persist to SQLite periodically (not every 3 s to avoid excessive I/O)
    _log_counter += 1
    if _log_counter >= _LOG_EVERY:
        _log_counter = 0
        try:
            log_event(
                risk_score=status["live_risk_score"],
                sim_risk_score=status["sim_risk_score"],
                alerts=status["alerts"],
                network_info=status["network"],
                mode=status["mode"],
            )
        except Exception as exc:
            logger.error("DB log failed: %s", exc)

    return jsonify(status)


@app.route("/api/history", methods=["GET"])
def get_event_history():
    limit = min(int(request.args.get("limit", 100)), 500)
    return jsonify(get_history(limit))


@app.route("/api/stats", methods=["GET"])
def get_risk_stats():
    return jsonify(get_stats())


@app.route("/api/config", methods=["GET"])
def get_config():
    return jsonify({
        "webhook_url": notifier.webhook_url,
        "min_notification_interval_s": notifier.min_interval,
        "platform": detector.get_status()["platform"],
        "scapy_available": detector.get_status()["scapy_available"],
        "arp_sniff_active": detector.get_status()["arp_sniff_active"],
    })


@app.route("/api/config", methods=["POST"])
@require_token
def update_config():
    data = request.get_json(silent=True) or {}
    if "webhook_url" in data:
        notifier.update_webhook(data["webhook_url"])
    if "min_notification_interval_s" in data:
        try:
            notifier.min_interval = max(10, int(data["min_notification_interval_s"]))
        except (ValueError, TypeError):
            pass
    return jsonify({"status": "ok"})


@app.route("/api/scenario", methods=["POST"])
@require_token
def trigger_scenario():
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario")
    valid_scenarios = {"open", "evil_twin", "mitm", "dns", "ssl", "reset"}
    if scenario not in valid_scenarios:
        return jsonify({
            "status": "error",
            "message": f"Unknown scenario. Valid: {sorted(valid_scenarios)}"
        }), 400
    detector.set_scenario(scenario)
    logger.info("Scenario '%s' triggered by %s", scenario, request.remote_addr)
    return jsonify({"status": "success", "scenario": scenario})


app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # Cap uploads at 25MB

@app.route("/api/upload/airodump-csv", methods=["POST"])
@require_token
def upload_airodump_csv():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part in request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400
    try:
        file_bytes = file.read()
        result = parse_airodump_csv(file_bytes)
        detector.apply_capture_analysis(result, source="airodump-csv")
        return jsonify({"status": "success", "result": result})
    except Exception as exc:
        logger.error("Error parsing CSV: %s", exc)
        return jsonify({"status": "error", "message": f"Error parsing CSV: {exc}"}), 400

@app.route("/api/upload/pcap", methods=["POST"])
@require_token
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part in request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No selected file"}), 400
    
    # Save to a temporary file
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"upload_{uuid.uuid4().hex}.pcap")
    try:
        file.save(temp_path)
        result = parse_pcap(temp_path)
        detector.apply_capture_analysis(result, source="pcap")
        return jsonify({"status": "success", "result": result})
    except Exception as exc:
        logger.error("Error parsing PCAP: %s", exc)
        return jsonify({"status": "error", "message": f"Error parsing PCAP: {exc}"}), 400
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


# ── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
