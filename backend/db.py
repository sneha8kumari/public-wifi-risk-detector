"""
db.py — SQLite persistence layer for risk event logging.

Creates and manages the risk_history.db file in the backend directory.
Table schema: id, timestamp, risk_score, alerts_json, network_ssid, sim_risk_score, mode
"""

import sqlite3
import json
import os
import time
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "risk_history.db")


def get_connection():
    """Return a thread-safe SQLite connection."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the risk_events table if it does not already exist."""
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS risk_events (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      TEXT    NOT NULL,
                epoch          REAL    NOT NULL,
                risk_score     INTEGER NOT NULL,
                sim_risk_score INTEGER NOT NULL DEFAULT 0,
                mode           TEXT    NOT NULL DEFAULT 'live',
                alerts_json    TEXT    NOT NULL DEFAULT '[]',
                network_ssid   TEXT    NOT NULL DEFAULT '',
                network_bssid  TEXT    NOT NULL DEFAULT '',
                encryption     TEXT    NOT NULL DEFAULT ''
            )
        """)
        # Index on epoch for fast range queries
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_epoch ON risk_events (epoch)
        """)
        conn.commit()
    finally:
        conn.close()


def log_event(risk_score: int, sim_risk_score: int, alerts: list,
              network_info: dict, mode: str):
    """
    Insert one risk event row.

    Parameters
    ----------
    risk_score      : live detection risk score (0-100)
    sim_risk_score  : simulation overlay score (0 when no scenario active)
    alerts          : list of alert strings
    network_info    : dict with ssid, bssid, encryption, etc.
    mode            : 'live' | 'simulation' | 'both'
    """
    now = datetime.utcnow()
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO risk_events
                (timestamp, epoch, risk_score, sim_risk_score, mode,
                 alerts_json, network_ssid, network_bssid, encryption)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now.isoformat(),
            time.time(),
            int(risk_score),
            int(sim_risk_score),
            mode,
            json.dumps(alerts),
            network_info.get("ssid", ""),
            network_info.get("bssid", ""),
            network_info.get("encryption", ""),
        ))
        conn.commit()
    finally:
        conn.close()


def get_history(limit: int = 100) -> list:
    """
    Return the most recent `limit` events, newest-last (ascending epoch).

    Returns a list of dicts ready for JSON serialisation.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT id, timestamp, epoch, risk_score, sim_risk_score,
                   mode, alerts_json, network_ssid, encryption
            FROM risk_events
            ORDER BY epoch DESC
            LIMIT ?
        """, (limit,)).fetchall()
    finally:
        conn.close()

    events = []
    for row in reversed(rows):        # flip back to ascending order
        events.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "epoch": row["epoch"],
            "risk_score": row["risk_score"],
            "sim_risk_score": row["sim_risk_score"],
            "mode": row["mode"],
            "alerts": json.loads(row["alerts_json"]),
            "ssid": row["network_ssid"],
            "encryption": row["encryption"],
        })
    return events


def get_stats() -> dict:
    """Return aggregate stats: max, avg risk over last 24 h."""
    conn = get_connection()
    try:
        cutoff = time.time() - 86400
        row = conn.execute("""
            SELECT
                COUNT(*)          AS total_events,
                MAX(risk_score)   AS max_risk,
                AVG(risk_score)   AS avg_risk,
                SUM(CASE WHEN risk_score >= 60 THEN 1 ELSE 0 END) AS high_risk_events
            FROM risk_events
            WHERE epoch >= ?
        """, (cutoff,)).fetchone()
    finally:
        conn.close()

    if row:
        return {
            "total_events_24h": row["total_events"] or 0,
            "max_risk_24h": row["max_risk"] or 0,
            "avg_risk_24h": round(row["avg_risk"] or 0, 1),
            "high_risk_events_24h": row["high_risk_events"] or 0,
        }
    return {"total_events_24h": 0, "max_risk_24h": 0,
            "avg_risk_24h": 0, "high_risk_events_24h": 0}
