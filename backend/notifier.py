"""
notifier.py — Desktop toast and webhook alerting for the WiFi Risk Detector.

Provides a NotificationManager that debounces repeated notifications and
fires only when the risk score meaningfully changes (crosses a threshold
boundary or increases by ≥10 points).

Dependencies: plyer, requests (already in requirements.txt)
"""

import threading
import time
import logging
import os

logger = logging.getLogger(__name__)

# Risk threshold zones
THRESHOLDS = [30, 60, 90]


def _zone(score: int) -> int:
    """Map a score to its threshold zone index (0=safe, 1=med, 2=high, 3=crit)."""
    for i, t in enumerate(THRESHOLDS):
        if score < t:
            return i
    return len(THRESHOLDS)


def send_desktop_notification(title: str, message: str):
    """
    Send a desktop toast notification via plyer.
    Silently no-ops if plyer is not installed or the platform doesn't
    support it (e.g., a headless server).
    """
    try:
        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            app_name="WiFi Risk Detector",
            timeout=8,
        )
    except Exception as exc:
        logger.debug("Desktop notification unavailable: %s", exc)


def send_webhook(url: str, payload: dict):
    """
    POST a JSON payload to the given webhook URL.
    Compatible with Discord, Slack incoming webhooks, and generic HTTP endpoints.
    """
    if not url:
        return
    try:
        import requests
        # Discord expects {"content": "..."}, Slack expects {"text": "..."}
        # We send a generic payload that wraps both fields.
        data = {
            "content": payload.get("message", ""),
            "text": payload.get("message", ""),
            "embeds": [{
                "title": payload.get("title", "WiFi Risk Alert"),
                "description": payload.get("message", ""),
                "color": 0xf85149 if payload.get("risk_score", 0) >= 60 else 0xd29922,
                "fields": [
                    {"name": "Risk Score", "value": str(payload.get("risk_score", 0)), "inline": True},
                    {"name": "SSID", "value": payload.get("ssid", "Unknown"), "inline": True},
                    {"name": "Mode", "value": payload.get("mode", "live"), "inline": True},
                ],
            }],
        }
        requests.post(url, json=data, timeout=5)
    except Exception as exc:
        logger.warning("Webhook delivery failed: %s", exc)


class NotificationManager:
    """
    Tracks the last-notified risk zone and fires notifications only when:
      - The risk zone changes (e.g., safe → medium, medium → high), or
      - The risk score increases by ≥ 10 within the same zone.

    Notifications are debounced with a minimum interval of 60 seconds.
    """

    def __init__(self, webhook_url: str = ""):
        self.webhook_url = webhook_url or os.getenv("ALERT_WEBHOOK_URL", "")
        self._last_zone = 0
        self._last_score = 0
        self._last_fired = 0.0
        self._lock = threading.Lock()
        self.min_interval = 60  # seconds between notifications

    def update_webhook(self, url: str):
        with self._lock:
            self.webhook_url = url

    def check_and_notify(self, risk_score: int, alerts: list, ssid: str, mode: str):
        """
        Called on every detector cycle. Fires a notification if thresholds are crossed.
        """
        with self._lock:
            now = time.time()
            current_zone = _zone(risk_score)
            score_jumped = (risk_score - self._last_score) >= 10
            zone_changed = current_zone > self._last_zone
            cooldown_ok = (now - self._last_fired) >= self.min_interval

            if not cooldown_ok:
                return

            should_fire = zone_changed or (score_jumped and current_zone >= 1)
            if not should_fire:
                return

            # Build notification content
            zone_labels = {0: "Safe", 1: "⚠️ Medium Risk", 2: "🔴 High Risk", 3: "🚨 Critical Risk"}
            label = zone_labels.get(current_zone, "Unknown")
            top_alert = alerts[0] if alerts else "Risk level elevated"
            title = f"WiFi Risk Detector — {label}"
            message = f"Score: {risk_score}/100 | SSID: {ssid}\n{top_alert}"

            # Fire in background so we don't block the detector thread
            threading.Thread(
                target=self._fire,
                args=(title, message, risk_score, ssid, mode),
                daemon=True,
            ).start()

            self._last_zone = current_zone
            self._last_score = risk_score
            self._last_fired = now

    def _fire(self, title: str, message: str, risk_score: int, ssid: str, mode: str):
        send_desktop_notification(title, message)
        if self.webhook_url:
            send_webhook(self.webhook_url, {
                "title": title,
                "message": message,
                "risk_score": risk_score,
                "ssid": ssid,
                "mode": mode,
            })
