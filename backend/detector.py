import subprocess
import re
import time
import threading
from scapy.all import ARP, Ether, srp
import psutil

class WiFiDetector:
    def __init__(self):
        self.risk_score = 0
        self.alerts = []
        self.current_network = {
            "ssid": "Scanning...",
            "bssid": "Scanning...",
            "encryption": "Scanning...",
            "gateway_ip": "Scanning...",
            "gateway_mac": "Scanning...",
            "channel": "Unknown",
            "signal": "Unknown",
            "dns": "Unknown",
            "subnet": "Unknown"
        }
        self.gateway_mac_history = []
        self.stop_thread = False
        self.demo_mode = False
        self.active_scenario = None

    def get_network_info(self):
        try:
            # Try to get real info
            output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
            
            ssid_match = re.search(r"SSID\s+:\s+(.+)", output)
            bssid_match = re.search(r"BSSID\s+:\s+(.+)", output)
            auth_match = re.search(r"Authentication\s+:\s+(.+)", output)
            channel_match = re.search(r"Channel\s+:\s+(.+)", output)
            signal_match = re.search(r"Signal\s+:\s+(.+)", output)
            
            if ssid_match: self.current_network["ssid"] = ssid_match.group(1).strip()
            if bssid_match: self.current_network["bssid"] = bssid_match.group(1).strip()
            if auth_match: self.current_network["encryption"] = auth_match.group(1).strip()
            if channel_match: self.current_network["channel"] = channel_match.group(1).strip()
            if signal_match: self.current_network["signal"] = signal_match.group(1).strip()

            # Get DNS and Subnet
            addrs = psutil.net_if_addrs()
            for interface, snics in addrs.items():
                for snic in snics:
                    if snic.family == psutil.AF_INET and snic.address != '127.0.0.1':
                        self.current_network["subnet"] = snic.netmask

            # Get Gateway IP
            gateways = psutil.net_gways()
            if gateways['default'][psutil.AF_INET]:
                self.current_network["gateway_ip"] = gateways['default'][psutil.AF_INET][0]

            # Get Gateway MAC
            self.current_network["gateway_mac"] = self.get_mac(self.current_network["gateway_ip"])
            self.demo_mode = False

        except Exception:
            # Fallback to Demo Data if real WiFi is not available
            if not self.active_scenario:
                self.current_network = {
                    "ssid": "Nims office",
                    "bssid": "54:6C:EB:DE:E2:CA",
                    "encryption": "WPA2",
                    "gateway_ip": "192.168.99.241",
                    "gateway_mac": "54:6C:EB:DE:E2:CA",
                    "channel": "11",
                    "signal": "98%",
                    "dns": "8.8.8.8",
                    "subnet": "255.255.255.0"
                }
            self.demo_mode = True

    def get_mac(self, ip):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except:
            pass
        return "Unknown"

    def set_scenario(self, scenario_name):
        self.active_scenario = scenario_name
        if scenario_name == "open":
            self.current_network["encryption"] = "Open"
            self.risk_score = 40
            self.alerts = ["⚠️ Insecure Network: No encryption detected. Data can be intercepted."]
        elif scenario_name == "evil_twin":
            self.risk_score = 70
            self.alerts = ["⚠️ Possible Evil Twin: Duplicate SSID detected with a suspicious MAC address (00:DE:AD:BE:EF:00)."]
        elif scenario_name == "mitm":
            self.current_network["gateway_mac"] = "DE:AD:BE:EF:12:34"
            self.risk_score = 90
            self.alerts = ["⚠️ MITM Attack Detected: Gateway MAC address has changed! Possible ARP Spoofing in progress."]
        elif scenario_name == "reset":
            self.active_scenario = None
            self.risk_score = 0
            self.alerts = []
            self.get_network_info()

    def run_checks(self):
        while not self.stop_thread:
            if not self.active_scenario:
                self.get_network_info()
                new_alerts = []
                score = 0

                # Real-time checks
                if "Open" in self.current_network["encryption"]:
                    score += 40
                    new_alerts.append("⚠️ Insecure Network: No encryption detected.")
                
                # Simple ARP monitor
                current_mac = self.current_network["gateway_mac"]
                if current_mac != "Unknown" and current_mac != "Scanning...":
                    if not self.gateway_mac_history:
                        self.gateway_mac_history.append(current_mac)
                    elif current_mac != self.gateway_mac_history[-1]:
                        score += 50
                        new_alerts.append("⚠️ ARP Anomaly Detected: Possible MITM attack!")

                self.risk_score = score
                self.alerts = new_alerts

            time.sleep(3)

    def start_monitoring(self):
        self.thread = threading.Thread(target=self.run_checks)
        self.thread.daemon = True
        self.thread.start()

    def get_status(self):
        return {
            "network": self.current_network,
            "risk_score": self.risk_score,
            "alerts": self.alerts,
            "demo_mode": self.demo_mode
        }
