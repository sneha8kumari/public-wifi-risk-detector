"""
capture_analyzer.py — Offline forensic analysis of airodump-ng CSV dumps
                       and Wireshark / airodump-ng .pcap / .cap captures.
"""

import csv
import io
import logging
import re
from collections import defaultdict
from typing import Union

logger = logging.getLogger(__name__)

# ── Optional Scapy import ─────────────────────────────────────────────────────
try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11Disas, ARP, EAPOL
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — pcap analysis disabled.")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_mac(mac: str) -> str:
    """Upper-case and colon-separate a MAC address string."""
    return mac.strip().upper().replace("-", ":").replace(".", ":")


def _parse_airodump_csv_sections(raw: str):
    """
    Split an airodump-ng CSV into the AP section and the Station section.
    The two sections are separated by a blank line.
    Returns (ap_lines, station_lines) as lists of strings.
    """
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    sections = re.split(r"\n\s*\n", raw.strip(), maxsplit=1)
    ap_section       = sections[0].splitlines() if len(sections) >= 1 else []
    station_section  = sections[1].splitlines() if len(sections) >= 2 else []
    return ap_section, station_section


def _beacon_ssid(pkt) -> str:
    """Extract the SSID string from a Dot11Beacon packet."""
    try:
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 0:  # SSID element
                return elt.info.decode("utf-8", errors="replace").strip()
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return ""


def _beacon_has_rsn(pkt) -> bool:
    """Return True if the beacon contains an RSN (WPA2) or WPA IE."""
    try:
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID in (48, 221):   # 48=RSN, 221=vendor (WPA)
                return True
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return False


def _get_beacon_encryption(pkt) -> str:
    try:
        cap = pkt[Dot11Beacon].cap
        is_wep = bool(cap & 0x0010)
        has_rsn = _beacon_has_rsn(pkt)
        if has_rsn:
            return "WPA2"
        elif is_wep:
            return "WEP"
        else:
            return "Open"
    except Exception:
        return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# parse_airodump_csv
# ─────────────────────────────────────────────────────────────────────────────

def parse_airodump_csv(file_bytes: bytes) -> dict:
    """
    Parse airodump-ng -w scan.csv output (AP table + Station table).
    Detect evil twins (same ESSID broadcast from multiple BSSIDs),
    open networks (Privacy == OPN), and WEP networks.
    Return a dict with score, alerts, networks, evil_twins.
    """
    raw = file_bytes.decode("utf-8", errors="replace")
    ap_lines, station_lines = _parse_airodump_csv_sections(raw)

    networks = []
    evil_twins = []
    alerts = []
    score = 0

    ap_reader = csv.reader(ap_lines[1:] if len(ap_lines) > 1 else [])
    essid_to_bssids = defaultdict(list)

    for row in ap_reader:
        if len(row) < 14:
            continue
        bssid   = _normalise_mac(row[0])
        channel = row[3].strip()
        privacy = row[5].strip()
        cipher  = row[6].strip()
        power   = row[8].strip()
        essid   = row[13].strip()

        if not bssid or bssid == "BSSID":
            continue

        ap = {
            "bssid": bssid,
            "essid": essid,
            "channel": channel,
            "privacy": privacy,
            "cipher": cipher,
            "power": power
        }
        networks.append(ap)

        if essid:
            essid_to_bssids[essid].append(bssid)

        privacy_upper = privacy.upper()
        if "OPN" in privacy_upper or privacy_upper == "":
            score += 25
            alerts.append(f"Open network detected: SSID '{essid or '(hidden)'}' (BSSID: {bssid})")
        elif "WEP" in privacy_upper:
            score += 30
            alerts.append(f"WEP network detected: SSID '{essid or '(hidden)'}' (BSSID: {bssid})")

    for essid, bssids in essid_to_bssids.items():
        if len(bssids) > 1:
            score += 35
            evil_twins.append({"essid": essid, "bssids": bssids})
            alerts.append(f"Evil Twin detected: SSID '{essid}' broadcast from multiple BSSIDs ({', '.join(bssids)})")

    return {
        "score": min(score, 100),
        "alerts": alerts,
        "networks": networks,
        "evil_twins": evil_twins
    }


# ─────────────────────────────────────────────────────────────────────────────
# parse_pcap
# ─────────────────────────────────────────────────────────────────────────────

def parse_pcap(file_path: str) -> dict:
    """
    Use Scapy to parse .pcap/.cap files.
    Extract Dot11Beacon frames to build an AP list,
    count Dot11Deauth/Dot11Disas frames (flag as deauth flood if >=10),
    detect EAPOL handshake frames per BSSID (flag as WPA handshake),
    and detect ARP replies where the same IP maps to multiple MACs (flag as ARP conflict).
    Return score, alerts, networks, evil_twins, deauth_count, disassoc_count,
    eapol_bssids, arp_conflicts, packet_count.
    """
    result = {
        "score": 0,
        "alerts": [],
        "networks": [],
        "evil_twins": [],
        "deauth_count": 0,
        "disassoc_count": 0,
        "eapol_bssids": [],
        "arp_conflicts": [],
        "packet_count": 0
    }

    if not SCAPY_AVAILABLE:
        result["alerts"].append("Scapy not installed — pcap analysis unavailable.")
        return result

    try:
        packets = rdpcap(file_path)
    except Exception as exc:
        result["alerts"].append(f"Failed to read pcap: {exc}")
        return result

    result["packet_count"] = len(packets)

    known_bssids = set()
    bssid_to_ssid = {}
    bssid_to_encryption = {}
    ssid_to_bssids = defaultdict(set)
    ip_to_macs = defaultdict(set)
    
    deauth_count = 0
    disassoc_count = 0
    eapol_frames_by_bssid = defaultdict(list)

    for pkt in packets:
        # ── Beacon frames ────────────────────────────────────────────────────
        if pkt.haslayer(Dot11Beacon):
            try:
                bssid = _normalise_mac(pkt[Dot11].addr3 or pkt[Dot11].addr2 or "")
                if bssid:
                    ssid = _beacon_ssid(pkt)
                    encryption = _get_beacon_encryption(pkt)
                    
                    known_bssids.add(bssid)
                    bssid_to_ssid[bssid] = ssid
                    bssid_to_encryption[bssid] = encryption
                    if ssid:
                        ssid_to_bssids[ssid].add(bssid)
            except Exception:
                pass

        # ── Deauth / Disassoc frames ─────────────────────────────────────────
        elif pkt.haslayer(Dot11Deauth):
            deauth_count += 1
        elif pkt.haslayer(Dot11Disas):
            disassoc_count += 1

        # ── EAPOL Handshake ──────────────────────────────────────────────────
        elif pkt.haslayer(EAPOL):
            if pkt.haslayer(Dot11):
                try:
                    addr1 = _normalise_mac(pkt[Dot11].addr1 or "")
                    addr2 = _normalise_mac(pkt[Dot11].addr2 or "")
                    addr3 = _normalise_mac(pkt[Dot11].addr3 or "")
                    
                    # Associate with known BSSID if possible, else fallback
                    bssid = None
                    for addr in (addr3, addr2, addr1):
                        if addr in known_bssids:
                            bssid = addr
                            break
                    if not bssid:
                        bssid = addr3 if addr3 else (addr2 if addr2 else addr1)
                        
                    if bssid:
                        eapol_frames_by_bssid[bssid].append(pkt)
                except Exception:
                    pass

        # ── ARP reply packets ────────────────────────────────────────────────
        elif pkt.haslayer(ARP):
            try:
                arp = pkt[ARP]
                if arp.op == 2:  # Reply
                    ip = arp.psrc
                    mac = _normalise_mac(arp.hwsrc)
                    if ip and ip != "0.0.0.0" and mac:
                        ip_to_macs[ip].add(mac)
            except Exception:
                pass

    result["deauth_count"] = deauth_count
    result["disassoc_count"] = disassoc_count

    # Build networks list
    networks = []
    for bssid in known_bssids:
        networks.append({
            "bssid": bssid,
            "essid": bssid_to_ssid.get(bssid, "(hidden)"),
            "encryption": bssid_to_encryption.get(bssid, "Unknown")
        })
    result["networks"] = networks

    # ── Alerts and Score Calculation ──────────────────────────────────────────
    score = 0
    alerts = []

    # Evil twins
    evil_twins = []
    for ssid, bssids in ssid_to_bssids.items():
        if len(bssids) > 1:
            bssid_list = sorted(list(bssids))
            evil_twins.append({"ssid": ssid, "bssids": bssid_list})
            score += 35
            alerts.append(f"Evil Twin detected: SSID '{ssid}' broadcast from multiple BSSIDs ({', '.join(bssid_list)})")
    result["evil_twins"] = evil_twins

    # Open / WEP network check from beacons
    for bssid, ssid in bssid_to_ssid.items():
        enc = bssid_to_encryption.get(bssid, "Unknown")
        if enc == "Open":
            score += 25
            alerts.append(f"Open network detected: SSID '{ssid or '(hidden)'}' (BSSID: {bssid})")
        elif enc == "WEP":
            score += 30
            alerts.append(f"WEP network detected: SSID '{ssid or '(hidden)'}' (BSSID: {bssid})")

    # Deauth flood
    if (deauth_count + disassoc_count) >= 10:
        score += 45
        alerts.append(f"Deauth Flood detected: {deauth_count + disassoc_count} deauth/disassociation frames captured (possible active MITM/DoS attack)")

    # EAPOL Handshakes
    eapol_bssids = []
    for bssid, frames in eapol_frames_by_bssid.items():
        if len(frames) >= 4:
            eapol_bssids.append(bssid)
            score += 40
            ssid_label = bssid_to_ssid.get(bssid, "Unknown ESSID")
            alerts.append(f"WPA Handshake captured for network '{ssid_label}' (BSSID: {bssid}). Pre-shared key can be cracked offline.")
    result["eapol_bssids"] = eapol_bssids

    # ARP conflicts
    arp_conflicts = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            mac_list = sorted(list(macs))
            arp_conflicts.append({"ip": ip, "mac_a": mac_list[0], "mac_b": mac_list[1]})
            score += 50
            alerts.append(f"ARP Conflict / MITM detected: IP {ip} maps to multiple MACs: {', '.join(mac_list)}")
    result["arp_conflicts"] = arp_conflicts

    result["score"] = min(score, 100)
    result["alerts"] = alerts
    return result
