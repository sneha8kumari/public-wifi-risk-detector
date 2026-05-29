# Public WiFi Risk Detector - Lab Setup Guide 🧪

This guide explains how to set up a controlled environment to simulate and detect WiFi threats.

## 1. Prerequisites
- **Host Machine**: Windows (running the Detector app).
- **Network Driver**: [Npcap](https://npcap.com/) (Required for Scapy to perform ARP scanning on Windows).
- **Attacker**: Kali Linux (VM or separate machine).
- **Victim**: Any device (Smartphone or another VM).
- **WiFi**: A router you control (or a mobile hotspot).

## 2. Threat Simulations (Educational Only)

### Scenario A: Open WiFi Risk
1. Configure your router/hotspot to have **No Security** (Open).
2. Connect your host machine to this network.
3. **Detection**: The dashboard will show a **+40 Risk Score** and alert you about the lack of encryption.

### Scenario B: Evil Twin (Fake WiFi)
1. On Kali Linux, use `airgeddon` or `wifiphisher` to create a fake AP with the **same SSID** as your legitimate network.
2. Ensure the host machine is within range.
3. **Detection**: The detector scans nearby networks. If it finds multiple BSSIDs for the same SSID, it flags a **Possible Evil Twin** (+30 Risk).

### Scenario C: ARP Spoofing (MITM)
1. Use `arpspoof` on Kali Linux:
   ```bash
   arpspoof -i eth0 -t <Host_IP> <Gateway_IP>
   ```
2. This will change the Gateway MAC address on the host machine.
3. **Detection**: The detector monitors the Gateway MAC. When it changes from the initial state, it triggers a **MITM Alert** (+30 Risk).

## 3. Running the Project

### Backend
1. Open a terminal in the `backend` folder.
2. Install dependencies: `pip install -r requirements.txt`.
3. Run the server: `python app.py`.
   > [!NOTE]
   > You may need to run as **Administrator** to allow Scapy to perform ARP scans.

### Frontend
1. Open a terminal in the `frontend` folder.
2. Run the dashboard: `npm run dev`.
3. Open the URL (usually `http://localhost:5173`) in your browser.

## 4. Academic Disclaimer
All experiments must be conducted in an isolated lab environment. Unauthorized access to networks is illegal and unethical. This tool is built for **detection and mitigation education**.
