import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Wifi, Activity, Play, RefreshCw } from 'lucide-react';
import './index.css';

function App() {
  const [data, setData] = useState({
    network: { ssid: "Loading...", bssid: "", encryption: "", gateway_ip: "", gateway_mac: "" },
    risk_score: 0,
    alerts: [],
    demo_mode: false
  });

  const fetchData = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/status');
      const result = await response.json();
      setData(result);
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };

  const triggerScenario = async (scenario) => {
    try {
      await fetch('http://localhost:5000/api/scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      fetchData();
    } catch (error) {
      console.error("Error triggering scenario:", error);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const getRiskColor = (score) => {
    if (score < 30) return 'var(--risk-low)';
    if (score < 60) return 'var(--risk-med)';
    return 'var(--risk-high)';
  };

  return (
    <div className="app-container">
      <header className="header">
        <div>
          <h1>WiFi Risk Detector</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '4px' }}>
            Ethical VAPT Lab Environment {data.demo_mode && "(Simulation Mode Active)"}
          </p>
        </div>
        <div className="status-badge" style={{ borderColor: data.demo_mode ? 'var(--risk-med)' : 'var(--accent-cyan)', color: data.demo_mode ? 'var(--risk-med)' : 'var(--accent-cyan)' }}>
          <Activity size={16} className="pulse" />
          {data.demo_mode ? "Demo Data Active" : "Live Monitoring"}
        </div>
      </header>

      {/* Demo Control Panel */}
      <div className="card" style={{ marginBottom: '2rem', background: 'rgba(33, 136, 255, 0.05)', border: '1px dashed var(--accent-blue)' }}>
        <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', color: 'var(--accent-blue)', textTransform: 'uppercase' }}>Demo Control Panel</h3>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button onClick={() => triggerScenario('open')} className="demo-btn">Simulate Open WiFi</button>
          <button onClick={() => triggerScenario('evil_twin')} className="demo-btn">Simulate Evil Twin</button>
          <button onClick={() => triggerScenario('mitm')} className="demo-btn">Simulate MITM/ARP Spoof</button>
          <button onClick={() => triggerScenario('reset')} className="demo-btn reset-btn">Reset to Normal</button>
        </div>
      </div>

      <div className="dashboard-grid">
        <section className="card risk-section">
          <div className="risk-meter">
            <div className="risk-circle" style={{ borderColor: getRiskColor(data.risk_score) }}>
              <div className="risk-value" style={{ color: getRiskColor(data.risk_score) }}>{data.risk_score}</div>
            </div>
          </div>
          <div className="risk-label">Risk Level</div>
        </section>

        <section className="card">
          <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '1.1rem' }}>
            <Wifi size={18} color="var(--accent-cyan)" /> Network Identity
          </h2>
          <div className="info-grid">
            <div className="info-item">
              <label>SSID</label>
              <div className="value">{data.network.ssid}</div>
            </div>
            <div className="info-item">
              <label>Encryption</label>
              <div className="value">{data.network.encryption}</div>
            </div>
            <div className="info-item">
              <label>Gateway MAC</label>
              <div className="value">{data.network.gateway_mac}</div>
            </div>
            <div className="info-item">
              <label>Channel</label>
              <div className="value">{data.network.channel}</div>
            </div>
            <div className="info-item">
              <label>Signal Strength</label>
              <div className="value">{data.network.signal}</div>
            </div>
            <div className="info-item">
              <label>Subnet Mask</label>
              <div className="value">{data.network.subnet}</div>
            </div>
            <div className="info-item">
              <label>DNS Server</label>
              <div className="value">{data.network.dns}</div>
            </div>
          </div>
        </section>

        <section className="card alerts-section">
          <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '1.1rem' }}>
            <ShieldAlert size={18} color="var(--risk-high)" /> Security Alerts
          </h2>
          <div className="alert-list">
            {data.alerts.length > 0 ? (
              data.alerts.map((alert, index) => (
                <div key={index} className="alert-item">
                  <div className="alert-text">{alert}</div>
                </div>
              ))
            ) : (
              <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-secondary)' }}>
                <Shield size={32} style={{ marginBottom: '1rem', opacity: 0.2 }} />
                <p>No active threats detected.</p>
              </div>
            )}
          </div>
        </section>
      </div>

      <style dangerouslySetInnerHTML={{ __html: `
        .demo-btn {
          background: transparent;
          border: 1px solid var(--accent-blue);
          color: var(--accent-blue);
          padding: 8px 16px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 0.85rem;
          transition: all 0.2s;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .demo-btn:hover {
          background: rgba(33, 136, 255, 0.1);
          transform: translateY(-2px);
        }
        .reset-btn {
          border-color: var(--text-secondary);
          color: var(--text-secondary);
        }
        .reset-btn:hover {
          background: rgba(139, 148, 158, 0.1);
        }
      `}} />
    </div>
  );
}

export default App;
