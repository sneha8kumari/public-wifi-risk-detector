import React from 'react';
import { CheckCircle, XCircle, HelpCircle, AlertTriangle } from 'lucide-react';

const STATUS_CONFIG = {
  pass:    { icon: CheckCircle,   color: 'var(--risk-low)',  label: 'Pass',    bg: 'rgba(35,134,54,0.12)' },
  fail:    { icon: XCircle,       color: 'var(--risk-high)', label: 'Fail',    bg: 'rgba(248,81,73,0.12)' },
  warn:    { icon: AlertTriangle, color: 'var(--risk-med)',  label: 'Warn',    bg: 'rgba(210,153,34,0.12)' },
  unknown: { icon: HelpCircle,    color: 'var(--text-secondary)', label: '—', bg: 'rgba(139,148,158,0.08)' },
};

const CHECK_LABELS = {
  open_network: 'Open Network',
  evil_twin:    'Evil Twin',
  arp_spoof:    'ARP Spoof',
  dns_spoof:    'DNS Spoof',
  ssl_strip:    'SSL Strip',
};

/**
 * CheckBadge — displays the pass/fail/warn/unknown status of one detection check.
 *
 * Props:
 *   checkKey  — key from CHECK_LABELS (e.g. "evil_twin")
 *   result    — { status: "pass"|"fail"|"warn"|"unknown", score: number, detail: string }
 */
export function CheckBadge({ checkKey, result = {} }) {
  const { status = 'unknown', score = 0, detail = '' } = result;
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.unknown;
  const Icon = cfg.icon;
  const label = CHECK_LABELS[checkKey] || checkKey;

  return (
    <div
      className="check-badge"
      style={{ background: cfg.bg, borderColor: cfg.color + '40' }}
      title={detail || label}
      aria-label={`${label}: ${cfg.label}`}
    >
      <Icon size={14} color={cfg.color} strokeWidth={2.5} />
      <span className="check-badge-name">{label}</span>
      {score > 0 && (
        <span className="check-badge-score" style={{ color: cfg.color }}>
          +{score}
        </span>
      )}
      <span className="check-badge-status" style={{ color: cfg.color }}>
        {cfg.label}
      </span>
    </div>
  );
}

/**
 * CheckGrid — renders all check badges in a responsive row.
 *
 * Props:
 *   checkResults — the full check_results dict from /api/status
 */
export function CheckGrid({ checkResults = {} }) {
  const keys = ['open_network', 'evil_twin', 'arp_spoof', 'dns_spoof', 'ssl_strip'];
  return (
    <div className="check-grid" aria-label="Detection check results">
      {keys.map((key) => (
        <CheckBadge key={key} checkKey={key} result={checkResults[key]} />
      ))}
    </div>
  );
}
