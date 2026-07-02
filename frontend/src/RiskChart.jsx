import React, { useMemo } from 'react';

const W = 480;
const H = 120;
const PAD = { top: 10, right: 12, bottom: 28, left: 36 };

const CHART_W = W - PAD.left - PAD.right;
const CHART_H = H - PAD.top - PAD.bottom;

function scoreColor(score) {
  if (score < 30) return '#238636';
  if (score < 60) return '#d29922';
  return '#f85149';
}

/**
 * RiskChart — SVG sparkline showing risk_score over time.
 *
 * Props:
 *   history  — array of { epoch, risk_score, sim_risk_score, timestamp }
 *   width    — optional override (defaults to 100%)
 */
export default function RiskChart({ history = [] }) {
  const points = useMemo(() => {
    if (history.length < 2) return { live: '', sim: '', dots: [] };

    const minEpoch = history[0].epoch;
    const maxEpoch = history[history.length - 1].epoch;
    const epochRange = Math.max(maxEpoch - minEpoch, 1);

    const toX = (e) => PAD.left + ((e - minEpoch) / epochRange) * CHART_W;
    const toY = (s) => PAD.top + CHART_H - (s / 100) * CHART_H;

    const livePts = history.map((d) => [toX(d.epoch), toY(d.risk_score)]);
    const simPts  = history.map((d) => [toX(d.epoch), toY(d.sim_risk_score || 0)]);

    const polyline = (pts) => pts.map((p) => p.join(',')).join(' ');

    // Build gradient area path for live score
    const areaPath = [
      `M ${livePts[0][0]},${PAD.top + CHART_H}`,
      ...livePts.map(([x, y]) => `L ${x},${y}`),
      `L ${livePts[livePts.length - 1][0]},${PAD.top + CHART_H}`,
      'Z',
    ].join(' ');

    return {
      live: polyline(livePts),
      sim: polyline(simPts),
      area: areaPath,
      dots: history.slice(-1).map((d) => ({
        x: toX(d.epoch),
        y: toY(d.risk_score),
        color: scoreColor(d.risk_score),
        score: d.risk_score,
      })),
    };
  }, [history]);

  // Y-axis grid lines at 0, 30, 60, 90, 100
  const gridLines = [0, 30, 60, 90].map((score) => ({
    score,
    y: PAD.top + CHART_H - (score / 100) * CHART_H,
    color: scoreColor(score + 1),
  }));

  // X-axis time labels
  const timeLabels = useMemo(() => {
    if (history.length < 2) return [];
    const first = history[0];
    const last = history[history.length - 1];
    const mid = history[Math.floor(history.length / 2)];
    return [first, mid, last].map((d) => ({
      x: PAD.left + ((d.epoch - history[0].epoch) / Math.max(history[history.length - 1].epoch - history[0].epoch, 1)) * CHART_W,
      label: new Date(d.epoch * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }));
  }, [history]);

  const lastScore = history.length > 0 ? history[history.length - 1].risk_score : 0;

  return (
    <div className="risk-chart-container">
      <div className="risk-chart-header">
        <span className="risk-chart-title">Risk History</span>
        <span className="risk-chart-badge" style={{ color: scoreColor(lastScore) }}>
          Latest: {lastScore}
        </span>
      </div>

      {history.length < 2 ? (
        <div className="risk-chart-empty">
          Collecting data… (updates every ~15 s)
        </div>
      ) : (
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="risk-chart-svg"
          aria-label="Risk score over time"
        >
          <defs>
            <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={scoreColor(lastScore)} stopOpacity="0.25" />
              <stop offset="100%" stopColor={scoreColor(lastScore)} stopOpacity="0.01" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {gridLines.map(({ score, y, color }) => (
            <g key={score}>
              <line
                x1={PAD.left} y1={y} x2={PAD.left + CHART_W} y2={y}
                stroke={color} strokeOpacity="0.15" strokeWidth="1"
                strokeDasharray="4 3"
              />
              <text x={PAD.left - 4} y={y + 4} textAnchor="end"
                fontSize="9" fill={color} fillOpacity="0.7">
                {score}
              </text>
            </g>
          ))}

          {/* Area fill */}
          {points.area && (
            <path d={points.area} fill="url(#areaGrad)" />
          )}

          {/* Simulation score line (dashed) */}
          {points.sim && (
            <polyline
              points={points.sim}
              fill="none"
              stroke="#2188ff"
              strokeWidth="1.5"
              strokeDasharray="5 3"
              strokeOpacity="0.6"
            />
          )}

          {/* Live score line */}
          {points.live && (
            <polyline
              points={points.live}
              fill="none"
              stroke={scoreColor(lastScore)}
              strokeWidth="2"
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          )}

          {/* Latest value dot */}
          {points.dots && points.dots.map((dot, i) => (
            <circle key={i} cx={dot.x} cy={dot.y} r="4"
              fill={dot.color} stroke="#0a0e14" strokeWidth="2" />
          ))}

          {/* X-axis time labels */}
          {timeLabels.map(({ x, label }, i) => (
            <text key={i} x={x} y={H - 4} textAnchor="middle"
              fontSize="9" fill="#8b949e">
              {label}
            </text>
          ))}

          {/* Legend */}
          <g transform={`translate(${PAD.left + CHART_W - 120}, ${PAD.top})`}>
            <line x1="0" y1="6" x2="14" y2="6" stroke={scoreColor(lastScore)} strokeWidth="2" />
            <text x="18" y="10" fontSize="9" fill="#8b949e">Live</text>
            <line x1="40" y1="6" x2="54" y2="6" stroke="#2188ff" strokeWidth="1.5" strokeDasharray="4 2" />
            <text x="58" y="10" fontSize="9" fill="#8b949e">Sim</text>
          </g>
        </svg>
      )}
    </div>
  );
}
