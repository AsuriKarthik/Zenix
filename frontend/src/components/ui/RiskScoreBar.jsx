/**
 * RiskScoreBar — Visual risk score display
 *
 * Maps RiskScore.final_score (0–10) to:
 *  - Numeric value (JetBrains Mono)
 *  - Color-coded fill bar
 *  - Severity label
 */

import React from 'react';
import { getRiskLevel } from '../../utils/severity';
import { formatScore as fmt } from '../../utils/formatters';

/**
 * @param {{ score: number|null, showLabel?: boolean }} props
 */
export default function RiskScoreBar({ score, showLabel = false }) {
  const { color, label } = getRiskLevel(score);
  const pct = score !== null && score !== undefined
    ? Math.min((Number(score) / 10) * 100, 100)
    : 0;

  return (
    <div className="risk-score-bar">
      <span className="risk-score-value" style={{ color }}>
        {fmt(score)}
      </span>
      <div className="risk-score-track">
        <div
          className="risk-score-fill"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
      {showLabel && (
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 10,
            letterSpacing: 1,
            color,
            minWidth: 50,
          }}
        >
          {label}
        </span>
      )}
    </div>
  );
}
