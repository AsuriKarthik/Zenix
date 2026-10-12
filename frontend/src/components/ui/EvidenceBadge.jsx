/**
 * EvidenceBadge — ETW/psutil/none source indicator
 *
 * Maps EtwEvent.evidence_source / ReachabilityVerdict.evidence_source
 * to color-coded badge with confidence level.
 *
 * ETW    → high confidence → teal (#20E1A3)
 * psutil → medium confidence → amber (#F5A524)
 * none   → no evidence → muted (#8A8A93)
 */

import React from 'react';
import { Zap, Cpu, Minus } from 'lucide-react';

const SOURCE_CONFIG = {
  etw: {
    label: 'ETW',
    cssClass: 'etw',
    icon: Zap,
    confidence: 'HIGH',
  },
  psutil: {
    label: 'PSUTIL',
    cssClass: 'psutil',
    icon: Cpu,
    confidence: 'MED',
  },
  none: {
    label: 'NONE',
    cssClass: 'none',
    icon: Minus,
    confidence: 'LOW',
  },
};

/**
 * @param {{ source: 'etw'|'psutil'|'none'|null }} props
 */
export default function EvidenceBadge({ source }) {
  const key = (source || 'none').toLowerCase();
  const cfg = SOURCE_CONFIG[key] || SOURCE_CONFIG.none;
  const Icon = cfg.icon;

  return (
    <span className={`evidence-badge evidence-badge-${cfg.cssClass}`}>
      <Icon size={9} />
      {cfg.label}
    </span>
  );
}
