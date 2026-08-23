/**
 * PulseIndicator — ETW heartbeat / active state indicator
 *
 * Triggers when: ETW connection is active or job is running.
 * variant: 'verified' (teal) | 'critical' (red) | 'warning' (amber) | 'muted' (gray)
 */

import React from 'react';

/**
 * @param {{ variant?: string, size?: number }} props
 */
export default function PulseIndicator({ variant = 'verified', size = 10 }) {
  return (
    <span
      className="pulse-indicator"
      style={{ width: size, height: size }}
    >
      <span className={`pulse-dot ${variant === 'verified' ? '' : variant}`} />
      <span className={`pulse-ring ${variant === 'verified' ? '' : variant}`} />
    </span>
  );
}
