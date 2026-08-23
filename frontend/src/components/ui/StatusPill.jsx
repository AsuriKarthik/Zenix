/**
 * StatusPill — Reachability verdict display
 *
 * Maps ReachabilityVerdict.status to color-coded pill.
 * REACHABLE → red (critical)
 * NOT_REACHABLE → teal (verified)
 * UNKNOWN → yellow (investigation)
 */

import React from 'react';
import { getReachabilityClass, getReachabilityLabel } from '../../utils/severity';

export default function StatusPill({ status }) {
  const cls = getReachabilityClass(status);
  const label = getReachabilityLabel(status);

  return (
    <span className={`status-pill status-pill-${cls}`}>
      {label}
    </span>
  );
}

/**
 * JobStatusPill — Job status display
 */
export function JobStatusPill({ status }) {
  return (
    <span className={`status-pill status-pill-${(status || 'queued').toLowerCase()}`}>
      {(status || '—').toUpperCase()}
    </span>
  );
}
