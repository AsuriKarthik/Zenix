/**
 * Severity and reachability color/label mapping for Zenix.
 *
 * Color semantics:
 *   #E5484D — critical / reachable / KEV
 *   #F5A524 — high / warning / medium confidence
 *   #F5D90A — medium / unknown state
 *   #20E1A3 — verified / not-reachable / confirmed safe
 *   #8A8A93 — low / no evidence
 */

/**
 * Get color and label for a risk final_score (0–10).
 * @param {number|null} score
 * @returns {{ color: string, label: string, bg: string }}
 */
export function getRiskLevel(score) {
  if (score === null || score === undefined) {
    return { color: '#8A8A93', label: 'N/A', bg: 'rgba(138,138,147,0.1)' };
  }
  const s = Number(score);
  if (s >= 9.0) return { color: '#E5484D', label: 'CRITICAL', bg: 'rgba(229,72,77,0.1)' };
  if (s >= 7.0) return { color: '#F5A524', label: 'HIGH',     bg: 'rgba(245,165,36,0.1)' };
  if (s >= 4.0) return { color: '#F5D90A', label: 'MEDIUM',   bg: 'rgba(245,217,10,0.1)' };
  if (s >= 1.0) return { color: '#20E1A3', label: 'LOW',      bg: 'rgba(32,225,163,0.1)' };
  return           { color: '#8A8A93', label: 'NONE',     bg: 'rgba(138,138,147,0.1)' };
}

/**
 * Get CSS class suffix for reachability status.
 * Maps ReachabilityVerdict.status values.
 * @param {string|null} status
 * @returns {string}
 */
export function getReachabilityClass(status) {
  switch ((status || '').toUpperCase()) {
    case 'REACHABLE':     return 'reachable';
    case 'NOT_REACHABLE': return 'not-reachable';
    case 'UNKNOWN':       return 'unknown';
    default:              return 'unknown';
  }
}

/**
 * Get display label for reachability status.
 * @param {string|null} status
 * @returns {string}
 */
export function getReachabilityLabel(status) {
  switch ((status || '').toUpperCase()) {
    case 'REACHABLE':     return 'REACHABLE';
    case 'NOT_REACHABLE': return 'NOT REACHABLE';
    case 'UNKNOWN':       return 'UNKNOWN';
    default:              return status || 'UNKNOWN';
  }
}

/**
 * Get color for confidence level string.
 * @param {'high'|'medium'|'low'|null} confidence
 * @returns {string}
 */
export function getConfidenceColor(confidence) {
  switch ((confidence || '').toLowerCase()) {
    case 'high':   return '#20E1A3';
    case 'medium': return '#F5A524';
    case 'low':    return '#8A8A93';
    default:       return '#8A8A93';
  }
}

/**
 * Get CSS class for confidence level.
 * @param {string|null} confidence
 * @returns {string}
 */
export function getConfidenceClass(confidence) {
  switch ((confidence || '').toLowerCase()) {
    case 'high':   return 'high';
    case 'medium': return 'medium';
    case 'low':    return 'low';
    default:       return 'low';
  }
}

/**
 * Get VEX status display info.
 * @param {string|null} status
 * @returns {{ label: string, cssClass: string }}
 */
export function getVexStatusInfo(status) {
  switch ((status || '').toLowerCase()) {
    case 'not_affected':
      return { label: 'NOT AFFECTED', cssClass: 'not-affected' };
    case 'affected':
      return { label: 'AFFECTED', cssClass: 'affected' };
    case 'fixed':
      return { label: 'FIXED', cssClass: 'fixed' };
    case 'under_investigation':
      return { label: 'INVESTIGATING', cssClass: 'under-investigation' };
    default:
      return { label: status || 'UNKNOWN', cssClass: 'under-investigation' };
  }
}

/**
 * Get job status display info.
 * @param {string|null} status
 * @returns {{ label: string, cssClass: string }}
 */
export function getJobStatusInfo(status) {
  switch ((status || '').toLowerCase()) {
    case 'queued':  return { label: 'QUEUED',     cssClass: 'queued' };
    case 'running': return { label: 'RUNNING',    cssClass: 'running' };
    case 'done':    return { label: 'COMPLETE',   cssClass: 'done' };
    case 'failed':  return { label: 'FAILED',     cssClass: 'failed' };
    default:        return { label: status || '—', cssClass: 'queued' };
  }
}
