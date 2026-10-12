/**
 * Utility formatters for Zenix UI
 */

/**
 * Format an ISO timestamp to a readable local string.
 * @param {string|null} isoString
 * @returns {string}
 */
export function formatTimestamp(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return isoString;
  return d.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

/**
 * Format an ISO timestamp as relative time ("3m ago", "2h ago").
 * @param {string|null} isoString
 * @returns {string}
 */
export function formatRelativeTime(isoString) {
  if (!isoString) return '—';
  const now = Date.now();
  const then = new Date(isoString).getTime();
  if (isNaN(then)) return isoString;
  const diff = Math.floor((now - then) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

/**
 * Format a duration between two ISO strings.
 * @param {string|null} start
 * @param {string|null} end
 * @returns {string}
 */
export function formatDuration(start, end) {
  if (!start || !end) return '—';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (isNaN(ms) || ms < 0) return '—';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

/**
 * Format a float score to 2 decimal places, or dash if null.
 * @param {number|null} score
 * @returns {string}
 */
export function formatScore(score) {
  if (score === null || score === undefined) return '—';
  return Number(score).toFixed(2);
}

/**
 * Format CVSS score with label.
 * @param {number|null} cvss
 * @returns {string}
 */
export function formatCvss(cvss) {
  if (cvss === null || cvss === undefined) return '—';
  return Number(cvss).toFixed(1);
}

/**
 * Format EPSS probability as percentage.
 * @param {number|null} epss  — value between 0 and 1
 * @returns {string}
 */
export function formatEpss(epss) {
  if (epss === null || epss === undefined) return '—';
  return `${(Number(epss) * 100).toFixed(2)}%`;
}

/**
 * Truncate a file path to the last N segments.
 * @param {string} path
 * @param {number} segments
 * @returns {string}
 */
export function truncatePath(path, segments = 3) {
  if (!path) return '—';
  const parts = path.replace(/\\/g, '/').split('/').filter(Boolean);
  if (parts.length <= segments) return path;
  return '…/' + parts.slice(-segments).join('/');
}

/**
 * Truncate a string hash for display.
 * @param {string|null} hash
 * @param {number} len
 * @returns {string}
 */
export function truncateHash(hash, len = 16) {
  if (!hash) return '—';
  return hash.length > len ? hash.slice(0, len) + '…' : hash;
}

/**
 * Format a job ID for display (first 8 chars of UUID).
 * @param {string|null} jobId
 * @returns {string}
 */
export function formatJobId(jobId) {
  if (!jobId) return '—';
  return `ZX-${jobId.slice(0, 8).toUpperCase()}`;
}
