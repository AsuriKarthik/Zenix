/**
 * Utility formatters for Zenix UI
 */

/**
 * Format an ISO timestamp to a readable local date and time string.
 * Automatically normalizes naive UTC strings by appending 'Z'.
 * @param {string|null} isoString
 * @returns {string}
 */
export function formatTimestamp(isoString) {
  if (!isoString) return '—';
  let normalized = isoString;
  if (typeof normalized === 'string') {
    if (/^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}$/.test(normalized)) {
      return normalized;
    }
    if (!normalized.endsWith('Z') && !/[+\-]\d{2}:\d{2}$/.test(normalized)) {
      normalized = normalized + 'Z';
    }
  }
  const d = new Date(normalized);
  if (isNaN(d.getTime())) return String(isoString);

  const pad = (n) => String(n).padStart(2, '0');
  const year = d.getFullYear();
  const month = pad(d.getMonth() + 1);
  const day = pad(d.getDate());
  const hours = pad(d.getHours());
  const minutes = pad(d.getMinutes());
  const seconds = pad(d.getSeconds());
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

/**
 * Format an ISO timestamp as relative time ("3m ago", "2h ago").
 * Always treats timestamps as UTC — appends 'Z' if no timezone offset present.
 * @param {string|null} isoString
 * @returns {string}
 */
export function formatRelativeTime(isoString) {
  if (!isoString) return '—';
  let normalized = isoString;
  if (typeof normalized === 'string' && !normalized.endsWith('Z') && !/[+\-]\d{2}:\d{2}$/.test(normalized)) {
    normalized = normalized + 'Z';
  }
  const now = Date.now();
  const then = new Date(normalized).getTime();
  if (isNaN(then)) return isoString;
  const diff = Math.floor((now - then) / 1000);
  if (diff < 5)    return 'just now';
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
 * @param {number|null} epss — value between 0 and 1
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
  const parts = path.replace(/\\/g, '/').split('/');
  if (parts.length <= segments) return path;
  return '…/' + parts.slice(-segments).join('/');
}

/**
 * Truncate a hash string for UI display.
 * @param {string|null} hash
 * @param {number} len
 * @returns {string}
 */
export function truncateHash(hash, len = 12) {
  if (!hash) return '—';
  if (hash.length <= len) return hash;
  return `${hash.slice(0, len)}…`;
}

/**
 * Format Job ID for UI header display.
 * @param {string} jobId
 * @returns {string}
 */
export function formatJobId(jobId) {
  if (!jobId) return '—';
  if (jobId.startsWith('ZX-')) return jobId;
  return `ZX-${jobId.slice(0, 8).toUpperCase()}`;
}
