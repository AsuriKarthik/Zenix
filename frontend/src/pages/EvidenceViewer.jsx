/**
 * Evidence Viewer
 *
 * Purpose: Show WHY Zenix reached a reachability conclusion.
 *
 * Data source: GET /api/telemetry/events
 *
 * Displays:
 *   - ETW / psutil events in terminal-style viewer
 *   - timestamp | PID | process_name | image_path | evidence_source
 *   - Filter by source (ETW vs psutil)
 *   - Confidence indicators
 *
 * Terminal styling is functional, not decorative —
 * the data IS technical and warrants it.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion } from 'framer-motion';
import { RefreshCw, AlertTriangle, Download, Filter } from 'lucide-react';
import { getTelemetryEvents } from '../api/telemetry';
import { formatTimestamp, truncatePath } from '../utils/formatters';
import EvidenceBadge from '../components/ui/EvidenceBadge';
import EmptyState from '../components/ui/EmptyState';
import { Terminal } from 'lucide-react';

const LIMITS = [50, 100, 250, 500];

export default function EvidenceViewer() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sourceFilter, setSourceFilter] = useState('');
  const [limit, setLimit] = useState(100);
  const bottomRef = useRef(null);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getTelemetryEvents({
        limit,
        evidence_source: sourceFilter || undefined,
      });
      setEvents(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load telemetry events.');
    } finally {
      setLoading(false);
    }
  }, [limit, sourceFilter]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  // Export events as JSON
  const handleExport = () => {
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `zenix-events-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const etwCount    = events.filter(e => e.evidence_source === 'etw').length;
  const psutilCount = events.filter(e => e.evidence_source === 'psutil').length;

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1 className="page-header-title">Evidence Viewer</h1>
          <div className="page-header-meta">
            <span className="page-header-hud">RUNTIME TELEMETRY · ETW + PSUTIL</span>
          </div>
        </div>
        <div className="page-header-actions">
          <select
            id="evidence-limit-select"
            className="select"
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
            style={{ width: 100 }}
          >
            {LIMITS.map(l => (
              <option key={l} value={l}>Last {l}</option>
            ))}
          </select>
          <button className="btn btn-ghost btn-sm" onClick={fetchEvents}>
            <RefreshCw size={13} /> Refresh
          </button>
          <button className="btn btn-secondary btn-sm" onClick={handleExport} disabled={events.length === 0}>
            <Download size={13} /> Export
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="stat-grid-3 mb-6">
        <div className="stat-card">
          <div className="stat-card-label">TOTAL EVENTS</div>
          <div className="stat-card-value">{loading ? '—' : events.length}</div>
          <div className="stat-card-sub">From last {limit} records</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">ETW EVENTS</div>
          <div className="stat-card-value" style={{ color: 'var(--color-verified)' }}>
            {loading ? '—' : etwCount}
          </div>
          <div className="stat-card-sub">High confidence</div>
          <div className="stat-card-accent-line" style={{ background: 'var(--color-verified)', opacity: 0.3 }} />
        </div>
        <div className="stat-card">
          <div className="stat-card-label">PSUTIL EVENTS</div>
          <div className="stat-card-value" style={{ color: 'var(--color-warning)' }}>
            {loading ? '—' : psutilCount}
          </div>
          <div className="stat-card-sub">Medium confidence</div>
          <div className="stat-card-accent-line" style={{ background: 'var(--color-warning)', opacity: 0.3 }} />
        </div>
      </div>

      {/* Filter bar */}
      <div className="filter-bar mb-4">
        <Filter size={12} style={{ color: 'var(--text-muted)' }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase' }}>Source:</span>
        {['', 'etw', 'psutil'].map((src) => (
          <button
            key={src || 'all'}
            className={`filter-chip ${sourceFilter === src ? 'active' : ''}`}
            onClick={() => setSourceFilter(src)}
          >
            {src === '' ? 'ALL' : src.toUpperCase()}
          </button>
        ))}
      </div>

      {error && (
        <div className="alert alert-error mb-4">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Terminal viewer */}
      <div className="terminal-viewer">
        <div className="terminal-header">
          <span className="terminal-title">TELEMETRY EVENT LOG</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
            {events.length} EVENT{events.length !== 1 ? 'S' : ''}
          </span>
        </div>

        <div className="terminal-body">
          {/* Column headers */}
          <div className="terminal-row" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', marginBottom: 4, paddingBottom: 4 }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 2, textTransform: 'uppercase', color: 'var(--text-muted)' }}>TIMESTAMP</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 2, textTransform: 'uppercase', color: 'var(--text-muted)' }}>PID</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 2, textTransform: 'uppercase', color: 'var(--text-muted)' }}>PROCESS</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 2, textTransform: 'uppercase', color: 'var(--text-muted)' }}>IMAGE PATH</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 2, textTransform: 'uppercase', color: 'var(--text-muted)', textAlign: 'right' }}>SOURCE</span>
          </div>

          {loading ? (
            <div style={{ padding: 'var(--space-6)', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading events…
            </div>
          ) : events.length === 0 ? (
            <div style={{ padding: 'var(--space-6)', textAlign: 'center', color: 'var(--text-muted)' }}>
              No events. ETW collector may be inactive.
            </div>
          ) : (
            events.map((evt, i) => (
              <motion.div
                key={evt.id}
                className="terminal-row"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: Math.min(i * 0.008, 0.3) }}
              >
                <span className="terminal-cell-ts">{formatTimestamp(evt.timestamp)}</span>
                <span className="terminal-cell-pid">{evt.pid ?? '—'}</span>
                <span className="terminal-cell-proc">{evt.process_name || '—'}</span>
                <span className="terminal-cell-path" title={evt.image_path}>
                  {truncatePath(evt.image_path, 4)}
                </span>
                <span className="terminal-cell-src">
                  <EvidenceBadge source={evt.evidence_source} />
                </span>
              </motion.div>
            ))
          )}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}
