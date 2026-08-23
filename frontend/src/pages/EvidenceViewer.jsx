/**
 * Evidence Viewer — Time-Based Session Exploration & Telemetry Auditability
 *
 * Data source: GET /api/telemetry/events, GET /api/telemetry/sessions
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion } from 'framer-motion';
import { RefreshCw, AlertTriangle, Download, Filter, Calendar, Search, ShieldCheck } from 'lucide-react';
import { getTelemetryEvents, getTelemetrySessions, getTelemetryStatus } from '../api/telemetry';
import { formatTimestamp, truncatePath } from '../utils/formatters';
import EvidenceBadge from '../components/ui/EvidenceBadge';
import EmptyState from '../components/ui/EmptyState';

const LIMITS = [50, 100, 250, 500, 1000, 0];

export default function EvidenceViewer() {
  const [events, setEvents] = useState([]);
  const [counts, setCounts] = useState({ total: 0, etw: 0, psutil: 0 });
  const [sessionData, setSessionData] = useState({ dates: [], sessions: [] });
  const [etwOnline, setEtwOnline] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const [sourceFilter, setSourceFilter] = useState('');
  const [selectedDate, setSelectedDate] = useState('');
  const [processFilter, setProcessFilter] = useState('');
  const [limit, setLimit] = useState(100);
  const bottomRef = useRef(null);

  const fetchEtwStatus = async () => {
    try {
      const st = await getTelemetryStatus();
      const isOnline = !!(st.running || st.collector_status === 'ACTIVE' || st.connection_status === 'CONNECTED');
      setEtwOnline(isOnline);
    } catch {
      setEtwOnline(false);
    }
  };

  const fetchSessions = async () => {
    try {
      const data = await getTelemetrySessions();
      setSessionData(data);
      if (data.dates && data.dates.length > 0 && !selectedDate) {
        setSelectedDate(data.dates[0]); // Default to today / newest date
      }
    } catch {}
  };

  const fetchEvents = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true);
    setError(null);
    try {
      const data = await getTelemetryEvents({
        limit,
        evidence_source: sourceFilter || undefined,
        date: selectedDate || undefined,
        process: processFilter || undefined,
        include_summary: true,
      });

      if (data && typeof data === 'object' && Array.isArray(data.events)) {
        setEvents(data.events);
        setCounts({
          total: data.total_count ?? data.events.length,
          etw: data.etw_count ?? data.events.filter(e => e.evidence_source === 'etw').length,
          psutil: data.psutil_count ?? data.events.filter(e => e.evidence_source === 'psutil').length,
        });
      } else if (Array.isArray(data)) {
        setEvents(data);
        const etwC = data.filter(e => e.evidence_source === 'etw').length;
        const psutilC = data.filter(e => e.evidence_source === 'psutil').length;
        setCounts({ total: data.length, etw: etwC, psutil: psutilC });
      }
    } catch (err) {
      if (!isSilent) setError(err.response?.data?.error || 'Failed to load telemetry events.');
    } finally {
      if (!isSilent) setLoading(false);
    }
  }, [limit, sourceFilter, selectedDate, processFilter]);

  useEffect(() => {
    fetchSessions();
    fetchEtwStatus();
  }, []);

  // Live polling every 3 seconds for fresh telemetry events & ETW collector status
  useEffect(() => {
    fetchEvents(false);
    const timer = setInterval(() => {
      fetchEvents(true);
      fetchEtwStatus();
    }, 3000);
    return () => clearInterval(timer);
  }, [fetchEvents]);

  const handleManualRefresh = async () => {
    setRefreshing(true);
    await fetchEvents(false);
    await fetchEtwStatus();
    setRefreshing(false);
  };

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1 className="page-header-title">Evidence Viewer</h1>
          <div className="page-header-meta">
            <span className="page-header-hud">RUNTIME TELEMETRY · TIME-BASED SESSIONS</span>
          </div>
        </div>
        <div className="page-header-actions">
          {etwOnline ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.25)', padding: '4px 10px', borderRadius: 100, fontSize: 11, color: '#4ADE80', fontWeight: 600, fontFamily: 'monospace' }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', display: 'inline-block', boxShadow: '0 0 6px #22c55e' }}></span>
              LIVE STREAMING
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', padding: '4px 10px', borderRadius: 100, fontSize: 11, color: '#F87171', fontWeight: 600, fontFamily: 'monospace' }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#EF4444', display: 'inline-block' }}></span>
              ETW OFFLINE
            </div>
          )}
          <select
            id="evidence-limit-select"
            className="select"
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
            style={{ minWidth: 120 }}
          >
            {LIMITS.map(l => (
              <option key={l} value={l}>{l === 0 ? 'All Events' : `Last ${l}`}</option>
            ))}
          </select>
          <button className="btn btn-ghost btn-sm" onClick={handleManualRefresh} disabled={refreshing}>
            <RefreshCw size={13} className={refreshing ? 'spin' : ''} /> {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="stat-grid-3 mb-6">
        <div className="stat-card">
          <div className="stat-card-label">TOTAL EVENTS</div>
          <div className="stat-card-value">{loading ? '—' : counts.total.toLocaleString()}</div>
          <div className="stat-card-sub">Total collected telemetry events</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">ETW EVENTS</div>
          <div className="stat-card-value" style={{ color: 'var(--color-verified)' }}>
            {loading ? '—' : counts.etw.toLocaleString()}
          </div>
          <div className="stat-card-sub">High confidence</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">PSUTIL EVENTS</div>
          <div className="stat-card-value" style={{ color: 'var(--color-warning)' }}>
            {loading ? '—' : counts.psutil.toLocaleString()}
          </div>
          <div className="stat-card-sub">Medium confidence</div>
        </div>
      </div>

      {/* Time-Based Session Filter & Search Bar */}
      <div className="filter-bar mb-4" style={{ flexWrap: 'wrap', gap: 'var(--space-3)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <Calendar size={13} style={{ color: 'var(--text-muted)' }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase' }}>Session Date:</span>
          <select
            id="evidence-date-select"
            className="select"
            value={selectedDate}
            onChange={e => setSelectedDate(e.target.value)}
            style={{ minWidth: 150 }}
          >
            <option value="">All Days</option>
            {sessionData.dates.map((d, i) => (
              <option key={d} value={d}>
                {i === 0 ? `Today (${d})` : d}
              </option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
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

        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginLeft: 'auto' }}>
          <Search size={13} style={{ color: 'var(--text-muted)' }} />
          <input
            id="evidence-process-search"
            className="input"
            type="text"
            placeholder="Search process or DLL..."
            value={processFilter}
            onChange={e => setProcessFilter(e.target.value)}
            style={{ width: 180, padding: '4px 10px', fontSize: 12 }}
          />
        </div>
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
          <span className="terminal-title">
            TELEMETRY EVENT LOG {selectedDate ? `· ${selectedDate}` : ''}
          </span>
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
              Loading evidence events…
            </div>
          ) : events.length === 0 ? (
            <div style={{ padding: 'var(--space-6)', textAlign: 'center', color: 'var(--text-muted)' }}>
              No telemetry events found for {selectedDate || 'the selected filter'}. Start ETW monitoring to capture real-time evidence.
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
