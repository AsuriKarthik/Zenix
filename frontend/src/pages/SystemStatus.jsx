/**
 * System Status Page
 *
 * Purpose: Build user trust through transparency.
 *
 * Data sources:
 *   GET /api/telemetry/status     → ETW agent state, mode, elevation
 *   GET /api/telemetry/audit-logs → ETW activation history
 *
 * Displays:
 *   - ETW agent card with pulse
 *   - Mode and elevation state
 *   - Audit log for ETW activations
 *   - Feed freshness (from telemetry status)
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { motion } from 'framer-motion';
import { RefreshCw, AlertTriangle, Server, Database, Shield, Activity, Calendar } from 'lucide-react';
import { getTelemetryStatus, getAuditLogs } from '../api/telemetry';
import { formatTimestamp, formatRelativeTime } from '../utils/formatters';
import PulseIndicator from '../components/ui/PulseIndicator';
import EmptyState from '../components/ui/EmptyState';
import CalendarPicker from '../components/ui/CalendarPicker';

const POLL_MS = 3000;

/* ── Status Card ─────────────────────────────────────────────────── */
function StatusCard({ icon: Icon, title, status, sub, isOnline, detail }) {
  const variant = isOnline ? 'verified' : 'muted';
  const statusLabel = isOnline ? 'ONLINE' : 'OFFLINE';
  const statusColor = isOnline ? 'var(--color-verified)' : 'var(--text-muted)';

  return (
    <div className="card">
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <div style={{
            width: 36, height: 36,
            background: 'var(--bg-surface-2)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Icon size={16} style={{ color: isOnline ? 'var(--color-verified)' : 'var(--text-muted)' }} />
          </div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{title}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{sub}</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <PulseIndicator variant={variant} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, letterSpacing: 1, color: statusColor }}>
            {statusLabel}
          </span>
        </div>
      </div>

      {detail && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 'var(--space-3)',
        }}>
          {Object.entries(detail).map(([label, value]) => (
            <div key={label} style={{
              padding: 'var(--space-2) var(--space-3)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-sm)',
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                {label}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                {value ?? '—'}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Audit Log Row ───────────────────────────────────────────────── */
function AuditRow({ log }) {
  const isSuccess = log.result === 'success';
  const isFailed  = log.result === 'auth_failed' || log.result === 'elevation_failed';

  const resultColor = isSuccess
    ? 'var(--color-verified)'
    : isFailed
    ? 'var(--color-critical)'
    : 'var(--color-warning)';

  return (
    <tr>
      <td className="cell-mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>
        {formatTimestamp(log.timestamp)}
      </td>
      <td className="cell-mono" style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
        {log.action?.toUpperCase()}
      </td>
      <td>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: 1,
          color: resultColor,
        }}>
          {log.result?.replace('_', ' ').toUpperCase()}
        </span>
      </td>
      <td className="cell-mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>
        {log.ip_address}
      </td>
      <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
        {log.details || '—'}
      </td>
    </tr>
  );
}

/* ── Main Component ─────────────────────────────────────────────── */
export default function SystemStatus() {
  const [status, setStatus]     = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [selectedDate, setSelectedDate] = useState('ALL');
  const [isCalendarOpen, setIsCalendarOpen] = useState(false);

  // Compute map of dates with authentication counts for calendar indicators
  const authDatesMap = useMemo(() => {
    const counts = {};
    for (const l of auditLogs) {
      const d = (l.timestamp || '').slice(0, 10);
      if (/^\d{4}-\d{2}-\d{2}$/.test(d)) {
        counts[d] = (counts[d] || 0) + 1;
      }
    }
    return counts;
  }, [auditLogs]);

  // Filter logs by selected date if specified
  const filteredLogs = useMemo(() => {
    if (selectedDate === 'ALL') return auditLogs;
    return auditLogs.filter(l => (l.timestamp || '').startsWith(selectedDate));
  }, [auditLogs, selectedDate]);

  // Show strictly only the latest 10 entries
  const displayedLogs = useMemo(() => {
    return filteredLogs.slice(0, 10);
  }, [filteredLogs]);

  const fetchData = useCallback(async () => {
    try {
      const [telStatus, logs] = await Promise.all([
        getTelemetryStatus(),
        getAuditLogs().catch(() => []),
      ]);
      setStatus(telStatus);
      setAuditLogs(logs);
      setLastUpdate(new Date());
      setError(null);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load system status.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const t = setInterval(fetchData, POLL_MS);
    return () => clearInterval(t);
  }, [fetchData]);

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1 className="page-header-title">System Status</h1>
          <div className="page-header-meta">
            <span className="page-header-hud">INFRASTRUCTURE HEALTH</span>
            {lastUpdate && (
              <span className="page-header-hud" style={{ color: 'var(--text-muted)' }}>
                UPDATED {formatRelativeTime(lastUpdate.toISOString())}
              </span>
            )}
          </div>
        </div>
        <div className="page-header-actions">
          <button className="btn btn-ghost btn-sm" onClick={fetchData}>
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-error mb-6">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Status Cards Grid */}
      <div className="stat-grid-2 mb-8">
        <StatusCard
          icon={Activity}
          title="ETW Collector"
          sub={`PROVIDER: ${status?.provider || 'Microsoft-Windows-Kernel-Process'}`}
          isOnline={status?.running}
          detail={loading ? null : {
            'Mode':       (status?.mode || '—').toUpperCase(),
            'Elevation':  status?.elevation_state || (status?.is_elevated ? 'Elevated (Admin)' : 'Standard User'),
            'Events':     status?.event_count ?? status?.event_count_total ?? 0,
            'Status':     status?.running ? 'Active' : 'Stopped',
          }}
        />
        <StatusCard
          icon={Server}
          title="Analysis Engine"
          sub="FLASK · SQLALCHEMY · JOB QUEUE"
          isOnline={!error}
          detail={loading ? null : {
            'Backend':    'Flask 3.x',
            'DB':         'SQLite / SQLAlchemy',
            'Workers':    '2',
            'API':        '/api/v1',
          }}
        />
        <StatusCard
          icon={Database}
          title="Vulnerability Feeds"
          sub="OSV · NVD · EPSS · CISA KEV"
          isOnline={!error}
          detail={loading ? null : {
            'OSV Feed':   status?.osv_freshness || 'Active',
            'NVD':        status?.nvd_freshness || 'Active',
            'EPSS':       status?.epss_freshness || 'Active',
            'CISA KEV':   status?.kev_freshness || 'Active',
          }}
        />
        <StatusCard
          icon={Shield}
          title="VEX Signing Service"
          sub="ECDSA P-256 · CYCLONEDX 1.4"
          isOnline={!error}
          detail={loading ? null : {
            'Algorithm':  'ECDSA P-256',
            'Format':     'CycloneDX 1.4',
            'Key':        'See /api/vex/public-key',
            'Status':     'Operational',
          }}
        />
      </div>

      {/* ETW Audit Log */}
      <div className="card" style={{ padding: 0, overflow: 'visible' }}>
        <div className="card-header" style={{
          padding: 'var(--space-3) var(--space-5)',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 'var(--space-3)',
          position: 'relative',
        }}>
          <span className="card-title">ETW Activation Audit Log</span>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            {/* Interactive Calendar Trigger & Dropdown Popup */}
            <div style={{ position: 'relative' }}>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setIsCalendarOpen(prev => !prev)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '4px 10px',
                  fontSize: 11,
                  fontFamily: 'var(--font-mono)',
                  backgroundColor: selectedDate !== 'ALL' ? 'rgba(56, 189, 248, 0.1)' : '#0E0E12',
                  border: selectedDate !== 'ALL' ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid rgba(255, 255, 255, 0.12)',
                  color: selectedDate !== 'ALL' ? '#38BDF8' : '#F5F5F7',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
                title="Shift days, months, and years to check ETW authentications"
              >
                <Calendar size={13} style={{ color: selectedDate !== 'ALL' ? '#38BDF8' : '#94A3B8' }} />
                <span>{selectedDate === 'ALL' ? 'All Days (Latest 10)' : selectedDate}</span>
              </button>

              <CalendarPicker
                selectedDate={selectedDate}
                onSelectDate={setSelectedDate}
                highlightDates={authDatesMap}
                isOpen={isCalendarOpen}
                onClose={() => setIsCalendarOpen(false)}
              />
            </div>

            <span className="card-hud-label" style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
              SHOWING {displayedLogs.length} OF {filteredLogs.length} ENTRIES
            </span>
          </div>
        </div>

        {displayedLogs.length === 0 ? (
          <EmptyState
            title="No audit entries"
            description={selectedDate !== 'ALL' ? `No ETW activation events found for ${selectedDate}.` : "ETW activation and deactivation events will appear here."}
          />
        ) : (
          <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>ACTION</th>
                  <th>RESULT</th>
                  <th>IP ADDRESS</th>
                  <th>DETAILS</th>
                </tr>
              </thead>
              <tbody>
                {displayedLogs.map((log) => (
                  <AuditRow key={log.id} log={log} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
