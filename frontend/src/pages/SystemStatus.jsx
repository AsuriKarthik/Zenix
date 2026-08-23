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

import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { RefreshCw, AlertTriangle, Server, Database, Shield, Activity } from 'lucide-react';
import { getTelemetryStatus, getAuditLogs } from '../api/telemetry';
import { formatTimestamp, formatRelativeTime } from '../utils/formatters';
import PulseIndicator from '../components/ui/PulseIndicator';
import EmptyState from '../components/ui/EmptyState';

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
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="card-header" style={{ padding: 'var(--space-4) var(--space-5)', borderBottom: '1px solid var(--border-subtle)' }}>
          <span className="card-title">ETW Activation Audit Log</span>
          <span className="card-hud-label">{auditLogs.length} ENTRIES</span>
        </div>

        {auditLogs.length === 0 ? (
          <EmptyState
            title="No audit entries"
            description="ETW activation and deactivation events will appear here."
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
                {auditLogs.map((log) => (
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
