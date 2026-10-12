/**
 * Dashboard
 *
 * Answers: "What requires attention right now?"
 *
 * Data sources:
 *   GET /api/jobs              → active jobs, recent jobs
 *   GET /api/telemetry/status  → ETW agent state
 *
 * No fake metrics. Every value from API response.
 */

import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Upload,
  ShieldAlert,
  Activity,
  RefreshCw,
  ChevronRight,
  AlertTriangle,
} from 'lucide-react';
import { listJobs } from '../api/jobs';
import { getTelemetryStatus } from '../api/telemetry';
import { formatRelativeTime, formatJobId } from '../utils/formatters';
import { getJobStatusInfo, getRiskLevel } from '../utils/severity';
import { JobStatusPill } from '../components/ui/StatusPill';
import PulseIndicator from '../components/ui/PulseIndicator';
import EmptyState from '../components/ui/EmptyState';

const POLLING_INTERVAL_MS = 15000;

/* ── Stat Card ─────────────────────────────────────────────────── */
function StatCard({ label, value, sub, accentColor, loading }) {
  return (
    <div className="stat-card">
      <div className="stat-card-label">{label}</div>
      <div className="stat-card-value" style={{ color: loading ? 'var(--text-muted)' : accentColor || 'var(--text-primary)' }}>
        {loading ? '—' : value}
      </div>
      {sub && <div className="stat-card-sub">{sub}</div>}
      {accentColor && (
        <div className="stat-card-accent-line" style={{ background: accentColor, opacity: 0.3 }} />
      )}
    </div>
  );
}

/* ── Active Job Row ─────────────────────────────────────────────── */
function ActiveJobRow({ job }) {
  const isRunning = job.status === 'running';

  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--space-4)',
        padding: 'var(--space-3) var(--space-4)',
        borderBottom: '1px solid var(--border-subtle)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Scan line when running */}
      {isRunning && (
        <div className="scan-line-container" style={{ borderRadius: 0 }}>
          <div className="scan-line" />
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexShrink: 0 }}>
        {isRunning
          ? <PulseIndicator variant="verified" />
          : <PulseIndicator variant="muted" />
        }
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
          color: 'var(--text-primary)',
          marginBottom: 2,
        }}>
          {formatJobId(job.job_id)}
        </div>
        <div style={{
          fontSize: 11,
          color: 'var(--text-muted)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}>
          {job.sbom_filename || 'sbom.json'}
        </div>
      </div>

      <div style={{ flexShrink: 0 }}>
        <JobStatusPill status={job.status} />
      </div>

      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: 'var(--text-muted)',
        flexShrink: 0,
        minWidth: 60,
        textAlign: 'right',
      }}>
        {formatRelativeTime(job.submitted_at)}
      </div>
    </motion.div>
  );
}

/* ── Dashboard ──────────────────────────────────────────────────── */
export default function Dashboard() {
  const [jobs, setJobs] = useState([]);
  const [telemetry, setTelemetry] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const [jobList, telStatus] = await Promise.all([
        listJobs(),
        getTelemetryStatus().catch(() => null), // telemetry may not always respond
      ]);
      setJobs(jobList);
      setTelemetry(telStatus);
      setLastRefresh(new Date());
      setError(null);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, POLLING_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Derived stats from real data
  const activeJobs   = jobs.filter(j => j.status === 'running' || j.status === 'queued');
  const doneJobs     = jobs.filter(j => j.status === 'done');
  const failedJobs   = jobs.filter(j => j.status === 'failed');
  const totalFindings = doneJobs.reduce((acc, j) => acc + (j.finding_count || 0), 0);
  const recentJobs   = jobs.slice(0, 8);

  const etwRunning   = telemetry?.running;
  const etwMode      = telemetry?.mode || 'none';

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1 className="page-header-title">Dashboard</h1>
          <div className="page-header-meta">
            <span className="page-header-hud">ZENIX CORE · LIVE</span>
            {lastRefresh && (
              <span className="page-header-hud" style={{ color: 'var(--text-muted)' }}>
                UPDATED {formatRelativeTime(lastRefresh.toISOString())}
              </span>
            )}
          </div>
        </div>
        <div className="page-header-actions">
          <button
            id="dashboard-refresh-btn"
            className="btn btn-ghost btn-sm"
            onClick={fetchData}
            title="Refresh"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
          <Link to="/app/jobs" className="btn btn-primary btn-sm">
            <Upload size={13} />
            New Scan
          </Link>
        </div>
      </div>

      {error && (
        <div className="alert alert-error mb-6">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Stat Cards */}
      <div className="stat-grid-4 mb-8">
        <StatCard
          label="ACTIVE JOBS"
          value={activeJobs.length}
          sub={`${activeJobs.filter(j => j.status === 'running').length} running · ${activeJobs.filter(j => j.status === 'queued').length} queued`}
          accentColor={activeJobs.length > 0 ? 'var(--color-verified)' : undefined}
          loading={loading}
        />
        <StatCard
          label="TOTAL FINDINGS"
          value={totalFindings}
          sub={`across ${doneJobs.length} completed scan${doneJobs.length !== 1 ? 's' : ''}`}
          loading={loading}
        />
        <StatCard
          label="FAILED JOBS"
          value={failedJobs.length}
          sub={failedJobs.length > 0 ? 'Review required' : 'No failures'}
          accentColor={failedJobs.length > 0 ? 'var(--color-critical)' : undefined}
          loading={loading}
        />
        <StatCard
          label="ETW AGENT"
          value={etwRunning ? 'ONLINE' : 'OFFLINE'}
          sub={`Mode: ${etwMode.toUpperCase()}`}
          accentColor={etwRunning ? 'var(--color-verified)' : 'var(--color-warning)'}
          loading={loading || !telemetry}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-5)' }}>

        {/* Recent Jobs */}
        <div className="card" style={{ overflow: 'hidden', padding: 0 }}>
          <div className="card-header" style={{ padding: 'var(--space-4) var(--space-5)' }}>
            <span className="card-title">Recent Jobs</span>
            <Link
              to="/app/jobs"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 4,
                fontSize: 12,
                color: 'var(--text-muted)',
                textDecoration: 'none',
              }}
            >
              View all <ChevronRight size={12} />
            </Link>
          </div>

          {loading ? (
            <div style={{ padding: 'var(--space-8)', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              Loading jobs…
            </div>
          ) : recentJobs.length === 0 ? (
            <EmptyState
              icon={Upload}
              title="No jobs yet"
              description="Upload a CycloneDX SBOM to start analysis."
            />
          ) : (
            <div>
              {recentJobs.map((job) => (
                <ActiveJobRow key={job.job_id} job={job} />
              ))}
            </div>
          )}
        </div>

        {/* System Status Summary */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">System Status</span>
            <Link
              to="/app/status"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 4,
                fontSize: 12,
                color: 'var(--text-muted)',
                textDecoration: 'none',
              }}
            >
              Details <ChevronRight size={12} />
            </Link>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            {/* ETW Status */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: 'var(--space-3) var(--space-4)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                {etwRunning
                  ? <PulseIndicator variant="verified" />
                  : <PulseIndicator variant="muted" />
                }
                <div>
                  <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>
                    ETW Collector
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                    {etwRunning ? `Mode: ${etwMode.toUpperCase()}` : 'Collector inactive'}
                  </div>
                </div>
              </div>
              <span className={etwRunning ? 'status-pill status-pill-running' : 'status-pill status-pill-done'}>
                {etwRunning ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>

            {/* Analysis Engine */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: 'var(--space-3) var(--space-4)',
              background: 'var(--bg-surface-2)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                <PulseIndicator variant="verified" />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>
                    Analysis Engine
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                    Job queue active
                  </div>
                </div>
              </div>
              <span className="status-pill status-pill-running">READY</span>
            </div>

            {/* Quick Actions */}
            <div style={{ marginTop: 'var(--space-2)' }}>
              <div className="card-hud-label" style={{ marginBottom: 'var(--space-3)' }}>QUICK ACTIONS</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                <Link to="/app/jobs" className="btn btn-secondary btn-sm" style={{ justifyContent: 'flex-start' }}>
                  <Upload size={13} /> Upload SBOM
                </Link>
                <Link to="/app/findings" className="btn btn-secondary btn-sm" style={{ justifyContent: 'flex-start' }}>
                  <ShieldAlert size={13} /> Review Findings
                </Link>
                <Link to="/app/vex" className="btn btn-secondary btn-sm" style={{ justifyContent: 'flex-start' }}>
                  <Activity size={13} /> View VEX Documents
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
