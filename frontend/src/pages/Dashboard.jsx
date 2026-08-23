/**
 * Dashboard / Overview Page — Zenix Security Platform
 *
 * Evidence-driven security triage overview:
 *   - Primary Metrics: Real numbers from backend DB for Total Findings, Reachable, Unknown, KEV & High Risk
 *   - Security Triage Summary Banner
 *   - Middle Section: Priority Queue (Full Width with 5 items per page pagination: Prev / Page numbers / Next)
 *   - Bottom Section: Recent Scans (Left 65%) + Latest Vulnerabilities & Threats (Right 35%)
 */

import React, { useEffect, useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Upload,
  RefreshCw,
  ChevronRight,
  ChevronLeft,
  AlertTriangle,
  ExternalLink,
  ShieldCheck,
  ArrowRight,
  Flame,
  Clock,
  ExternalLink as LinkIcon,
  Radio,
} from 'lucide-react';
import { listJobs, getTriageSummary, getLatestThreats } from '../api/jobs';
import { getTelemetryStatus } from '../api/telemetry';
import { formatRelativeTime, formatJobId, formatScore } from '../utils/formatters';
import { JobStatusPill } from '../components/ui/StatusPill';
import EmptyState from '../components/ui/EmptyState';

const POLLING_INTERVAL_MS = 15000;
const PQ_ITEMS_PER_PAGE = 5;

/* ── Glassmorphism Container Style ─────────────────────────────── */
const GLASS_CARD_STYLE = {
  background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.01) 100%)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  borderRadius: '16px',
  boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.1), 0 8px 32px 0 rgba(0, 0, 0, 0.36)',
  transition: 'all 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
};

/* ── Count Up Animated Number Component ────────────────────────── */
function CountUpNumber({ value, duration = 1200 }) {
  const [displayVal, setDisplayVal] = useState(0);

  useEffect(() => {
    if (value === '—' || value === null || value === undefined) {
      setDisplayVal(value);
      return;
    }
    const target = typeof value === 'number' ? value : parseInt(value, 10);
    if (isNaN(target)) {
      setDisplayVal(value);
      return;
    }

    if (target === 0) {
      setDisplayVal(0);
      return;
    }

    let startTime = null;

    const animateCount = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      const current = Math.floor(easeProgress * target);
      setDisplayVal(current);

      if (progress < 1) {
        requestAnimationFrame(animateCount);
      } else {
        setDisplayVal(target);
      }
    };

    requestAnimationFrame(animateCount);
  }, [value, duration]);

  return <span>{displayVal}</span>;
}

/* ── Primary Metric Card ────────────────────────────────────────── */
function PrimaryMetricCard({ label, value, sub, color }) {
  return (
    <div 
      style={{
        ...GLASS_CARD_STYLE,
        padding: 'var(--space-4) var(--space-5)',
      }}
    >
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: 1.2,
        color: 'rgba(255, 255, 255, 0.5)',
        textTransform: 'uppercase',
        marginBottom: 6,
      }}>
        {label}
      </div>
      <div style={{
        fontFamily: 'var(--font-heading)',
        fontSize: 28,
        fontWeight: 800,
        color: color || '#FFFFFF',
        lineHeight: 1.1,
      }}>
        <CountUpNumber value={value} />
      </div>
      {sub && (
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'rgba(255, 255, 255, 0.5)',
          marginTop: 6,
        }}>
          {sub}
        </div>
      )}
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState([]);
  const [triageData, setTriageData] = useState(null);
  const [telemetry, setTelemetry] = useState(null);
  const [latestThreats, setLatestThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [refreshing, setRefreshing] = useState(false);
  
  // Priority Queue Pagination State (5 items per page)
  const [pqPage, setPqPage] = useState(1);

  const fetchData = useCallback(async () => {
    try {
      const [jobList, triageRes, telStatus, threatRes] = await Promise.all([
        listJobs(),
        getTriageSummary().catch(() => null),
        getTelemetryStatus().catch(() => null),
        getLatestThreats().catch(() => null),
      ]);
      setJobs(jobList);
      setTriageData(triageRes);
      setTelemetry(telStatus);
      if (threatRes?.threats) setLatestThreats(threatRes.threats);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load triage overview data.');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleManualRefresh = async () => {
    setRefreshing(true);
    await fetchData();
    setRefreshing(false);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, POLLING_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchData]);

  const recentJobs     = jobs.slice(0, 6);
  const metrics        = triageData?.metrics || { needs_attention: 0, reachable: 0, unknown: 0, high_confidence: 0, total_findings: 0, kev_count: 0 };
  const priorityQueue  = triageData?.priority_queue || [];

  // Pagination Math for Priority Queue
  const totalPqPages    = Math.max(1, Math.ceil(priorityQueue.length / PQ_ITEMS_PER_PAGE));
  const currentPqItems  = priorityQueue.slice((pqPage - 1) * PQ_ITEMS_PER_PAGE, pqPage * PQ_ITEMS_PER_PAGE);

  useEffect(() => {
    if (pqPage > totalPqPages && totalPqPages > 0) {
      setPqPage(1);
    }
  }, [priorityQueue.length, totalPqPages, pqPage]);

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto' }}>
      
      {/* Top Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 'var(--space-6)',
        paddingBottom: 'var(--space-4)',
        borderBottom: '1px solid var(--border-subtle)',
      }}>
        <div>
          <h1 style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 24,
            fontWeight: 700,
            color: '#FFFFFF',
            letterSpacing: '-0.5px',
            margin: 0,
          }}>
            Overview
          </h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'rgba(255, 255, 255, 0.5)', marginTop: 2 }}>
            EVIDENCE-DRIVEN VULNERABILITY TRIAGE
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <Link to="/app/jobs" className="btn btn-primary btn-sm">
            <Upload size={13} />
            New Scan
          </Link>
        </div>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: 'var(--space-6)' }}>
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Primary Overview Metric Cards (Real Database Numbers) */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 'var(--space-4)',
        marginBottom: 'var(--space-6)',
      }}>
        <PrimaryMetricCard
          label="TOTAL FINDINGS"
          value={loading ? '—' : (metrics.total_findings ?? metrics.needs_attention)}
          sub="Identified CVEs across scans"
          color="#FFFFFF"
        />
        <PrimaryMetricCard
          label="REACHABLE THREATS"
          value={loading ? '—' : metrics.reachable}
          sub="Active memory & process execution"
          color={metrics.reachable > 0 ? 'var(--color-critical)' : 'var(--color-verified)'}
        />
        <PrimaryMetricCard
          label="UNKNOWN REACHABILITY"
          value={loading ? '—' : metrics.unknown}
          sub="Awaiting telemetry profiling"
          color={metrics.unknown > 0 ? 'rgba(255, 255, 255, 0.8)' : undefined}
        />
        <PrimaryMetricCard
          label="KEV & HIGH RISK"
          value={loading ? '—' : (metrics.kev_count > 0 ? metrics.kev_count : metrics.high_confidence)}
          sub="CISA KEV & High Severity Intel"
          color="var(--color-accent)"
        />
      </div>

      {/* Security Triage Summary Banner */}
      <div 
        style={{
          ...GLASS_CARD_STYLE,
          background: 'linear-gradient(135deg, rgba(234, 179, 8, 0.08) 0%, rgba(239, 68, 68, 0.04) 100%)',
          border: '1px solid rgba(234, 179, 8, 0.25)',
          padding: 'var(--space-5) var(--space-6)',
          marginBottom: 'var(--space-6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 1.5, color: 'var(--color-warning)', textTransform: 'uppercase', marginBottom: 4, fontWeight: 700 }}>
            SECURITY TRIAGE SUMMARY
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#FFFFFF' }}>
            {loading ? 'Analyzing security decision state…' : `${metrics.needs_attention || metrics.total_findings} vulnerability finding${(metrics.needs_attention || metrics.total_findings) === 1 ? '' : 's'} require analyst review`}
          </div>
          <div style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.6)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            {metrics.reachable} Reachable · {metrics.unknown} Unknown Reachability · {metrics.high_confidence} High Confidence
          </div>
        </div>
        <button
          className="btn btn-primary btn-md"
          onClick={() => navigate('/app/findings?filter=needs_attention')}
          style={{ gap: 'var(--space-2)' }}
        >
          Review Findings <ArrowRight size={14} />
        </button>
      </div>

      {/* Middle Section: Priority Queue (Full Width with 5 Items per Page Pagination) */}
      <div 
        style={{ ...GLASS_CARD_STYLE, marginBottom: 'var(--space-6)', overflow: 'hidden' }}
      >
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: 'var(--space-5) var(--space-6)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          flexWrap: 'wrap',
          gap: 'var(--space-3)',
        }}>
          <div>
            <div style={{ fontFamily: 'var(--font-heading)', fontSize: 15, fontWeight: 700, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: 8 }}>
              Priority Queue
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                color: 'var(--color-accent)', background: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: 4, padding: '2px 7px',
              }}>
                PAGE {pqPage} OF {totalPqPages}
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'rgba(255, 255, 255, 0.5)', marginTop: 2 }}>
              Highest risk vulnerabilities deserving analyst attention first (5 per page)
            </div>
          </div>

          {/* Pagination Shift Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <button
                className="btn btn-ghost btn-sm"
                disabled={pqPage <= 1}
                onClick={() => setPqPage(p => Math.max(1, p - 1))}
                style={{ padding: '3px 8px', fontSize: 11, opacity: pqPage <= 1 ? 0.4 : 1, cursor: pqPage <= 1 ? 'not-allowed' : 'pointer' }}
                title="Previous 5 Items"
              >
                <ChevronLeft size={14} /> Prev
              </button>

              {Array.from({ length: totalPqPages }, (_, i) => i + 1).slice(0, 6).map(pg => (
                <button
                  key={pg}
                  onClick={() => setPqPage(pg)}
                  style={{
                    padding: '2px 8px',
                    borderRadius: 4,
                    fontSize: 11,
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    cursor: 'pointer',
                    border: pqPage === pg ? '1px solid var(--color-accent)' : '1px solid rgba(255, 255, 255, 0.1)',
                    background: pqPage === pg ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255, 255, 255, 0.03)',
                    color: pqPage === pg ? 'var(--color-accent)' : 'rgba(255, 255, 255, 0.7)',
                  }}
                >
                  {pg}
                </button>
              ))}

              <button
                className="btn btn-ghost btn-sm"
                disabled={pqPage >= totalPqPages}
                onClick={() => setPqPage(p => Math.min(totalPqPages, p + 1))}
                style={{ padding: '3px 8px', fontSize: 11, opacity: pqPage >= totalPqPages ? 0.4 : 1, cursor: pqPage >= totalPqPages ? 'not-allowed' : 'pointer' }}
                title="Next 5 Items"
              >
                Next <ChevronRight size={14} />
              </button>
            </div>

            <Link to="/app/findings?filter=needs_attention" style={{ fontSize: 11, color: 'var(--color-accent)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'var(--font-mono)', marginLeft: 8 }}>
              VIEW ALL FINDINGS <ChevronRight size={12} />
            </Link>
          </div>
        </div>

        {loading ? (
          <div style={{ padding: 'var(--space-8)', textAlign: 'center', color: 'rgba(255, 255, 255, 0.5)', fontSize: 13 }}>
            Computing priority queue…
          </div>
        ) : currentPqItems.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No high-priority findings requiring attention"
            description="Submit an SBOM on the Analyze page to run evidence-driven triage."
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {currentPqItems.map((item, idx) => {
              const reachability = (item.reachability_status || 'UNKNOWN').toUpperCase();
              return (
                <div
                  key={`${item.cve_id}-${item.vulnerability_id}-${idx}`}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: 'var(--space-4) var(--space-6)',
                    borderBottom: idx < currentPqItems.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none',
                    background: idx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', flex: 1.5 }}>
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: 'var(--color-accent)', display: 'flex', alignItems: 'center', gap: 6 }}>
                        {item.cve_id}
                        {item.is_kev && (
                          <span style={{
                            fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
                            color: 'var(--color-critical)', background: 'var(--color-critical-bg)',
                            border: '1px solid var(--color-critical-border)', borderRadius: 3, padding: '1px 5px',
                          }}>
                            KEV
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: 12, color: '#FFFFFF', marginTop: 2 }}>
                        {item.component_name} <span style={{ color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>v{item.component_version || '0.0.0'}</span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flex: 1.2 }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                      color: reachability === 'REACHABLE' ? 'var(--color-critical)' : reachability === 'NOT_REACHABLE' ? 'var(--color-verified)' : 'rgba(255, 255, 255, 0.6)',
                      background: reachability === 'REACHABLE' ? 'var(--color-critical-bg)' : reachability === 'NOT_REACHABLE' ? 'var(--color-verified-bg)' : 'rgba(255, 255, 255, 0.05)',
                      border: `1px solid ${reachability === 'REACHABLE' ? 'var(--color-critical-border)' : reachability === 'NOT_REACHABLE' ? 'var(--color-verified-border)' : 'rgba(255, 255, 255, 0.1)'}`,
                      borderRadius: 4, padding: '2px 7px',
                    }}>
                      {reachability}
                    </span>

                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'rgba(255, 255, 255, 0.5)' }}>
                      {item.confidence} CONF.
                    </span>
                  </div>

                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: '#FFFFFF', flex: 0.8 }}>
                    Risk {formatScore(item.final_score)}
                  </div>

                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => navigate(`/app/findings?jobId=${item.job_id}&cveId=${item.cve_id}`)}
                    title="Investigate finding detail"
                    style={{ color: 'var(--color-accent)', padding: '4px 8px' }}
                  >
                    <ArrowRight size={14} />
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Bottom Grid: Recent Analysis Scans Table (Left 65%) & Latest Threat Feed (Right 35%) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.6fr', gap: 'var(--space-6)' }}>

        {/* Recent Analysis Scans Table */}
        <div 
          style={{
            ...GLASS_CARD_STYLE,
            overflow: 'hidden',
          }}
        >
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: 'var(--space-5) var(--space-6)',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          }}>
            <span style={{ fontFamily: 'var(--font-heading)', fontSize: 15, fontWeight: 700, color: '#FFFFFF' }}>
              Recent Scans
            </span>
            <Link to="/app/jobs" style={{ fontSize: 11, color: 'var(--color-accent)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'var(--font-mono)' }}>
              VIEW ALL SCANS <ChevronRight size={12} />
            </Link>
          </div>

          {loading ? (
            <div style={{ padding: 'var(--space-8)', textAlign: 'center', color: 'rgba(255, 255, 255, 0.5)', fontSize: 13 }}>
              Loading scans…
            </div>
          ) : recentJobs.length === 0 ? (
            <EmptyState
              icon={Upload}
              title="No scans yet"
              description="Upload an SBOM on the Analyze page to start your first scan."
            />
          ) : (
            <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0, background: 'transparent' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>SCAN ID</th>
                    <th>SCAN NAME</th>
                    <th>TOTAL</th>
                    <th>REACHABLE</th>
                    <th>UNKNOWN</th>
                    <th>STATUS</th>
                    <th>CREATED</th>
                    <th style={{ textAlign: 'right' }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {recentJobs.map(j => {
                    const isDone = j.status === 'done';
                    return (
                      <tr key={j.job_id} style={{ cursor: isDone ? 'pointer' : 'default' }} onClick={() => {
                        if (isDone) navigate(`/app/findings?jobId=${j.job_id}`);
                      }}>
                        <td className="cell-mono cell-primary" style={{ fontSize: 12 }}>
                          {formatJobId(j.job_id)}
                        </td>
                        <td style={{ fontSize: 13, color: 'rgba(255, 255, 255, 0.95)', fontWeight: 500, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {j.sbom_filename || 'sbom.json'}
                        </td>
                        <td className="cell-mono" style={{ fontSize: 12, fontWeight: 600 }}>
                          {j.status === 'done' ? (j.finding_count ?? 0) : '—'}
                        </td>
                        <td className="cell-mono" style={{ fontSize: 12, fontWeight: 700, color: j.reachable_count > 0 ? 'var(--color-critical)' : 'rgba(255, 255, 255, 0.7)' }}>
                          {j.status === 'done' ? (j.reachable_count ?? 0) : '—'}
                        </td>
                        <td className="cell-mono" style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.7)' }}>
                          {j.status === 'done' ? (j.unknown_count ?? 0) : '—'}
                        </td>
                        <td>
                          <JobStatusPill status={j.status} />
                        </td>
                        <td className="cell-mono" style={{ fontSize: 11, color: 'rgba(255, 255, 255, 0.5)' }}>
                          {formatRelativeTime(j.submitted_at)}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          {isDone ? (
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate(`/app/findings?jobId=${j.job_id}`);
                              }}
                              title="Open Findings for this scan"
                              style={{ padding: '4px 8px', color: 'var(--color-accent)' }}
                            >
                              <ExternalLink size={14} />
                            </button>
                          ) : (
                            <span style={{ fontSize: 11, color: 'rgba(255, 255, 255, 0.4)' }}>—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Latest Vulnerabilities & Threats Feed Box (Right Side) */}
        <div 
          style={{
            ...GLASS_CARD_STYLE,
            padding: 'var(--space-6)',
          }}
        >
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 'var(--space-4)',
            paddingBottom: 'var(--space-3)',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          }}>
            <div>
              <span style={{ fontFamily: 'var(--font-heading)', fontSize: 14, fontWeight: 700, color: '#FFFFFF', letterSpacing: 0.5, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Flame size={15} style={{ color: '#f97316' }} /> LATEST THREAT INTEL
              </span>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'rgba(255,255,255,0.4)', marginTop: 2 }}>
                CISA KEV CATALOG & REAL-TIME FEED
              </div>
            </div>
            <a 
              href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" 
              target="_blank" 
              rel="noopener noreferrer"
              style={{ fontSize: 10, color: 'var(--color-accent)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 3, fontFamily: 'var(--font-mono)' }}
            >
              FEED <LinkIcon size={11} />
            </a>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', maxHeight: 380, overflowY: 'auto', paddingRight: 2 }}>
            {latestThreats.length === 0 ? (
              <div style={{ padding: 'var(--space-6) var(--space-4)', textAlign: 'center', color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: '#f59e0b', padding: '4px 10px', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: 6, marginBottom: 8, fontWeight: 600 }}>
                  FEED OFFLINE
                </div>
                <div>Live threat feed unreachable or offline</div>
              </div>
            ) : (
              latestThreats.slice(0, 4).map((threat, tIdx) => (
                <div key={threat.cve_id || tIdx} style={{
                  background: 'rgba(255, 255, 255, 0.03)',
                  backdropFilter: 'blur(12px)',
                  WebkitBackdropFilter: 'blur(12px)',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  borderRadius: '12px',
                  padding: 'var(--space-3) var(--space-4)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: '#DAFC6F' }}>
                      {threat.cve_id}
                    </span>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 9,
                      fontWeight: 700,
                      color: threat.severity === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-warning)',
                      background: threat.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(245, 158, 11, 0.1)',
                      border: threat.severity === 'CRITICAL' ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(245, 158, 11, 0.3)',
                      borderRadius: 4,
                      padding: '1px 5px',
                    }}>
                      {threat.severity || 'CRITICAL'}
                    </span>
                  </div>

                  <div style={{ fontSize: 12, fontWeight: 600, color: '#FFFFFF', marginBottom: 4, lineHeight: 1.3 }}>
                    {threat.title}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)' }}>
                    <span>{threat.vendor} · {threat.product}</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                      <Clock size={10} /> {threat.date_added}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
