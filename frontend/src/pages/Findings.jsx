/**
 * Findings Page — Core security analysis screen
 *
 * Purpose: Show every finding with context to make a security decision.
 *
 * Data sources:
 *   GET /api/jobs            → job selector
 *   GET /api/jobs/:id/result → findings, risk scores, reachability
 *
 * Per finding shows:
 *   CVE ID · Component · CVSS · EPSS · KEV · Reachability · Risk Score · Confidence
 *
 * Row expansion shows:
 *   Risk score breakdown (cvss_contrib, epss_contrib, kev_contrib, reachability_multiplier)
 *   Evidence source · Confidence notes · Reason
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChevronDown, ChevronRight, RefreshCw, AlertTriangle, Filter, X
} from 'lucide-react';
import { listJobs, getJobResult } from '../api/jobs';
import { formatCvss, formatEpss, formatScore, formatJobId } from '../utils/formatters';
import { getRiskLevel } from '../utils/severity';
import StatusPill from '../components/ui/StatusPill';
import EvidenceBadge from '../components/ui/EvidenceBadge';
import RiskScoreBar from '../components/ui/RiskScoreBar';
import EmptyState from '../components/ui/EmptyState';

/* ── Score breakdown panel (row expansion) ──────────────────────── */
function ScoreBreakdown({ finding }) {
  const rs = finding.risk_score;
  if (!rs) return null;

  const items = [
    { label: 'CVSS CONTRIB',     value: formatScore(rs.cvss_contrib) },
    { label: 'EPSS CONTRIB',     value: formatScore(rs.epss_contrib) },
    { label: 'KEV CONTRIB',      value: formatScore(rs.kev_contrib) },
    { label: 'BASE SCORE',       value: formatScore(rs.base_score) },
    { label: 'REACH. MULT.',     value: `×${formatScore(rs.reachability_multiplier)}` },
    { label: 'FINAL SCORE',      value: formatScore(rs.final_score) },
  ];

  return (
    <div>
      {/* Score breakdown grid */}
      <div className="score-breakdown" style={{ gridTemplateColumns: 'repeat(6, 1fr)', marginBottom: 'var(--space-4)' }}>
        {items.map(({ label, value }) => (
          <div key={label} className="score-breakdown-item">
            <div className="score-breakdown-label">{label}</div>
            <div className="score-breakdown-value"
              style={{
                fontSize: 16,
                color: label === 'FINAL SCORE'
                  ? getRiskLevel(rs.final_score).color
                  : 'var(--text-primary)',
              }}
            >
              {value}
            </div>
          </div>
        ))}
      </div>

      {/* Reason */}
      {rs.reason && (
        <div style={{
          padding: 'var(--space-3) var(--space-4)',
          background: 'var(--bg-surface-2)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)',
          marginBottom: 'var(--space-3)',
        }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 2, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>
            Risk Reason
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{rs.reason}</div>
        </div>
      )}

      {/* Confidence notes */}
      {rs.confidence_notes && rs.confidence_notes.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
          {rs.confidence_notes.map((note, i) => (
            <span key={i} style={{
              padding: '2px 8px',
              background: 'var(--color-warning-bg)',
              border: '1px solid var(--color-warning-border)',
              borderRadius: 'var(--radius-sm)',
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: 'var(--color-warning)',
            }}>
              {note}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Finding Row ─────────────────────────────────────────────────── */
function FindingRow({ finding, isExpanded, onToggle }) {
  const riskLevel = getRiskLevel(finding.risk_score?.final_score);
  const isKev = finding.vulnerability?.is_kev;

  return (
    <>
      <motion.tr
        className={isExpanded ? 'row-expanded' : ''}
        onClick={onToggle}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        {/* CVE ID */}
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
              color: 'var(--text-primary)',
              fontWeight: 500,
            }}>
              {finding.vulnerability?.cve_id || '—'}
            </span>
            {isKev && <span className="kev-badge">KEV</span>}
          </div>
        </td>

        {/* Component */}
        <td>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            {finding.component?.name}
          </div>
          {finding.component?.version && (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              v{finding.component.version}
            </div>
          )}
        </td>

        {/* CVSS */}
        <td className="cell-mono" style={{ color: 'var(--text-secondary)' }}>
          {formatCvss(finding.vulnerability?.cvss)}
        </td>

        {/* EPSS */}
        <td className="cell-mono" style={{ color: 'var(--text-secondary)' }}>
          {formatEpss(finding.vulnerability?.epss)}
        </td>

        {/* Reachability */}
        <td>
          <StatusPill status={finding.reachability?.status} />
        </td>

        {/* Evidence */}
        <td>
          <EvidenceBadge source={finding.reachability?.evidence_source} />
        </td>

        {/* Risk Score */}
        <td style={{ minWidth: 120 }}>
          <RiskScoreBar score={finding.risk_score?.final_score} showLabel />
        </td>

        {/* Confidence */}
        <td>
          <span className={`confidence-tag confidence-${(finding.risk_score?.confidence || 'low').toLowerCase()}`}>
            {(finding.risk_score?.confidence || '—').toUpperCase()}
          </span>
        </td>

        {/* Expand icon */}
        <td style={{ width: 32 }}>
          {isExpanded
            ? <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />
            : <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
          }
        </td>
      </motion.tr>

      {/* Expanded detail */}
      <AnimatePresence>
        {isExpanded && (
          <tr className="row-expansion">
            <td colSpan={9}>
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
              >
                <ScoreBreakdown finding={finding} />
              </motion.div>
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  );
}

/* ── Main Component ─────────────────────────────────────────────── */
export default function Findings() {
  const [jobs, setJobs] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState('');
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);

  // Filters
  const [filterReachability, setFilterReachability] = useState('');
  const [filterKev, setFilterKev] = useState(false);
  const [filterConfidence, setFilterConfidence] = useState('');
  const [sortCol, setSortCol] = useState('final_score');
  const [sortDir, setSortDir] = useState('desc');

  // Load jobs for selector
  useEffect(() => {
    (async () => {
      try {
        const data = await listJobs();
        // Only show completed jobs that have findings
        const done = data.filter(j => j.status === 'done');
        setJobs(done);
        if (done.length > 0) setSelectedJobId(done[0].job_id);
      } finally {
        setJobsLoading(false);
      }
    })();
  }, []);

  // Load findings when job selected
  useEffect(() => {
    if (!selectedJobId) return;
    setLoading(true);
    setError(null);
    setFindings([]);
    setExpandedRow(null);

    getJobResult(selectedJobId)
      .then((result) => {
        // result.findings is expected to be an array of finding objects
        // each with: { component, vulnerability, reachability, risk_score }
        const raw = result.findings || [];
        setFindings(raw);
      })
      .catch((err) => {
        setError(err.response?.data?.error || 'Failed to load findings.');
      })
      .finally(() => setLoading(false));
  }, [selectedJobId]);

  // Sort and filter
  const filtered = findings
    .filter(f => !filterReachability || (f.reachability?.status || '').toUpperCase() === filterReachability.toUpperCase())
    .filter(f => !filterKev || f.vulnerability?.is_kev === true)
    .filter(f => !filterConfidence || (f.risk_score?.confidence || '').toLowerCase() === filterConfidence.toLowerCase());

  const sorted = [...filtered].sort((a, b) => {
    const dir = sortDir === 'asc' ? 1 : -1;
    if (sortCol === 'final_score') {
      return dir * ((a.risk_score?.final_score || 0) - (b.risk_score?.final_score || 0));
    }
    if (sortCol === 'cvss') {
      return dir * ((a.vulnerability?.cvss || 0) - (b.vulnerability?.cvss || 0));
    }
    return 0;
  });

  const handleSort = (col) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  const toggleRow = (idx) => setExpandedRow(expandedRow === idx ? null : idx);

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1 className="page-header-title">Findings</h1>
          <div className="page-header-meta">
            <span className="page-header-hud">VULNERABILITY TRIAGE · EVIDENCE-BASED</span>
          </div>
        </div>
        <div className="page-header-actions">
          {/* Job selector */}
          {!jobsLoading && jobs.length > 0 && (
            <select
              id="findings-job-selector"
              className="select"
              value={selectedJobId}
              onChange={e => setSelectedJobId(e.target.value)}
              style={{ minWidth: 200 }}
            >
              {jobs.map(j => (
                <option key={j.job_id} value={j.job_id}>
                  {formatJobId(j.job_id)} · {j.sbom_filename || 'sbom.json'}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar">
        <Filter size={12} style={{ color: 'var(--text-muted)' }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase', marginRight: 4 }}>
          Filter:
        </span>
        {['REACHABLE', 'NOT_REACHABLE', 'UNKNOWN'].map(r => (
          <button
            key={r}
            className={`filter-chip ${filterReachability === r ? 'active' : ''}`}
            onClick={() => setFilterReachability(filterReachability === r ? '' : r)}
          >
            {r.replace('_', ' ')}
          </button>
        ))}
        <button
          className={`filter-chip ${filterKev ? 'active' : ''}`}
          onClick={() => setFilterKev(v => !v)}
        >
          KEV ONLY
        </button>
        {['high', 'medium', 'low'].map(c => (
          <button
            key={c}
            className={`filter-chip ${filterConfidence === c ? 'active' : ''}`}
            onClick={() => setFilterConfidence(filterConfidence === c ? '' : c)}
          >
            {c.toUpperCase()} CONF.
          </button>
        ))}
        {(filterReachability || filterKev || filterConfidence) && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => { setFilterReachability(''); setFilterKev(false); setFilterConfidence(''); }}
            style={{ marginLeft: 'auto' }}
          >
            <X size={12} /> Clear
          </button>
        )}
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
          {sorted.length} / {findings.length} findings
        </span>
      </div>

      {/* Error */}
      {error && (
        <div className="alert alert-error mb-4">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* No completed jobs */}
      {!jobsLoading && jobs.length === 0 && (
        <EmptyState
          title="No completed jobs"
          description="Submit an SBOM file and wait for analysis to complete before viewing findings."
        />
      )}

      {/* Findings Table */}
      {(jobs.length > 0 || loading) && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          {loading ? (
            <div style={{ padding: 'var(--space-8)', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              Loading findings…
            </div>
          ) : sorted.length === 0 ? (
            <EmptyState
              title="No findings match filters"
              description="Adjust the filters above to see findings."
            />
          ) : (
            <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>COMPONENT</th>
                    <th
                      className={sortCol === 'cvss' ? 'sort-active' : ''}
                      onClick={() => handleSort('cvss')}
                    >
                      CVSS
                    </th>
                    <th>EPSS</th>
                    <th>REACHABILITY</th>
                    <th>EVIDENCE</th>
                    <th
                      className={sortCol === 'final_score' ? 'sort-active' : ''}
                      onClick={() => handleSort('final_score')}
                    >
                      RISK SCORE ↕
                    </th>
                    <th>CONFIDENCE</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((finding, idx) => (
                    <FindingRow
                      key={`${finding.vulnerability?.cve_id}-${finding.component?.name}-${idx}`}
                      finding={finding}
                      isExpanded={expandedRow === idx}
                      onToggle={() => toggleRow(idx)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
