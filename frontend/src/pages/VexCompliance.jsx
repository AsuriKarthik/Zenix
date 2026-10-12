/**
 * VEX / Compliance Page
 *
 * Purpose: Auditable vulnerability decisions.
 *
 * Data sources:
 *   GET /api/vex               → VEX documents
 *   GET /api/vex/:id/download  → raw CycloneDX VEX JSON
 *   GET /api/vex/public-key    → ECDSA public key
 *
 * Displays:
 *   - VEX document table with sig validation
 *   - Download individual VEX documents
 *   - Filter by status
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  RefreshCw, Download, ShieldCheck, ShieldX, Key, AlertTriangle, Filter
} from 'lucide-react';
import { getVexDocuments, downloadVexDocument, getVexPublicKey } from '../api/vex';
import { listJobs } from '../api/jobs';
import { formatTimestamp, formatJobId } from '../utils/formatters';
import { getVexStatusInfo } from '../utils/severity';
import EmptyState from '../components/ui/EmptyState';

/* ── VEX Status Pill ─────────────────────────────────────────────── */
function VexStatusPill({ status }) {
  const { label, cssClass } = getVexStatusInfo(status);
  return (
    <span className={`status-pill vex-status-${cssClass}`} style={{ borderRadius: 4 }}>
      {label}
    </span>
  );
}

/* ── Signature indicator ────────────────────────────────────────── */
function SigValid({ valid }) {
  if (valid) {
    return (
      <span className="sig-valid">
        <ShieldCheck size={11} />
        ECDSA VALID
      </span>
    );
  }
  return (
    <span className="sig-valid sig-invalid">
      <ShieldX size={11} />
      INVALID
    </span>
  );
}

/* ── Main Component ─────────────────────────────────────────────── */
export default function VexCompliance() {
  const [docs, setDocs] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [jobFilter, setJobFilter] = useState('');
  const [publicKey, setPublicKey] = useState(null);
  const [showPublicKey, setShowPublicKey] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [vexData, jobList] = await Promise.all([
        getVexDocuments({
          status: statusFilter || undefined,
          job_id: jobFilter || undefined,
        }),
        listJobs(),
      ]);
      setDocs(vexData);
      setJobs(jobList.filter(j => j.status === 'done'));
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load VEX documents.');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, jobFilter]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleFetchPublicKey = async () => {
    if (publicKey) { setShowPublicKey(v => !v); return; }
    try {
      const pem = await getVexPublicKey();
      setPublicKey(pem);
      setShowPublicKey(true);
    } catch {
      setPublicKey('Failed to fetch public key.');
      setShowPublicKey(true);
    }
  };

  const sigValidCount   = docs.filter(d => d.signature_valid).length;
  const sigInvalidCount = docs.filter(d => !d.signature_valid).length;

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1 className="page-header-title">VEX / Compliance</h1>
          <div className="page-header-meta">
            <span className="page-header-hud">CYCLONEDX VEX · ECDSA SIGNED</span>
          </div>
        </div>
        <div className="page-header-actions">
          <button
            id="vex-public-key-btn"
            className="btn btn-ghost btn-sm"
            onClick={handleFetchPublicKey}
          >
            <Key size={13} />
            {showPublicKey ? 'Hide' : 'View'} Public Key
          </button>
          <button className="btn btn-ghost btn-sm" onClick={fetchData}>
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="stat-grid-3 mb-6">
        <div className="stat-card">
          <div className="stat-card-label">TOTAL DOCUMENTS</div>
          <div className="stat-card-value">{loading ? '—' : docs.length}</div>
          <div className="stat-card-sub">VEX statements generated</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">VALID SIGNATURES</div>
          <div className="stat-card-value" style={{ color: 'var(--color-verified)' }}>
            {loading ? '—' : sigValidCount}
          </div>
          <div className="stat-card-sub">ECDSA verified</div>
          <div className="stat-card-accent-line" style={{ background: 'var(--color-verified)', opacity: 0.3 }} />
        </div>
        <div className="stat-card">
          <div className="stat-card-label">INVALID SIGNATURES</div>
          <div className="stat-card-value" style={{ color: sigInvalidCount > 0 ? 'var(--color-critical)' : 'var(--text-primary)' }}>
            {loading ? '—' : sigInvalidCount}
          </div>
          <div className="stat-card-sub">{sigInvalidCount > 0 ? 'Review required' : 'All valid'}</div>
          {sigInvalidCount > 0 && (
            <div className="stat-card-accent-line" style={{ background: 'var(--color-critical)', opacity: 0.3 }} />
          )}
        </div>
      </div>

      {/* Public Key viewer */}
      {showPublicKey && publicKey && (
        <motion.div
          className="terminal-viewer mb-6"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
        >
          <div className="terminal-header">
            <span className="terminal-title">ECDSA PUBLIC KEY (PEM)</span>
          </div>
          <div className="terminal-body" style={{ fontSize: 11, color: 'var(--color-verified)', maxHeight: 180 }}>
            <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{publicKey}</pre>
          </div>
        </motion.div>
      )}

      {/* Filters */}
      <div className="filter-bar mb-4">
        <Filter size={12} style={{ color: 'var(--text-muted)' }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase' }}>Status:</span>
        {['', 'not_affected', 'affected', 'fixed', 'under_investigation'].map(s => (
          <button
            key={s || 'all'}
            className={`filter-chip ${statusFilter === s ? 'active' : ''}`}
            onClick={() => setStatusFilter(s)}
          >
            {s === '' ? 'ALL' : getVexStatusInfo(s).label}
          </button>
        ))}
        {jobs.length > 0 && (
          <>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase', marginLeft: 8 }}>Job:</span>
            <select
              id="vex-job-filter"
              className="select"
              style={{ width: 'auto', minWidth: 160 }}
              value={jobFilter}
              onChange={e => setJobFilter(e.target.value)}
            >
              <option value="">All Jobs</option>
              {jobs.map(j => (
                <option key={j.job_id} value={j.job_id}>
                  {formatJobId(j.job_id)}
                </option>
              ))}
            </select>
          </>
        )}
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
          {docs.length} DOCUMENT{docs.length !== 1 ? 'S' : ''}
        </span>
      </div>

      {error && (
        <div className="alert alert-error mb-4">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* VEX Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: 'var(--space-8)', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
            Loading VEX documents…
          </div>
        ) : docs.length === 0 ? (
          <EmptyState
            title="No VEX documents"
            description="VEX documents are generated automatically after SBOM analysis completes."
          />
        ) : (
          <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>VEX ID</th>
                  <th>CVE ID</th>
                  <th>JOB</th>
                  <th>STATUS</th>
                  <th>JUSTIFICATION</th>
                  <th>SIGNATURE</th>
                  <th>GENERATED</th>
                  <th>DOWNLOAD</th>
                </tr>
              </thead>
              <tbody>
                {docs.map((doc) => (
                  <motion.tr
                    key={doc.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                  >
                    <td className="cell-mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {doc.vex_id?.slice(0, 16)}…
                    </td>
                    <td className="cell-mono" style={{ color: 'var(--text-primary)', fontSize: 12 }}>
                      {doc.cve_id}
                    </td>
                    <td className="cell-mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                      {formatJobId(doc.job_id)}
                    </td>
                    <td><VexStatusPill status={doc.status} /></td>
                    <td style={{ maxWidth: 200 }}>
                      <span style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {doc.justification || '—'}
                      </span>
                    </td>
                    <td><SigValid valid={doc.signature_valid} /></td>
                    <td className="cell-mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                      {formatTimestamp(doc.generated_at)}
                    </td>
                    <td>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => downloadVexDocument(doc.vex_id, `${doc.vex_id}.cdx.json`)}
                        title="Download CycloneDX VEX JSON"
                      >
                        <Download size={13} />
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
