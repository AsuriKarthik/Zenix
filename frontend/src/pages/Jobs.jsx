/**
 * Jobs Page — Submit / Jobs
 *
 * Purpose: SBOM processing workflow.
 *
 * Data sources:
 *   POST /api/jobs/upload  → upload + enqueue SBOM
 *   GET  /api/jobs         → list jobs
 *   GET  /api/jobs/:id/status → poll running jobs
 *
 * Features:
 *   - Drag-and-drop CycloneDX JSON upload (max 10MB)
 *   - Real validation errors from backend
 *   - Job queue table with live status polling
 *   - Scan line animation on running jobs
 */

import React, { useState, useCallback, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload,
  FileJson,
  X,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { uploadSbom, listJobs, getJobStatus } from '../api/jobs';
import { formatRelativeTime, formatJobId, formatDuration, truncateHash } from '../utils/formatters';
import { JobStatusPill } from '../components/ui/StatusPill';
import EmptyState from '../components/ui/EmptyState';

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB — matches backend
const POLL_INTERVAL_MS = 5000;

/* ── Upload Zone ────────────────────────────────────────────────── */
function UploadZone({ onUpload, uploading, uploadError, uploadResult }) {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);

  const handleFile = useCallback((file) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.json')) {
      return;
    }
    setSelectedFile(file);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    handleFile(file);
  }, [handleFile]);

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => setDragOver(false);

  const handleInputChange = (e) => {
    handleFile(e.target.files?.[0]);
  };

  const handleSubmit = async () => {
    if (!selectedFile) return;
    await onUpload(selectedFile);
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const clearFile = () => {
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="card mb-6">
      <div className="card-header">
        <span className="card-title">Upload SBOM</span>
        <span className="card-hud-label">CYCLONEDX JSON · MAX 10MB</span>
      </div>

      {/* Drop zone */}
      <div
        id="sbom-upload-zone"
        className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => !selectedFile && fileInputRef.current?.click()}
        style={selectedFile ? { cursor: 'default' } : {}}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".json"
          style={{ display: 'none' }}
          onChange={handleInputChange}
          id="sbom-file-input"
        />

        {selectedFile ? (
          <div onClick={(e) => e.stopPropagation()}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-3)',
              justifyContent: 'center',
              marginBottom: 'var(--space-4)',
            }}>
              <FileJson size={22} style={{ color: 'var(--color-nav)' }} />
              <div>
                <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-primary)' }}>
                  {selectedFile.name}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                  {(selectedFile.size / 1024).toFixed(1)} KB
                  {selectedFile.size > MAX_FILE_SIZE_BYTES && (
                    <span style={{ color: 'var(--color-critical)', marginLeft: 8 }}>
                      EXCEEDS 10MB LIMIT
                    </span>
                  )}
                </div>
              </div>
              <button
                className="btn btn-ghost btn-sm"
                onClick={clearFile}
                style={{ marginLeft: 8 }}
              >
                <X size={14} />
              </button>
            </div>
            <button
              id="sbom-upload-btn"
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={uploading || selectedFile.size > MAX_FILE_SIZE_BYTES}
            >
              {uploading ? (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: 1 }}>
                  UPLOADING…
                </span>
              ) : (
                <>
                  <Upload size={14} />
                  Start Analysis
                </>
              )}
            </button>
          </div>
        ) : (
          <>
            <Upload className="upload-zone-icon" />
            <div className="upload-zone-title">Drop CycloneDX JSON here</div>
            <div className="upload-zone-sub">or click to browse</div>
            <div className="upload-zone-limit">SUPPORTS: CYCLONEDX 1.4+ · MAX 10 MB</div>
          </>
        )}
      </div>

      {/* Upload result / error */}
      <AnimatePresence mode="wait">
        {uploadError && (
          <motion.div
            className="alert alert-error"
            style={{ marginTop: 'var(--space-4)' }}
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
          >
            <AlertTriangle size={14} style={{ flexShrink: 0 }} />
            {uploadError}
          </motion.div>
        )}
        {uploadResult && (
          <motion.div
            className="alert alert-success"
            style={{ marginTop: 'var(--space-4)' }}
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
          >
            <CheckCircle size={14} style={{ flexShrink: 0 }} />
            <div>
              Job queued successfully.{' '}
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                ID: {formatJobId(uploadResult.job_id)}
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ── Job Row ────────────────────────────────────────────────────── */
function JobRow({ job, onSelect, isSelected }) {
  const isRunning = job.status === 'running';

  return (
    <motion.tr
      className={isSelected ? 'row-expanded' : ''}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      style={{ position: 'relative', overflow: 'hidden' }}
      onClick={() => onSelect(isSelected ? null : job.job_id)}
    >
      {/* Scan line for running jobs */}
      {isRunning && (
        <td colSpan={6} style={{ padding: 0, position: 'absolute', inset: 0, pointerEvents: 'none' }}>
          <div className="scan-line-container" style={{ borderRadius: 0 }}>
            <div className="scan-line" />
          </div>
        </td>
      )}

      <td className="cell-mono cell-primary">
        {formatJobId(job.job_id)}
      </td>
      <td style={{ color: 'var(--text-secondary)', fontSize: 13, maxWidth: 200 }}>
        <span className="truncate" style={{ display: 'block' }}>
          {job.sbom_filename || '—'}
        </span>
      </td>
      <td><JobStatusPill status={job.status} /></td>
      <td className="cell-mono" style={{ color: 'var(--text-secondary)' }}>
        {job.component_count ?? '—'}
      </td>
      <td className="cell-mono" style={{ color: 'var(--text-secondary)' }}>
        {job.finding_count ?? '—'}
      </td>
      <td className="cell-mono" style={{ color: 'var(--text-muted)' }}>
        {formatRelativeTime(job.submitted_at)}
      </td>
    </motion.tr>
  );
}

/* ── Job Detail Expansion ───────────────────────────────────────── */
function JobDetail({ job }) {
  if (!job) return null;
  return (
    <tr className="row-expansion">
      <td colSpan={6}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 'var(--space-4)',
        }}>
          {[
            { label: 'JOB ID',       value: job.job_id, mono: true },
            { label: 'SBOM SHA256',  value: truncateHash(job.sbom_sha256, 20), mono: true },
            { label: 'SUBMITTED',    value: new Date(job.submitted_at).toLocaleString() },
            { label: 'DURATION',     value: formatDuration(job.submitted_at, job.finished_at) },
          ].map(({ label, value, mono }) => (
            <div key={label}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 2, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase' }}>
                {label}
              </div>
              <div style={{ fontFamily: mono ? 'var(--font-mono)' : 'var(--font-body)', fontSize: 12, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                {value || '—'}
              </div>
            </div>
          ))}
          {job.error_msg && (
            <div style={{ gridColumn: '1 / -1' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 2, color: 'var(--color-critical)', marginBottom: 6, textTransform: 'uppercase' }}>
                ERROR
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-critical)' }}>{job.error_msg}</div>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}

/* ── Main Component ─────────────────────────────────────────────── */
export default function Jobs() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [selectedJobId, setSelectedJobId] = useState(null);
  const [listError, setListError] = useState(null);

  const fetchJobs = useCallback(async () => {
    try {
      const data = await listJobs();
      setJobs(data);
      setListError(null);
    } catch (err) {
      setListError(err.response?.data?.error || 'Failed to load jobs.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchJobs();
    const interval = setInterval(fetchJobs, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchJobs]);

  const handleUpload = async (file) => {
    setUploading(true);
    setUploadError(null);
    setUploadResult(null);
    try {
      const result = await uploadSbom(file);
      setUploadResult(result);
      // Immediately refresh job list to show queued job
      await fetchJobs();
    } catch (err) {
      setUploadError(err.response?.data?.error || 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  const selectedJob = jobs.find(j => j.job_id === selectedJobId) || null;

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1 className="page-header-title">Submit / Jobs</h1>
          <div className="page-header-meta">
            <span className="page-header-hud">SBOM ANALYSIS PIPELINE</span>
          </div>
        </div>
        <div className="page-header-actions">
          <button
            id="jobs-refresh-btn"
            className="btn btn-ghost btn-sm"
            onClick={fetchJobs}
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
      </div>

      {/* Upload Zone */}
      <UploadZone
        onUpload={handleUpload}
        uploading={uploading}
        uploadError={uploadError}
        uploadResult={uploadResult}
      />

      {/* Job Queue Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="card-header" style={{ padding: 'var(--space-4) var(--space-5)', borderBottom: '1px solid var(--border-subtle)' }}>
          <span className="card-title">Job Queue</span>
          <span className="card-hud-label">{jobs.length} JOB{jobs.length !== 1 ? 'S' : ''}</span>
        </div>

        {listError && (
          <div className="alert alert-error" style={{ margin: 'var(--space-4)' }}>
            <AlertTriangle size={14} />
            {listError}
          </div>
        )}

        {loading ? (
          <div style={{ padding: 'var(--space-8)', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
            Loading jobs…
          </div>
        ) : jobs.length === 0 ? (
          <EmptyState
            icon={Clock}
            title="No jobs submitted"
            description="Upload a CycloneDX JSON SBOM above to start vulnerability analysis."
          />
        ) : (
          <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>JOB ID</th>
                  <th>SBOM FILE</th>
                  <th>STATUS</th>
                  <th>COMPONENTS</th>
                  <th>FINDINGS</th>
                  <th>SUBMITTED</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <React.Fragment key={job.job_id}>
                    <JobRow
                      job={job}
                      onSelect={setSelectedJobId}
                      isSelected={selectedJobId === job.job_id}
                    />
                    {selectedJobId === job.job_id && (
                      <JobDetail job={selectedJob} />
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
