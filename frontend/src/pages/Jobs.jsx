/**
 * Jobs Page — Analyze / Submit
 *
 * Uniform Frosted Glassmorphism Design across Upload Zone and Job Queue
 */

import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ExternalLink,
  Loader2,
  Bell,
  X,
  RotateCcw,
  Trash2,
} from 'lucide-react';

import { uploadSbom, listJobs, deleteJob } from '../api/jobs';

import { formatRelativeTime, formatJobId } from '../utils/formatters';
import { JobStatusPill } from '../components/ui/StatusPill';
import EmptyState from '../components/ui/EmptyState';

const POLL_INTERVAL_MS = 5000;

/* ── Uniform Glassmorphism Card Style ──────────────────────────── */
const GLASS_CARD_STYLE = {
  background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.01) 100%)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  borderRadius: '16px',
  boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.1), 0 8px 32px 0 rgba(0, 0, 0, 0.36)',
};

/* ── Upload Zone ────────────────────────────────────────────────── */
function UploadZone({ onUpload, uploading, uploadError, uploadResult }) {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanName, setScanName] = useState('');
  const fileInputRef = useRef(null);

  const handleFile = useCallback((file) => {
    if (!file) return;
    const fname = file.name.toLowerCase();
    const valid = ['.json', '.xml', '.spdx', '.txt', '.cdx'].some(ext => fname.endsWith(ext));
    if (!valid) return;
    setSelectedFile(file);
    if (!scanName) {
      const defaultName = file.name.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' ');
      setScanName(defaultName);
    }
  }, [scanName]);

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

  const handleSubmit = async () => {
    if (!selectedFile) return;
    await onUpload(selectedFile, scanName);
    setSelectedFile(null);
    setScanName('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const clearFile = () => {
    setSelectedFile(null);
    setScanName('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div style={{
      ...GLASS_CARD_STYLE,
      padding: 'var(--space-6)',
      marginBottom: 'var(--space-6)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
        <span style={{ fontFamily: 'var(--font-heading)', fontSize: 16, fontWeight: 700, color: '#FFFFFF' }}>
          Upload SBOM File
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', letterSpacing: 1.5 }}>
          CYCLONEDX & SPDX (JSON / XML / TXT) · MAX 10MB
        </span>
      </div>

      {/* Scan Name Input Field */}
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <label className="input-label" htmlFor="scan-name-input" style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.8)', marginBottom: 6, display: 'block' }}>
          Scan Name (User-Friendly Display Name)
        </label>
        <input
          id="scan-name-input"
          className="input"
          type="text"
          placeholder="e.g., Payment Gateway Service Scan"
          value={scanName}
          onChange={(e) => setScanName(e.target.value)}
          disabled={uploading}
          style={{ width: '100%' }}
        />
      </div>

      <div
        id="sbom-upload-zone"
        className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
        style={{
          border: '1.5px dashed rgba(255, 255, 255, 0.15)',
          borderRadius: '12px',
          padding: 'var(--space-8)',
          textAlign: 'center',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
          background: 'rgba(0, 0, 0, 0.2)',
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".json,.xml,.spdx,.txt,.cdx"
          style={{ display: 'none' }}
          onChange={(e) => handleFile(e.target.files?.[0])}
        />

        <div style={{
          width: 48,
          height: 48,
          borderRadius: '12px',
          background: 'rgba(218, 252, 111, 0.1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          margin: '0 auto var(--space-3)',
        }}>
          <Upload size={24} color="#DAFC6F" />
        </div>

        <div style={{ fontFamily: 'var(--font-heading)', fontSize: 14, fontWeight: 600, color: '#FFFFFF', marginBottom: 4 }}>
          {selectedFile ? selectedFile.name : 'Drop SBOM File Here (CycloneDX / SPDX)'}
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
          {selectedFile
            ? `${(selectedFile.size / 1024).toFixed(1)} KB`
            : 'Supports .json, .xml, .spdx, .txt format files'}
        </div>
      </div>

      {/* File Action Controls */}
      {selectedFile && (
        <div style={{ display: 'flex', gap: 'var(--space-3)', marginTop: 'var(--space-4)', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-ghost btn-sm" onClick={clearFile} disabled={uploading}>
            Clear File
          </button>
          <button type="button" className="btn btn-primary btn-md" onClick={handleSubmit} disabled={uploading}>
            {uploading ? 'Queuing Analysis…' : 'Submit for Analysis'}
          </button>
        </div>
      )}

      {/* Error & Success Messages */}
      {uploadError && (
        <div style={{
          marginTop: 'var(--space-4)',
          padding: 'var(--space-3) var(--space-4)',
          borderRadius: '8px',
          background: 'rgba(255, 77, 77, 0.1)',
          border: '1px solid rgba(255, 77, 77, 0.3)',
          color: '#FF4D4D',
          fontSize: 13,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          <AlertTriangle size={16} />
          {uploadError}
        </div>
      )}

      {uploadResult && (
        <div style={{
          marginTop: 'var(--space-4)',
          padding: 'var(--space-3) var(--space-4)',
          borderRadius: '8px',
          background: 'rgba(218, 252, 111, 0.1)',
          border: '1px solid rgba(218, 252, 111, 0.3)',
          color: '#DAFC6F',
          fontSize: 13,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          <CheckCircle2 size={16} />
          Job queued successfully. Job ID: <strong style={{ fontFamily: 'var(--font-mono)' }}>{formatJobId(uploadResult.job_id)}</strong>
        </div>
      )}
    </div>
  );
}

/* ── Main Jobs Page Component ───────────────────────────────────── */
export default function Jobs() {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [listError, setListError] = useState(null);
  const [notification, setNotification] = useState(null);
  const prevJobsRef = useRef({});

  // Request browser notification permission on load
  useEffect(() => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, []);

  const fetchJobs = useCallback(async () => {
    try {
      const data = await listJobs();
      setJobs(data);
      setListError(null);

      // Track status transitions to fire scan completion notifications
      if (data && Array.isArray(data)) {
        const prevMap = prevJobsRef.current;
        const newMap = {};

        data.forEach(job => {
          newMap[job.id] = job;
          const prevJob = prevMap[job.id];
          
          if (prevJob) {
            if ((prevJob.status === 'running' || prevJob.status === 'queued') && job.status === 'done') {
              const shortId = formatJobId(job.id);
              const title = `Scan Completed (${shortId})`;
              const body = `Processed ${job.component_count || 0} components and identified ${job.finding_count || 0} vulnerability finding(s).`;
              
              setNotification({ type: 'success', title, body, jobId: job.id });
              
              if ('Notification' in window && Notification.permission === 'granted') {
                try {
                  new Notification(title, { body });
                } catch (e) {
                  /* Ignore browser notification errors */
                }
              }
            } else if ((prevJob.status === 'running' || prevJob.status === 'queued') && job.status === 'failed') {
              const shortId = formatJobId(job.id);
              const title = `Scan Failed (${shortId})`;
              const body = job.error_msg || 'Analysis encountered an error during execution.';
              
              setNotification({ type: 'error', title, body, jobId: job.id });
              
              if ('Notification' in window && Notification.permission === 'granted') {
                try {
                  new Notification(title, { body });
                } catch (e) {
                  /* Ignore browser notification errors */
                }
              }
            }
          }
        });

        prevJobsRef.current = newMap;
      }
    } catch (err) {
      setListError(err.response?.data?.error || 'Failed to load job queue.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchJobs();
    const interval = setInterval(fetchJobs, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchJobs]);

  const handleUpload = async (file, scanName) => {
    setUploading(true);
    setUploadError(null);
    setUploadResult(null);
    try {
      const result = await uploadSbom(file, scanName);
      setUploadResult(result);
      await fetchJobs();
    } catch (err) {
      setUploadError(err.response?.data?.error || 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto' }}>
      
      {/* Page Header */}
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
            Analyze
          </h1>
        </div>

        <button
          id="jobs-refresh-btn"
          className="btn btn-ghost btn-sm"
          onClick={fetchJobs}
        >
          <RefreshCw size={13} />
          Refresh Queue
        </button>
      </div>

      {/* Completion Toast Notification Banner */}
      {notification && (
        <div style={{
          marginBottom: 'var(--space-6)',
          padding: '16px 20px',
          borderRadius: '12px',
          background: notification.type === 'success' 
            ? 'linear-gradient(135deg, rgba(218, 252, 111, 0.15) 0%, rgba(218, 252, 111, 0.05) 100%)' 
            : 'linear-gradient(135deg, rgba(255, 77, 77, 0.15) 0%, rgba(255, 77, 77, 0.05) 100%)',
          border: notification.type === 'success' ? '1px solid #DAFC6F' : '1px solid #FF4D4D',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: '10px',
              background: notification.type === 'success' ? 'rgba(218, 252, 111, 0.2)' : 'rgba(255, 77, 77, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Bell size={18} color={notification.type === 'success' ? '#DAFC6F' : '#FF4D4D'} />
            </div>
            <div>
              <div style={{ fontFamily: 'var(--font-heading)', fontWeight: 700, fontSize: 14, color: '#FFFFFF' }}>
                {notification.title}
              </div>
              <div style={{ fontSize: 13, color: 'rgba(255, 255, 255, 0.8)', marginTop: 2 }}>
                {notification.body}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {notification.type === 'success' && (
              <button 
                className="btn btn-primary btn-sm"
                onClick={() => navigate('/dashboard/findings')}
              >
                View Findings
              </button>
            )}
            <button 
              className="btn btn-ghost btn-sm"
              onClick={() => setNotification(null)}
              style={{ padding: '6px 8px' }}
            >
              <X size={16} />
            </button>
          </div>
        </div>
      )}

      {/* Upload Section */}
      <UploadZone
        onUpload={handleUpload}
        uploading={uploading}
        uploadError={uploadError}
        uploadResult={uploadResult}
      />

      {/* Job Queue Section — Glassmorphism Container */}
      <div style={{
        ...GLASS_CARD_STYLE,
        overflow: 'hidden',
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: 'var(--space-4) var(--space-6)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        }}>
          <span style={{ fontFamily: 'var(--font-heading)', fontSize: 15, fontWeight: 700, color: '#FFFFFF' }}>
            Job Queue
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'rgba(255, 255, 255, 0.5)' }}>
            {jobs.length} TOTAL SCAN{jobs.length !== 1 ? 'S' : ''}
          </span>
        </div>

        {listError && (
          <div className="alert alert-error" style={{ margin: 'var(--space-4)' }}>
            <AlertTriangle size={14} />
            {listError}
          </div>
        )}

        {loading ? (
          <div style={{ padding: 'var(--space-8)', textAlign: 'center', color: 'rgba(255, 255, 255, 0.5)', fontSize: 13 }}>
            Loading job queue…
          </div>
        ) : jobs.length === 0 ? (
          <EmptyState
            icon={Clock}
            title="No analysis jobs queued"
            description="Upload a CycloneDX JSON file above to start vulnerability analysis."
          />
        ) : (
          <div className="data-table-wrapper" style={{ border: 'none', borderRadius: 0, background: 'transparent' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>JOB ID</th>
                  <th>SCAN NAME</th>
                  <th>STATUS</th>
                  <th>COMPONENTS</th>
                  <th>FINDINGS</th>
                  <th>SUBMITTED</th>
                  <th style={{ textAlign: 'right' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const isDone = job.status === 'done';
                  const isRunning = job.status === 'running' || job.status === 'queued';
                  return (
                    <tr
                      key={job.job_id}
                      style={{ cursor: isDone ? 'pointer' : 'default' }}
                      onClick={() => {
                        if (isDone) navigate(`/app/findings?jobId=${job.job_id}`);
                      }}
                    >
                      <td className="cell-mono cell-primary" style={{ fontSize: 12 }}>
                        {formatJobId(job.job_id)}
                      </td>
                      <td style={{ fontSize: 13, color: 'rgba(255, 255, 255, 0.8)' }}>
                        {job.sbom_filename || 'sbom.json'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                          <JobStatusPill status={job.status} />
                          {isRunning && (
                            <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--color-accent)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                              <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />
                              {job.progress_pct ? `${job.progress_pct}%` : 'PROCESSING'}
                            </span>
                          )}
                          {job.status === 'failed' && job.error_msg && (
                            <span
                              style={{ fontSize: 11, color: '#FF4D4D', cursor: 'help', textDecoration: 'underline dotted' }}
                              title={job.error_msg}
                            >
                              [{job.error_code || 'ERROR'}]
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="cell-mono" style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.8)' }}>
                        {job.component_count ?? '—'}
                        {job.unscannable_count > 0 && (
                          <span style={{ fontSize: 10, color: '#f59e0b', marginLeft: 4 }} title={`${job.unscannable_count} malformed component(s) flagged as unscannable`}>
                            ({job.unscannable_count} unscannable)
                          </span>
                        )}
                      </td>
                      <td className="cell-mono" style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.8)' }}>
                        {job.status === 'done' ? (job.finding_count ?? 0) : '—'}
                      </td>
                      <td className="cell-mono" style={{ fontSize: 11, color: 'rgba(255, 255, 255, 0.5)' }}>
                        {formatRelativeTime(job.submitted_at)}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
                          {isDone && (
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate(`/app/findings?jobId=${job.job_id}`);
                              }}
                              title="Open Findings for this scan"
                              style={{ padding: '4px 8px', color: 'var(--color-accent)' }}
                            >
                              <ExternalLink size={14} />
                            </button>
                          )}
                          {job.status === 'failed' && (
                            <span 
                              style={{ fontSize: 11, color: '#FF4D4D', display: 'inline-flex', alignItems: 'center', gap: 4, cursor: 'pointer', padding: '2px 6px', background: 'rgba(255,77,77,0.1)', borderRadius: 4, border: '1px solid rgba(255,77,77,0.2)' }}
                              onClick={(e) => {
                                e.stopPropagation();
                                document.getElementById('sbom-upload-zone')?.click();
                              }}
                              title={job.error_msg ? `Reason: ${job.error_msg}. Click to re-submit scan` : "Click to select file and re-submit scan"}
                            >
                              <RotateCcw size={12} /> Retry
                            </span>
                          )}
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            onClick={async (e) => {
                              e.stopPropagation();
                              if (window.confirm(`Delete scan job ${formatJobId(job.job_id)}?`)) {
                                try {
                                  await deleteJob(job.job_id);
                                  fetchJobs();
                                } catch (err) {
                                  alert('Failed to delete job: ' + (err.response?.data?.error || err.message));
                                }
                              }
                            }}
                            title="Delete or cancel this scan job"
                            style={{ padding: '4px 8px', color: '#FF4D4D', opacity: 0.8 }}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>

                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
