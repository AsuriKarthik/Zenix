/**
 * Jobs API
 * Endpoints: /api/jobs/*
 */

import client from './client';

/**
 * POST /api/jobs/upload
 * Upload a CycloneDX JSON SBOM file for analysis.
 * @param {File} file
 * @param {Function} onUploadProgress — optional axios progress callback
 * @returns {{ job_id: string, status: string }}
 */
export async function uploadSbom(file, scanName = '', onUploadProgress = null) {
  const formData = new FormData();
  formData.append('file', file);
  if (scanName) {
    formData.append('scan_name', scanName);
  }

  const res = await client.post('/jobs/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress,
  });
  return res.data;
}

/**
 * GET /api/jobs
 * List jobs for the current user (analysts see own, admins see all).
 * @returns {Array<Job>}
 */
export async function listJobs() {
  const res = await client.get('/jobs');
  return res.data;
}

/**
 * GET /api/jobs/:jobId/status
 * @param {string} jobId
 * @returns {object} status info
 */
export async function getJobStatus(jobId) {
  const res = await client.get(`/jobs/${jobId}/status`);
  return res.data;
}

/**
 * GET /api/jobs/:jobId/result
 * Get full analysis result for a completed job.
 * @param {string} jobId
 * @returns {object} full result with findings, scores, verdicts
 */
export async function getJobResult(jobId) {
  const res = await client.get(`/jobs/${jobId}/result`);
  return res.data;
}

/**
 * GET /api/jobs/triage-summary
 * Get dynamic security triage metrics and priority queue items.
 * @returns {{ metrics: { needs_attention: number, reachable: number, unknown: number, high_confidence: number }, priority_queue: Array }}
 */
export async function getTriageSummary() {
  const res = await client.get('/jobs/triage-summary');
  return res.data;
}

/**
 * GET /api/jobs/latest-threats
 * Get latest vulnerabilities & threat intelligence from CISA KEV catalog feed.
 * @returns {{ threats: Array }}
 */
export async function getLatestThreats() {
  const res = await client.get('/jobs/latest-threats');
  return res.data;
}

/**
 * GET /api/jobs/findings
 * Paginated findings endpoint.
 * @param {object} params — { finding_type, page, per_page, job_id }
 * @returns {{ items: Array, total: number, page: number, per_page: number, has_more: boolean }}
 */
export async function listFindings(params = {}) {
  const res = await client.get('/jobs/findings', { params });
  return res.data;
}

/**
 * POST /api/jobs/findings/:vulnerabilityId/status
 * Update analyst triage status and notes.
 * @param {number} vulnerabilityId
 * @param {string} status — ACCEPT_RISK, UNDER_INVESTIGATION, FALSE_POSITIVE, MITIGATED, UNTRIAGED
 * @param {string} note
 */
export async function updateAnalystStatus(vulnerabilityId, status, note = '') {
  const res = await client.post(`/jobs/findings/${vulnerabilityId}/status`, { status, note });
  return res.data;
}

/**
 * DELETE /api/jobs/:jobId
 * Delete/cancel an analysis job.
 * @param {string} jobId
 */
export async function deleteJob(jobId) {
  const res = await client.delete(`/jobs/${jobId}`);
  return res.data;
}

