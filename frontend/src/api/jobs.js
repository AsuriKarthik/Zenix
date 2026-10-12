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
export async function uploadSbom(file, onUploadProgress) {
  const formData = new FormData();
  formData.append('file', file);

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
