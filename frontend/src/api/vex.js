/**
 * VEX API
 * Endpoints: /api/vex/*
 */

import client from './client';

/**
 * GET /api/vex
 * Returns VEX documents for the authenticated user's jobs.
 * @param {{ job_id?: string, cve_id?: string, status?: string }} filters
 */
export async function getVexDocuments({ job_id, cve_id, status } = {}) {
  const params = {};
  if (job_id) params.job_id = job_id;
  if (cve_id) params.cve_id = cve_id;
  if (status) params.status = status;
  const res = await client.get('/vex', { params });
  return res.data;
}

/**
 * GET /api/vex/:vexId/download
 * Triggers a file download of the raw CycloneDX VEX JSON.
 * @param {string} vexId
 * @param {string} filename  — suggested filename for save dialog
 */
export function downloadVexDocument(vexId, filename) {
  // Use window.open or create anchor — session cookie will be sent
  const url = `/api/vex/${vexId}/download`;
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename || `${vexId}.cdx.json`;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
}

/**
 * GET /api/vex/public-key
 * Returns the ECDSA public key PEM (no auth required).
 * @returns {string} PEM text
 */
export async function getVexPublicKey() {
  const res = await client.get('/vex/public-key', {
    headers: { Accept: 'application/x-pem-file' },
    responseType: 'text',
  });
  return res.data;
}
