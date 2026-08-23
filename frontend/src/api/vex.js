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
export async function getVexDocuments({ job_id, cve_id, status, source_type } = {}) {
  const params = {};
  if (job_id) params.job_id = job_id;
  if (cve_id) params.cve_id = cve_id;
  if (status) params.status = status;
  if (source_type && source_type !== 'ALL') params.source_type = source_type;
  const res = await client.get('/vex', { params });
  return res.data;
}

/**
 * POST /api/vex/:vexId/resolve
 * Resolves an investigation status for a VEX document.
 * @param {string} vexId
 * @param {{ status: string, justification: string }} data
 */
export async function resolveVexInvestigation(vexId, { status = 'not_affected', justification = 'vulnerable_code_not_in_execute_path' } = {}) {
  const res = await client.post(`/vex/${vexId}/resolve`, { status, justification });
  return res.data;
}

/**
 * GET /api/vex/:vexId/download
 * Downloads the VEX Compliance Report forced in PDF format ONLY.
 * @param {string} vexId
 * @param {string} filename — suggested filename for save dialog
 */
export async function downloadVexDocument(vexId, filename) {
  try {
    const res = await client.get(`/vex/${vexId}/download`, {
      responseType: 'blob',
    });

    const targetFilename = filename || `${vexId}_VEX_Report.pdf`;
    const blob = new Blob([res.data], { type: 'application/pdf' });
    const blobUrl = window.URL.createObjectURL(blob);

    const anchor = document.createElement('a');
    anchor.href = blobUrl;
    anchor.setAttribute('download', targetFilename);
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);

    setTimeout(() => {
      window.URL.revokeObjectURL(blobUrl);
    }, 1000);
  } catch (err) {
    console.error('Failed to download VEX PDF report:', err);
  }
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

/**
 * POST /api/vex/generate-runtime-report
 * Generates Live Telemetry Compliance VEX report for a specified history date.
 * @param {string} dateStr
 */
export async function generateRuntimeComplianceReport(dateStr = 'today') {
  const res = await client.post('/vex/generate-runtime-report', { date: dateStr });
  return res.data;
}
