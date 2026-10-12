/**
 * Telemetry API
 * Endpoints: /api/telemetry/*
 */

import client from './client';

/**
 * GET /api/telemetry/status
 * Returns ETW agent status: running, mode, elevation_state, event metrics.
 */
export async function getTelemetryStatus() {
  const res = await client.get('/telemetry/status');
  return res.data;
}

/**
 * GET /api/telemetry/events
 * Returns telemetry event logs.
 * @param {{ limit?: number, evidence_source?: 'etw'|'psutil' }} params
 */
export async function getTelemetryEvents({ limit = 100, evidence_source } = {}) {
  const params = { limit };
  if (evidence_source) params.evidence_source = evidence_source;
  const res = await client.get('/telemetry/events', { params });
  return res.data;
}

/**
 * POST /api/telemetry/enable
 * Enable ETW collector — requires secondary admin passphrase.
 * @param {string} passphrase
 */
export async function enableEtw(passphrase) {
  const res = await client.post('/telemetry/enable', { passphrase });
  return res.data;
}

/**
 * POST /api/telemetry/disable
 * Disable ETW collector.
 */
export async function disableEtw() {
  const res = await client.post('/telemetry/disable');
  return res.data;
}

/**
 * GET /api/telemetry/audit-logs
 * Returns ETW activation/deactivation audit history.
 */
export async function getAuditLogs() {
  const res = await client.get('/telemetry/audit-logs');
  return res.data;
}
