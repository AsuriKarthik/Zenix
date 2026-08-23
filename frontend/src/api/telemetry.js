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
 * @param {{ limit?: number, evidence_source?: 'etw'|'psutil', date?: string, process?: string, severity?: string }} params
 */
export async function getTelemetryEvents({ limit = 100, evidence_source, date, process, severity } = {}) {
  const params = { limit };
  if (evidence_source) params.evidence_source = evidence_source;
  if (date) params.date = date;
  if (process) params.process = process;
  if (severity) params.severity = severity;
  const res = await client.get('/telemetry/events', { params });
  return res.data;
}

/**
 * GET /api/telemetry/sessions
 * Returns available evidence dates and session history.
 */
export async function getTelemetrySessions() {
  const res = await client.get('/telemetry/sessions');
  return res.data;
}

/**
 * POST /api/telemetry/heartbeat
 * Maintains active ETW session heartbeat pulse.
 */
export async function sendTelemetryHeartbeat(token) {
  const res = await client.post('/telemetry/heartbeat', { session_token: token });
  return res.data;
}

/**
 * POST /api/telemetry/set-passphrase
 * Sets or updates the user's encrypted ETW passkey in the database.
 * @param {string} passphrase
 */
export async function setUserEtwPassphrase(passphrase) {
  const res = await client.post('/telemetry/set-passphrase', { passphrase });
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
