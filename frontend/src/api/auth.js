/**
 * Auth API
 * Endpoints: /api/auth/*
 */

import client, { setCsrfToken, clearCsrfToken } from './client';

/**
 * GET /api/auth/me
 * Returns current authenticated user + refreshed csrf_token.
 * Returns null if unauthenticated (401).
 */
export async function getMe() {
  try {
    const res = await client.get('/auth/me');
    if (res.data?.csrf_token) setCsrfToken(res.data.csrf_token);
    return res.data?.user ?? null;
  } catch (err) {
    if (err.response?.status === 401) {
      return null;
    }
    throw err;
  }
}

/**
 * POST /api/auth/login
 * @param {string} email
 * @param {string} password
 * @returns {{ user: object, csrf_token: string }}
 */
export async function login(email, password) {
  const res = await client.post('/auth/login', { email, password });
  if (res.data.csrf_token) setCsrfToken(res.data.csrf_token);
  return res.data;
}

/**
 * POST /api/auth/logout
 */
export async function logout() {
  await client.post('/auth/logout');
  clearCsrfToken();
}

/**
 * POST /api/auth/register
 * @param {string} email
 * @param {string} password
 * @param {'analyst'|'admin'} role
 * @param {string} etw_collector_password
 */
export async function register(email, password, role = 'analyst', etw_collector_password = '') {
  const res = await client.post('/auth/register', { email, password, role, etw_collector_password });
  return res.data;
}

/**
 * POST /api/auth/verify-email
 * @param {string} email
 * @param {string} otp
 */
export async function verifyEmail(email, otp) {
  const res = await client.post('/auth/verify-email', { email, otp });
  return res.data;
}

/**
 * POST /api/auth/setup-etw-password
 * @param {string} etw_collector_password
 */
export async function setupEtwPassword(etw_collector_password) {
  const res = await client.post('/auth/setup-etw-password', { etw_collector_password });
  return res.data;
}

/**
 * POST /api/auth/set-etw-passphrase
 * @param {string} etw_passphrase
 */
export async function setEtwPassphrase(etw_passphrase) {
  return setupEtwPassword(etw_passphrase);
}

/**
 * POST /api/auth/forgot-password/question
 * @param {string} email
 */
export async function getSecurityQuestion(email) {
  const res = await client.post('/auth/forgot-password/question', { email });
  return res.data;
}

/**
 * POST /api/auth/forgot-password/reset
 * @param {string} email
 * @param {string} security_answer
 * @param {string} new_password
 */
export async function resetPasswordWithSecurityAnswer(email, security_answer, new_password) {
  const res = await client.post('/auth/forgot-password/reset', { email, security_answer, new_password });
  return res.data;
}

/**
 * POST /api/auth/update-profile
 * Update user account details (e.g. email).
 * @param {object} data
 */
export async function updateProfile(data) {
  const res = await client.post('/auth/update-profile', data);
  return res.data;
}

