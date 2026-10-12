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
  const res = await client.get('/auth/me');
  if (res.data.csrf_token) setCsrfToken(res.data.csrf_token);
  return res.data.user;
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
 */
export async function register(email, password, role = 'analyst') {
  const res = await client.post('/auth/register', { email, password, role });
  return res.data;
}
