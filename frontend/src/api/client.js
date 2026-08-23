/**
 * Zenix API Client
 *
 * Axios instance with:
 *  - withCredentials: true  → session cookie sent on every request
 *  - CSRF token interceptor → fetches and attaches X-CSRF-Token header
 *    on every state-changing request (POST, PUT, DELETE, PATCH)
 */

import axios from 'axios';
import useLoadingStore from '../store/loadingStore';

const client = axios.create({
  baseURL: '/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// In-memory CSRF token cache
let _csrfToken = null;

/**
 * Fetch a fresh CSRF token from the backend.
 * Caches the token so we only fetch once per session.
 */
async function fetchCsrfToken() {
  const res = await axios.get('/api/auth/csrf-token', { withCredentials: true });
  _csrfToken = res.data.csrf_token;
  return _csrfToken;
}

/** Allow other modules to seed the CSRF token (e.g. after login response) */
export function setCsrfToken(token) {
  _csrfToken = token;
}

/** Clear CSRF token (on logout) */
export function clearCsrfToken() {
  _csrfToken = null;
}

// Request interceptor — attach CSRF header for mutating requests
client.interceptors.request.use(async (config) => {
  useLoadingStore.getState().startRequest();

  const mutating = ['post', 'put', 'delete', 'patch'];
  if (mutating.includes(config.method?.toLowerCase())) {
    if (!_csrfToken) {
      try {
        await fetchCsrfToken();
      } catch {
        // If CSRF fetch fails (unauthenticated), continue without it
      }
    }
    if (_csrfToken) {
      config.headers['X-CSRF-Token'] = _csrfToken;
    }
  }
  return config;
}, (error) => {
  useLoadingStore.getState().endRequest();
  return Promise.reject(error);
});

// Response interceptor — on 401, clear token cache
client.interceptors.response.use(
  (res) => {
    useLoadingStore.getState().endRequest();
    return res;
  },
  (err) => {
    useLoadingStore.getState().endRequest();
    if (err.response?.status === 401) {
      _csrfToken = null;
    }
    return Promise.reject(err);
  }
);

export default client;
