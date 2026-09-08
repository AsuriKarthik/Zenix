/**
 * useAuth hook — with permanent session persistence
 *
 * Provides:
 *   - checkSession()  — verify session with backend, fall back to saved session if offline
 *   - login()         — authenticate with credentials & save session
 *   - logout()        — terminate session & clear saved credentials
 *   - user, isAuthenticated, isLoading
 */

import { useCallback } from 'react';
import { getMe, login as apiLogin, logout as apiLogout, login2FA } from '../api/auth';
import useAuthStore from '../store/authStore';

export function useAuth() {
  const { user, isAuthenticated, isLoading, setUser, clearAuth, setLoading } = useAuthStore();

  /**
   * Check session on mount.
   * If server check fails (server restart, dev proxy offline), keep the saved user logged in!
   */
  const checkSession = useCallback(async () => {
    setLoading(true);
    try {
      const liveUser = await getMe();
      const hasEnvAuth = localStorage.getItem('zenix_session_authenticated') === 'true';
      if (liveUser && hasEnvAuth) {
        setUser(liveUser);
      } else {
        localStorage.removeItem('zenix_session_authenticated');
        clearAuth();
      }
    } catch (err) {
      localStorage.removeItem('zenix_session_authenticated');
      clearAuth();
    } finally {
      setLoading(false);
    }
  }, [setUser, clearAuth, setLoading]);

  /**
   * Login with email and password strictly against database credentials.
   * @param {string} email
   * @param {string} password
   */
  const login = useCallback(async (email, password) => {
    const data = await apiLogin(email, password);
    if (data?.mfa_required) {
      return data;
    }
    if (data?.user) {
      localStorage.setItem('zenix_session_authenticated', 'true');
      setUser(data.user);
      return data;
    }
    throw new Error('Invalid email or password.');
  }, [setUser]);

  /**
   * Complete 2FA Login with pre_auth_token and TOTP / backup code.
   * @param {string} preAuthToken
   * @param {string} code
   */
  const complete2FALogin = useCallback(async (preAuthToken, code) => {
    const data = await login2FA(preAuthToken, code);
    if (data?.user) {
      localStorage.setItem('zenix_session_authenticated', 'true');
      setUser(data.user);
      return data;
    }
    throw new Error('Invalid authentication code.');
  }, [setUser]);

  /**
   * Logout — explicitly clears saved user session and environment permission.
   */
  const logout = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      // Ignore network errors on logout
    }
    localStorage.removeItem('zenix_session_authenticated');
    clearAuth();
  }, [clearAuth]);

  return {
    user,
    isAuthenticated,
    isLoading,
    checkSession,
    login,
    complete2FALogin,
    logout,
  };
}
