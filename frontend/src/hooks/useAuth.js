/**
 * useAuth hook
 *
 * Provides:
 *   - checkSession()  — verify active session with backend
 *   - login()         — authenticate with credentials
 *   - logout()        — terminate session
 *   - user, isAuthenticated, isLoading
 */

import { useCallback } from 'react';
import { getMe, login as apiLogin, logout as apiLogout } from '../api/auth';
import useAuthStore from '../store/authStore';

export function useAuth() {
  const { user, isAuthenticated, isLoading, setUser, clearAuth, setLoading } = useAuthStore();

  /**
   * Check if there's an active server-side session.
   * Called once on app mount.
   */
  const checkSession = useCallback(async () => {
    setLoading(true);
    try {
      const user = await getMe();
      setUser(user);
    } catch {
      // 401 — not authenticated
      clearAuth();
    }
  }, [setUser, clearAuth, setLoading]);

  /**
   * Login with email and password.
   * @param {string} email
   * @param {string} password
   * @returns {{ user: object }} on success
   * @throws axios error with response.data.error on failure
   */
  const login = useCallback(async (email, password) => {
    const data = await apiLogin(email, password);
    setUser(data.user);
    return data;
  }, [setUser]);

  /**
   * Logout — clears session and local state.
   */
  const logout = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      // Even if backend fails, clear local state
    }
    clearAuth();
  }, [clearAuth]);

  return {
    user,
    isAuthenticated,
    isLoading,
    checkSession,
    login,
    logout,
  };
}
