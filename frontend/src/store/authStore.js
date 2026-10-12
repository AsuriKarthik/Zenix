/**
 * Zustand auth store — global authentication state.
 *
 * Stores: user object, loading state, CSRF token
 * Actions: setUser, setLoading, clearAuth
 */

import { create } from 'zustand';

const useAuthStore = create((set) => ({
  user: null,
  isLoading: true,  // true until session check completes
  isAuthenticated: false,

  setUser: (user) => set({
    user,
    isAuthenticated: !!user,
    isLoading: false,
  }),

  setLoading: (isLoading) => set({ isLoading }),

  clearAuth: () => set({
    user: null,
    isAuthenticated: false,
    isLoading: false,
  }),
}));

export default useAuthStore;
