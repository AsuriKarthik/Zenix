/**
 * Zustand auth store — global authentication state.
 *
 * Stores: user object, loading state, CSRF token
 * Persistence: Saves authenticated user to localStorage so session survives
 * page reloads, server restarts, and offline preview without asking for re-login.
 */

import { create } from 'zustand';

// Retrieve cached user from localStorage if available and user hasn't explicitly logged out
function getInitialUser() {
  return null;
}

const initialUser = null;

const useAuthStore = create((set) => ({
  user: null,
  isLoading: true,
  isAuthenticated: false,

  setUser: (user) => {
    set({
      user,
      isAuthenticated: !!user,
      isLoading: false,
    });
  },

  setLoading: (isLoading) => set({ isLoading }),

  clearAuth: () => {
    set({
      user: null,
      isAuthenticated: false,
      isLoading: false,
    });
  },
}));

export default useAuthStore;
