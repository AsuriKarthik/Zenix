/**
 * Zenix App — Root component
 *
 * Routing:
 *   /login       → LoginPage (public)
 *   /app/*       → AppShell (protected)
 *     /app/dashboard     → Dashboard
 *     /app/jobs          → Jobs
 *     /app/findings      → Findings
 *     /app/evidence      → EvidenceViewer
 *     /app/vex           → VexCompliance
 *     /app/status        → SystemStatus
 *     /app/settings/*    → Settings (Layout + sub-routes)
 *   /            → redirect based on auth
 *
 * Session check:
 *   On mount, GET /api/auth/me to restore session.
 *   Loading screen shown during check.
 */

import React, { useEffect, useState } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AnimatePresence } from 'framer-motion';

import { useAuth } from './hooks/useAuth';

// Layout
import AppShell from './components/layout/AppShell';
import LoadingScreen from './components/layout/LoadingScreen';

// Auth
import LoginPage from './components/auth/LoginPage';

// Pages
import Dashboard     from './pages/Dashboard';
import Jobs          from './pages/Jobs';
import Findings      from './pages/Findings';
import EvidenceViewer from './pages/EvidenceViewer';
import VexCompliance  from './pages/VexCompliance';
import SystemStatus   from './pages/SystemStatus';


// Settings
import SettingsLayout    from './pages/Settings/SettingsLayout';
import AccountSettings   from './pages/Settings/AccountSettings';
import EtwAccessSettings from './pages/Settings/EtwAccessSettings';
import ApiStatus         from './pages/Settings/ApiStatus';

export default function App() {
  const { isAuthenticated, checkSession } = useAuth();
  const location = useLocation();
  const [loadingDone, setLoadingDone] = useState(false);
  const [sessionChecked, setSessionChecked] = useState(false);

  // Check session on mount
  useEffect(() => {
    checkSession().finally(() => setSessionChecked(true));
  }, [checkSession]);

  // Show loading screen until both session is checked AND loading animation is done
  const showLoading = !sessionChecked || !loadingDone;

  if (showLoading) {
    return (
      <AnimatePresence>
        <LoadingScreen isReady={sessionChecked} onComplete={() => setLoadingDone(true)} />
      </AnimatePresence>
    );
  }

  return (
    <>
      <Routes>
        {/* Root redirect */}
        <Route
          path="/"
          element={<Navigate to={isAuthenticated ? '/app/dashboard' : '/login'} replace />}
        />

        {/* Login */}
        <Route path="/login" element={<LoginPage />} />

        {/* Protected app shell */}
        <Route path="/app" element={<AppShell />}>
          <Route index element={<Navigate to="dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="jobs"      element={<Jobs />} />
          <Route path="findings"  element={<Findings />} />
          <Route path="evidence"  element={<EvidenceViewer />} />
          <Route path="vex"       element={<VexCompliance />} />
          <Route path="status"    element={<SystemStatus />} />

          {/* Settings sub-routes */}
          <Route path="settings" element={<SettingsLayout />}>
            <Route index element={<Navigate to="account" replace />} />
            <Route path="account" element={<AccountSettings />} />
            <Route path="etw"     element={<EtwAccessSettings />} />
            <Route path="api"     element={<ApiStatus />} />
          </Route>

          {/* Catch-all inside app */}
          <Route path="*" element={<Navigate to="dashboard" replace />} />
        </Route>

        {/* Global catch-all */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}