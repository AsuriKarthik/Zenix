/**
 * AppShell — Protected application shell
 *
 * Renders: Sidebar + main content area (Outlet)
 * Guards: redirects to /login if not authenticated
 */

import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import Sidebar from './Sidebar';

export default function AppShell() {
  const { isAuthenticated, isLoading } = useAuth();

  // While session check is in progress, render nothing (App handles loading screen)
  if (isLoading) return null;

  // Not authenticated → redirect to login
  if (!isAuthenticated) return <Navigate to="/login" replace />;

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-content">
        <div className="page-body">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
