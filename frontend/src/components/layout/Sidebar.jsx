/**
 * Sidebar — Main navigation component
 *
 * Navigation structure tied to backend capability:
 *   Dashboard        → /api/jobs + /api/telemetry/status
 *   Submit / Jobs    → /api/jobs/upload + /api/jobs
 *   Findings         → /api/jobs/:id/result
 *   Evidence Viewer  → /api/telemetry/events
 *   VEX / Compliance → /api/vex
 *   System Status    → /api/telemetry/status + /api/telemetry/audit-logs
 *   Settings         → account + ETW access + API status
 */

import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Upload,
  ShieldAlert,
  Terminal,
  FileCheck2,
  Activity,
  Settings,
  LogOut,
} from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

const NAV_ITEMS = [
  {
    group: 'ANALYSIS',
    items: [
      { to: '/app/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/app/jobs',      icon: Upload,           label: 'Submit / Jobs' },
      { to: '/app/findings',  icon: ShieldAlert,      label: 'Findings' },
    ],
  },
  {
    group: 'EVIDENCE',
    items: [
      { to: '/app/evidence', icon: Terminal,    label: 'Evidence Viewer' },
      { to: '/app/vex',      icon: FileCheck2,  label: 'VEX / Compliance' },
    ],
  },
  {
    group: 'SYSTEM',
    items: [
      { to: '/app/status',   icon: Activity,  label: 'System Status' },
      { to: '/app/settings', icon: Settings,  label: 'Settings' },
    ],
  },
];

// Zenix mark — compact version for sidebar
function SidebarMark() {
  return (
    <svg width="22" height="22" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M 50 8 L 92 78 L 8 78 Z" stroke="rgba(124,38,236,0.7)" strokeWidth="3" fill="none" />
      <path d="M 50 24 L 78 68 L 22 68 Z" stroke="rgba(32,225,163,0.9)" strokeWidth="2" fill="none" />
      <line x1="50" y1="0" x2="50" y2="10" stroke="rgba(255,255,255,0.3)" strokeWidth="2" />
      <line x1="20" y1="70" x2="6" y2="88" stroke="rgba(255,255,255,0.2)" strokeWidth="2" />
      <line x1="80" y1="70" x2="94" y2="88" stroke="rgba(255,255,255,0.2)" strokeWidth="2" />
    </svg>
  );
}

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  // User initials for avatar
  const initials = user?.email
    ? user.email.slice(0, 2).toUpperCase()
    : 'ZX';

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="sidebar-logo-mark">
          <SidebarMark />
          <span className="sidebar-logo-text">ZENIX</span>
        </div>
        <div className="sidebar-hud-label">SCANNER V.2 · SECURE</div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((group) => (
          <div key={group.group}>
            <div className="sidebar-section-label">{group.group}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `sidebar-nav-item ${isActive ? 'active' : ''}`
                }
              >
                <item.icon size={15} />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Footer — user info + logout */}
      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="sidebar-user-avatar">{initials}</div>
          <div className="sidebar-user-info">
            <div className="sidebar-user-email">{user?.email || '—'}</div>
            <div className="sidebar-user-role">{user?.role || 'analyst'}</div>
          </div>
        </div>
        <button
          id="sidebar-logout-btn"
          className="sidebar-logout-btn"
          onClick={handleLogout}
        >
          <LogOut size={13} />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
}
