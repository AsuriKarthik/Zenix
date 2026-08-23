/**
 * Settings Layout — Native Zenix System Layout
 *
 * Sub-routes:
 *   /app/settings/account   → AccountSettings
 *   /app/settings/etw       → EtwAccessSettings (passphrase-gated)
 *   /app/settings/api       → ApiStatus
 */

import React from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { User, Shield, Database } from 'lucide-react';

const SETTINGS_TABS = [
  { to: '/app/settings/account', icon: User,     label: 'Account' },
  { to: '/app/settings/etw',     icon: Shield,   label: 'ETW Access' },
  { to: '/app/settings/api',     icon: Database, label: 'API / Feed Status' },
];

export default function SettingsLayout() {
  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1 className="page-header-title">Settings</h1>
          <div className="page-header-meta">
            <span className="page-header-hud">CONFIGURATION</span>
          </div>
        </div>
      </div>

      {/* Clean Tab navigation */}
      <div style={{
        display: 'flex',
        gap: 'var(--space-2)',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: 'var(--space-6)',
        paddingBottom: 0,
      }}>
        {SETTINGS_TABS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              padding: 'var(--space-2) var(--space-4)',
              paddingBottom: 12,
              fontSize: 13,
              fontWeight: 500,
              color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
              borderBottom: `2px solid ${isActive ? 'var(--color-nav)' : 'transparent'}`,
              textDecoration: 'none',
              transition: 'all 150ms',
              marginBottom: -1,
            })}
          >
            <Icon size={14} />
            {label}
          </NavLink>
        ))}
      </div>

      {/* Sub-route Outlet spanning full workspace width */}
      <Outlet />
    </div>
  );
}
