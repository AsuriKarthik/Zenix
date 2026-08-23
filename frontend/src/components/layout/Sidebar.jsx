/**
 * Sidebar — Refined product navigation and user profile card
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
  ChevronRight,
} from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

const NAV_ITEMS = [
  {
    group: 'WORKSPACE',
    items: [
      { to: '/app/dashboard', icon: LayoutDashboard, label: 'Overview' },
      { to: '/app/jobs',      icon: Upload,          label: 'Analyze' },
      { to: '/app/findings',  icon: ShieldAlert,     label: 'Findings' },
    ],
  },
  {
    group: 'EVIDENCE & VEX',
    items: [
      { to: '/app/evidence', icon: Terminal,   label: 'Evidence' },
      { to: '/app/vex',      icon: FileCheck2, label: 'Compliance' },
    ],
  },
  {
    group: 'SYSTEM',
    items: [
      { to: '/app/status',   icon: Activity, label: 'System' },
      { to: '/app/settings', icon: Settings, label: 'Settings' },
    ],
  },
];

function SidebarMark() {
  return (
    <svg width="22" height="22" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M 50 8 L 92 78 L 8 78 Z" stroke="var(--color-accent)" strokeWidth="3" fill="none" />
      <path d="M 50 24 L 78 68 L 22 68 Z" stroke="rgba(255,255,255,0.7)" strokeWidth="2" fill="none" />
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

  const userDisplayName = user?.display_name || user?.name || user?.email || 'analyst@zenix.local';

  const initials = userDisplayName
    ? userDisplayName.slice(0, 2).toUpperCase()
    : 'ZX';

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <motion.div 
        className="sidebar-logo"
        initial={{ opacity: 0, x: -16, filter: 'blur(6px)' }}
        animate={{ opacity: 1, x: 0, filter: 'blur(0px)' }}
        transition={{ duration: 0.4 }}
      >
        <div className="sidebar-logo-mark">
          <SidebarMark />
          <span className="sidebar-logo-text">ZENIX</span>
        </div>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          letterSpacing: 1.2,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          marginTop: 4,
        }}>
          SECURITY ANALYSIS PLATFORM
        </div>
      </motion.div>

      {/* Navigation Groups */}
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((group, groupIdx) => (
          <div key={group.group} style={{ marginBottom: 'var(--space-4)' }}>
            <div className="sidebar-section-label">{group.group}</div>
            {group.items.map((item, itemIdx) => (
              <motion.div
                key={item.to}
                initial={{ opacity: 0, x: -14, filter: 'blur(6px)' }}
                animate={{ opacity: 1, x: 0, filter: 'blur(0px)' }}
                transition={{
                  duration: 0.4,
                  delay: (groupIdx * 4 + itemIdx) * 0.05 + 0.1,
                  ease: [0.16, 1, 0.3, 1],
                }}
                whileHover={{ scale: 1.02, x: 3 }}
                whileTap={{ scale: 0.98 }}
              >
                <NavLink
                  to={item.to}
                  className={({ isActive }) =>
                    `sidebar-nav-item ${isActive ? 'active' : ''}`
                  }
                >
                  <item.icon size={15} />
                  <span>{item.label}</span>
                </NavLink>
              </motion.div>
            ))}
          </div>
        ))}
      </nav>

      {/* Account / User Card Footer — Clickable to Account Settings */}
      <div className="sidebar-footer">
        <div
          onClick={() => navigate('/app/settings/account')}
          title="Open Account Settings"
          style={{
            background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.01) 100%)',
            backdropFilter: 'blur(12px)',
            WebkitBackdropFilter: 'blur(12px)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '12px',
            boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08)',
            padding: 'var(--space-3)',
            marginBottom: 'var(--space-3)',
            cursor: 'pointer',
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = 'rgba(34, 211, 238, 0.4)';
            e.currentTarget.style.background = 'linear-gradient(135deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.02) 100%)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
            e.currentTarget.style.background = 'linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.01) 100%)';
          }}

        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <div style={{
              width: 28, height: 28, borderRadius: 4,
              background: 'var(--color-accent-bg)', border: '1px solid var(--color-accent-border)',
              color: 'var(--color-accent)', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
            }}>
              {initials}
            </div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {userDisplayName}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                {user?.role || 'Analyst'} Role
              </div>
            </div>
            <ChevronRight size={13} style={{ color: 'var(--text-muted)' }} />
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
