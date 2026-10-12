/**
 * Account Settings
 * Displays current user information from session.
 * Source: useAuth (from /api/auth/me on app load)
 */

import React from 'react';
import { useAuth } from '../../hooks/useAuth';
import { formatTimestamp } from '../../utils/formatters';

export default function AccountSettings() {
  const { user } = useAuth();

  const fields = [
    { label: 'EMAIL',      value: user?.email },
    { label: 'ROLE',       value: (user?.role || '—').toUpperCase() },
    { label: 'USER ID',    value: user?.id, mono: true },
    { label: 'REGISTERED', value: formatTimestamp(user?.created_at) },
  ];

  return (
    <div>
      <div className="card" style={{ maxWidth: 560 }}>
        <div className="card-header">
          <span className="card-title">Account</span>
          <span className="card-hud-label">SESSION INFO</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {fields.map(({ label, value, mono }) => (
            <div
              key={label}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: 'var(--space-3) var(--space-4)',
                background: 'var(--bg-surface-2)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                {label}
              </span>
              <span style={{ fontFamily: mono ? 'var(--font-mono)' : 'var(--font-body)', fontSize: 13, color: 'var(--text-primary)' }}>
                {value || '—'}
              </span>
            </div>
          ))}
        </div>

        <div className="alert alert-info" style={{ marginTop: 'var(--space-4)' }}>
          <span style={{ fontSize: 12 }}>
            Password changes and role management require administrator access via the backend.
          </span>
        </div>
      </div>
    </div>
  );
}
