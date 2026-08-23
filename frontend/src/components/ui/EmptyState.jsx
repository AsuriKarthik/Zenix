/**
 * EmptyState — No data placeholder
 */

import React from 'react';
import { Inbox } from 'lucide-react';

/**
 * @param {{ icon?: React.ElementType, title: string, description?: string, action?: React.ReactNode }} props
 */
export default function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
}) {
  return (
    <div className="empty-state">
      <Icon className="empty-state-icon" />
      <div className="empty-state-title">{title}</div>
      {description && (
        <div className="empty-state-desc">{description}</div>
      )}
      {action && (
        <div style={{ marginTop: 'var(--space-5)' }}>{action}</div>
      )}
    </div>
  );
}
