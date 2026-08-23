/**
 * API / Feed Status Settings — Native Zenix System Design
 *
 * Shows external data feed configuration and freshness.
 * Source: GET /api/telemetry/status
 */

import React, { useState, useEffect } from 'react';
import { RefreshCw, ExternalLink, Database } from 'lucide-react';
import { getTelemetryStatus } from '../../api/telemetry';
import PulseIndicator from '../../components/ui/PulseIndicator';

const FEEDS = [
  {
    name: 'OSV (Open Source Vulnerabilities)',
    key: 'osv',
    url: 'https://osv.dev',
    description: 'Primary vulnerability database for SBOM components',
    protocol: 'REST / JSON',
  },
  {
    name: 'NIST NVD',
    key: 'nvd',
    url: 'https://nvd.nist.gov',
    description: 'CVSS scores and extended vulnerability data',
    protocol: 'REST API v2',
  },
  {
    name: 'FIRST EPSS',
    key: 'epss',
    url: 'https://www.first.org/epss',
    description: 'Exploit probability scoring',
    protocol: 'CSV / JSON',
  },
  {
    name: 'CISA KEV',
    key: 'kev',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    description: 'Known exploited vulnerabilities catalog',
    protocol: 'JSON Feed',
  },
];

export default function ApiStatus() {
  const [status, setStatus]   = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const data = await getTelemetryStatus();
      setStatus(data);
    } catch {} finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchStatus(); }, []);

  return (
    <div>
      {/* 2-Column Full Width Grid for Feeds */}
      <div className="stat-grid-2 mb-6">
        {FEEDS.map((feed) => {
          const freshness = status?.[`${feed.key}_freshness`] || (loading ? 'Pinging endpoint…' : 'Unavailable');
          const feedStatus = status?.[`${feed.key}_status`] || (loading ? 'CHECKING' : 'OFFLINE');

          const isOnline = feedStatus === 'ONLINE';
          const isDegraded = feedStatus === 'DEGRADED' || feedStatus === 'STALE';
          const statusColor = isOnline
            ? 'var(--color-verified)'
            : isDegraded
            ? 'var(--color-warning)'
            : 'var(--color-critical)';

          const pulseVariant = isOnline ? 'verified' : isDegraded ? 'warning' : 'critical';

          return (
            <div key={feed.key} className="card">
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                  <div style={{
                    width: 36, height: 36,
                    background: 'var(--bg-surface-2)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Database size={16} style={{ color: statusColor }} />
                  </div>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{feed.name}</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                      {feed.description}
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <PulseIndicator variant={pulseVariant} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, letterSpacing: 1, color: statusColor }}>
                    {feedStatus}
                  </span>
                </div>
              </div>

              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 'var(--space-3)',
                marginBottom: 'var(--space-4)',
              }}>
                <div style={{
                  padding: 'var(--space-2) var(--space-3)',
                  background: 'var(--bg-surface-2)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                    FRESHNESS
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                    {freshness}
                  </div>
                </div>

                <div style={{
                  padding: 'var(--space-2) var(--space-3)',
                  background: 'var(--bg-surface-2)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4 }}>
                    PROTOCOL
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                    {feed.protocol}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <a
                  href={feed.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-ghost btn-sm"
                  style={{ gap: 6 }}
                >
                  View Feed Source <ExternalLink size={12} />
                </a>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
