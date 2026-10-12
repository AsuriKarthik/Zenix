/**
 * API / Feed Status Settings
 *
 * Shows external data feed configuration and freshness.
 * Source: GET /api/telemetry/status (contains feed metadata)
 */

import React, { useState, useEffect } from 'react';
import { RefreshCw, ExternalLink } from 'lucide-react';
import { getTelemetryStatus } from '../../api/telemetry';
import PulseIndicator from '../../components/ui/PulseIndicator';

const FEEDS = [
  {
    name: 'OSV (Open Source Vulnerabilities)',
    key: 'osv',
    url: 'https://osv.dev',
    description: 'Primary vulnerability database for SBOM components',
  },
  {
    name: 'NIST NVD',
    key: 'nvd',
    url: 'https://nvd.nist.gov',
    description: 'CVSS scores and extended vulnerability data',
  },
  {
    name: 'FIRST EPSS',
    key: 'epss',
    url: 'https://www.first.org/epss',
    description: 'Exploit probability scoring',
  },
  {
    name: 'CISA KEV',
    key: 'kev',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    description: 'Known exploited vulnerabilities catalog',
  },
];

export default function ApiStatus() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchStatus = async () => {
    try {
      const data = await getTelemetryStatus();
      setStatus(data);
    } catch {} finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchStatus(); }, []);

  return (
    <div style={{ maxWidth: 640 }}>
      <div className="card">
        <div className="card-header">
          <span className="card-title">External Feed Status</span>
          <button className="btn btn-ghost btn-sm" onClick={fetchStatus}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {FEEDS.map((feed) => {
            const freshness = status?.[`${feed.key}_freshness`] || (loading ? '…' : 'Active');

            return (
              <div
                key={feed.key}
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
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                  <PulseIndicator variant="verified" size={8} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 2 }}>
                      {feed.name}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{feed.description}</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexShrink: 0 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                    {freshness}
                  </span>
                  <a
                    href={feed.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-ghost btn-sm"
                    style={{ padding: '2px 6px' }}
                  >
                    <ExternalLink size={11} />
                  </a>
                </div>
              </div>
            );
          })}
        </div>

        <div className="alert alert-info" style={{ marginTop: 'var(--space-4)' }}>
          <span style={{ fontSize: 12 }}>
            Feed credentials and API keys are configured via backend environment variables.
            See <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>.env.example</code> in the backend directory.
          </span>
        </div>
      </div>
    </div>
  );
}
