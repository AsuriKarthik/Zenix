/**
 * Findings Page — Core Security Analysis & Vulnerability Triage
 *
 * Splitted Views: Uploaded Scan Findings vs Live Runtime Findings
 * 25-item Pagination with "Load More"
 * Progressive Disclosure Finding Detail View
 * Persistent Analyst Triage Actions
 */

import React, { useState, useEffect, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Filter,
  X,
  ShieldAlert,
  ShieldCheck,
  Info,
  FileCode,
  Hash,
  Clock,
  Layers,
  Activity,
  CheckCircle,
  Clock3,
  CheckSquare,
  XCircle,
  FileText,
  Download,
  Globe,
} from 'lucide-react';
import { listJobs, listFindings, updateAnalystStatus } from '../api/jobs';
import { getTelemetrySessions } from '../api/telemetry';
import { generateRuntimeComplianceReport } from '../api/vex';
import { formatCvss, formatEpss, formatScore, formatJobId, formatRelativeTime, truncateHash, formatTimestamp } from '../utils/formatters';
import { JobStatusPill } from '../components/ui/StatusPill';
import EmptyState from '../components/ui/EmptyState';

const GLASS_CARD_STYLE = {
  background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.01) 100%)',
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  borderRadius: '16px',
  boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.1), 0 8px 32px 0 rgba(0, 0, 0, 0.36)',
};

/* ── Risk Badge Helper ───────────────────────────────────────── */
function RiskBadge({ score, isUnknownReachability }) {
  if (score === null || score === undefined || Number(score) === 0) {
    return (
      <span style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        fontWeight: 600,
        color: 'rgba(255, 255, 255, 0.45)',
        background: 'rgba(255, 255, 255, 0.04)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 4,
        padding: '2px 7px',
      }}>
        0.00
      </span>
    );
  }
  const n = Number(score);
  let color = 'var(--color-verified)';
  if (n >= 7.0) color = 'var(--color-critical)';
  else if (n >= 4.0) color = 'var(--color-warning)';
  return (
    <span style={{
      fontFamily: 'var(--font-mono)',
      fontSize: 12,
      fontWeight: 700,
      color,
      background: `${color}15`,
      border: `1px solid ${color}35`,
      borderRadius: 4,
      padding: '2px 7px',
    }}>
      {n.toFixed(2)}
    </span>
  );
}

/* ── Reachability Verdict Badge Helper ────────────────────────── */
function ReachabilityBadge({ reachabilityStatus, evidenceSource, loadedModule, executablePath, isDetailView = false }) {
  const status = (reachabilityStatus || 'UNKNOWN').toUpperCase();
  const hasEvidence = (evidenceSource && evidenceSource !== 'none') ||
                      (loadedModule && loadedModule !== 'N/A' && loadedModule !== '') ||
                      (executablePath && executablePath !== 'N/A' && executablePath !== '');

  let label = 'NOT DETERMINED';
  let fullLabel = 'NOT DETERMINED (MODULE OBSERVED)';
  let color = '#94A3B8';
  let bg = 'rgba(148, 163, 184, 0.12)';
  let border = 'rgba(148, 163, 184, 0.3)';

  if (status === 'REACHABLE' || status === 'EXPOSED') {
    label = 'REACHABLE';
    fullLabel = 'REACHABLE';
    color = 'var(--color-critical)';
    bg = 'var(--color-critical-bg)';
    border = 'var(--color-critical-border)';
  } else if ((status === 'NOT_REACHABLE' || status === 'SAFE') && hasEvidence) {
    label = 'NOT REACHABLE';
    fullLabel = 'SAFE (NOT REACHABLE)';
    color = 'var(--color-verified)';
    bg = 'var(--color-verified-bg)';
    border = 'var(--color-verified-border)';
  }

  const textToDisplay = isDetailView ? fullLabel : label;

  return (
    <span style={{
      fontSize: isDetailView ? 11 : 10,
      fontWeight: 700,
      fontFamily: 'var(--font-mono)',
      color,
      background: bg,
      border: `1px solid ${border}`,
      borderRadius: 4,
      padding: isDetailView ? '3px 8px' : '2px 6px',
    }}>
      {isDetailView ? `REACHABILITY VERDICT: ${textToDisplay}` : textToDisplay}
    </span>
  );
}

/* ── Threat Judgment Badge Helper ──────────────────────────── */
function ThreatJudgmentBadge({ judgment }) {
  const j = (judgment || 'INFORMATIONAL').toUpperCase();
  let color = '#3B82F6';
  let bg = 'rgba(59, 130, 246, 0.12)';
  let border = 'rgba(59, 130, 246, 0.35)';

  if (j === 'HARMFUL') {
    color = 'var(--color-critical)';
    bg = 'var(--color-critical-bg)';
    border = 'var(--color-critical-border)';
  } else if (j === 'SUSPICIOUS') {
    color = 'var(--color-warning)';
    bg = 'var(--color-warning-bg)';
    border = 'var(--color-warning-border)';
  } else if (j === 'SAFE' || j === 'NOT_SUSPICIOUS') {
    color = 'var(--color-verified)';
    bg = 'var(--color-verified-bg)';
    border = 'var(--color-verified-border)';
  } else if (j === 'UNKNOWN') {
    color = '#94A3B8';
    bg = 'rgba(148, 163, 184, 0.12)';
    border = 'rgba(148, 163, 184, 0.3)';
  }

  return (
    <span style={{
      fontSize: 10,
      fontWeight: 700,
      fontFamily: 'var(--font-mono)',
      color,
      background: bg,
      border: `1px solid ${border}`,
      borderRadius: 4,
      padding: '2px 8px',
      textTransform: 'uppercase',
    }}>
      {j.replace(/_/g, ' ')}
    </span>
  );
}

/* ── CVSS / EPSS Color Badge Helper ──────────────────────────── */
function CvssEpssBadge({ cvss, epss, isLookupIncomplete, isCleanComponent }) {
  if (isLookupIncomplete) {
    return <span style={{ color: '#F59E0B', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700 }}>CVSS: INCOMPLETE</span>;
  }
  if (isCleanComponent || cvss === null || cvss === undefined) {
    return <span style={{ color: 'rgba(255, 255, 255, 0.4)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>CVSS: N/A · EPSS: N/A</span>;
  }

  const score = Number(cvss);
  let color = '#10B981'; // Low (Green)

  if (score >= 9.0) {
    color = '#EF4444'; // Critical (Red)
  } else if (score >= 7.0) {
    color = '#F97316'; // High (Orange)
  } else if (score >= 4.0) {
    color = '#F59E0B'; // Medium (Yellow)
  }

  const epssVal = epss !== null && epss !== undefined ? (Number(epss) * 100).toFixed(1) : null;

  return (
    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#94a3b8' }}>
      CVSS: <strong style={{ color, fontWeight: 700 }}>{score.toFixed(1)}</strong>
      {epssVal !== null && (
        <span> · EPSS: <span style={{ color: 'rgba(255, 255, 255, 0.85)', fontWeight: 600 }}>{epssVal}%</span></span>
      )}
    </span>
  );
}

/* ── Analyst Status Badge ───────────────────────────────────── */
function AnalystStatusBadge({ status }) {
  const st = (status || 'UNTRIAGED').toUpperCase();
  let color = 'rgba(255, 255, 255, 0.6)';
  let bg = 'rgba(255, 255, 255, 0.05)';

  if (st === 'ACCEPT_RISK') {
    color = '#A855F7';
    bg = 'rgba(168, 85, 247, 0.15)';
  } else if (st === 'UNDER_INVESTIGATION') {
    color = '#F59E0B';
    bg = 'rgba(245, 158, 11, 0.15)';
  } else if (st === 'FALSE_POSITIVE') {
    color = '#64748B';
    bg = 'rgba(100, 116, 139, 0.15)';
  } else if (st === 'MITIGATED') {
    color = '#10B981';
    bg = 'rgba(16, 185, 129, 0.15)';
  }

  return (
    <span style={{
      fontSize: 10,
      fontWeight: 700,
      fontFamily: 'var(--font-mono)',
      color,
      background: bg,
      border: `1px solid ${color}40`,
      borderRadius: 4,
      padding: '2px 8px',
      textTransform: 'uppercase',
    }}>
      {st.replace(/_/g, ' ')}
    </span>
  );
}

/* ── Progressive Disclosure Finding Detail Panel ──────────────── */
function FindingDetailPanel({ finding, onStatusUpdate }) {
  const navigate = useNavigate();
  const [modalOpen, setModalOpen] = useState(false);
  const [targetAction, setTargetAction] = useState('');
  const [actionNote, setActionNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const rawCve = finding.cve_id;
  const isLookupIncomplete = rawCve === 'LOOKUP INCOMPLETE' || finding.is_scannable === false || !!finding.unscannable_reason;
  const isCleanComponent = rawCve === 'NO KNOWN CVES';
  const isMatchedCve = !isLookupIncomplete && !isCleanComponent && !!rawCve && rawCve !== '—';

  const cveTitleDisplay = isLookupIncomplete ? 'LOOKUP INCOMPLETE' : isCleanComponent ? 'NO KNOWN CVES' : (rawCve || '—');
  const compName = finding.component_name || finding.process_name || '—';
  const compVersion = finding.component_version;
  const cvss = finding.cvss;
  const cvssVer = finding.cvss_version || (cvss && cvss >= 9.0 ? '4.0' : '3.1');
  const cvssSev = finding.cvss_severity || (cvss && cvss >= 7.0 ? 'HIGH' : cvss && cvss >= 4.0 ? 'MEDIUM' : 'LOW');
  const epss = finding.epss;
  const epssPct = finding.epss_percentile;
  const reachability = (finding.reachability_status || 'UNKNOWN').toUpperCase();
  const evidenceSource = finding.evidence_source || 'none';
  const cvssSource = finding.cvss_source || 'NVD';
  const epssSource = finding.epss_source || 'FIRST EPSS';
  const finalScore = finding.final_score;
  const confidence = (finding.confidence || 'low').toUpperCase();
  const description = finding.description;

  const hasEvidence = (evidenceSource && evidenceSource !== 'none') ||
                      (finding.loaded_module && finding.loaded_module !== 'N/A' && finding.loaded_module !== '') ||
                      (finding.executable_path && finding.executable_path !== 'N/A' && finding.executable_path !== '');
  const isConfirmedSafe = (reachability === 'NOT_REACHABLE' || reachability === 'SAFE') && hasEvidence;
  const isUnknownReachability = finding.is_unknown_reachability ?? (!(reachability === 'REACHABLE' || reachability === 'EXPOSED') && !isConfirmedSafe);

  const openActionDialog = (action) => {
    setTargetAction(action);
    setActionNote(finding.analyst_note || '');
    setModalOpen(true);
  };

  const handleActionSubmit = async () => {
    if (!finding.id && !finding.vulnerability_id) return;
    const vulnId = finding.vulnerability_id || finding.id;
    setSubmitting(true);
    try {
      const res = await updateAnalystStatus(vulnId, targetAction, actionNote);
      setModalOpen(false);
      if (onStatusUpdate) {
        onStatusUpdate(vulnId, res.analyst_status, res.analyst_note);
      }
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to update analyst status.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{
      background: 'linear-gradient(135deg, rgba(255, 255, 255, 0.03) 0%, rgba(255, 255, 255, 0.01) 100%)',
      backdropFilter: 'blur(16px)',
      WebkitBackdropFilter: 'blur(16px)',
      border: '1px solid rgba(255, 255, 255, 0.08)',
      borderRadius: '12px',
      padding: 'var(--space-5) var(--space-6)',
      margin: 'var(--space-3) var(--space-4)',
    }}>
      
      {/* Section 1: Summary Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingBottom: 'var(--space-4)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        marginBottom: 'var(--space-4)',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{
              fontSize: 18,
              fontWeight: 700,
              color: isLookupIncomplete ? '#F59E0B' : '#FFFFFF',
              fontFamily: 'var(--font-mono)'
            }}>
              {cveTitleDisplay}
            </span>
            <AnalystStatusBadge status={finding.analyst_status} />
          </div>
          <div style={{ fontSize: 13, color: 'rgba(255, 255, 255, 0.7)', marginTop: 4 }}>
            Process / Component: <strong style={{ color: '#FFFFFF' }}>{compName}</strong> {compVersion ? `(${compVersion})` : ''}
          </div>
          {(finding.detection_time || finding.timestamp) && (
            <div style={{ fontSize: 11, color: 'var(--color-accent)', marginTop: 4, fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Clock size={12} /> Detection Time: <strong>{formatTimestamp(finding.detection_time || finding.timestamp)}</strong>
            </div>
          )}
        </div>

        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'rgba(255, 255, 255, 0.5)' }}>CONTEXTUAL RISK SCORE</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4, justifyContent: 'flex-end' }}>
            <RiskBadge score={finalScore} isUnknownReachability={isUnknownReachability} />
            <span style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.6)', fontFamily: 'var(--font-mono)' }}>Confidence: {confidence}</span>
          </div>
        </div>
      </div>

      {/* Section 2: Vulnerability Intelligence */}
      <div style={{ marginBottom: 'var(--space-5)' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 1.5, color: 'var(--color-accent)', marginBottom: 8, textTransform: 'uppercase', fontWeight: 700 }}>
          VULNERABILITY INTELLIGENCE & THREAT METRICS
        </div>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: 'var(--space-3)', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)' }}>CVSS SEVERITY RATING</div>
            <div style={{
              fontSize: 14,
              fontWeight: 700,
              color: isLookupIncomplete
                ? '#F59E0B'
                : cvss && cvss >= 9.0
                ? '#EF4444'
                : cvss && cvss >= 7.0
                ? '#F97316'
                : cvss && cvss >= 4.0
                ? '#F59E0B'
                : cvss
                ? '#10B981'
                : '#94A3B8',
              marginTop: 4,
              fontFamily: 'var(--font-mono)'
            }}>
              {isLookupIncomplete
                ? 'LOOKUP INCOMPLETE'
                : isCleanComponent
                ? 'N/A (No Known CVEs)'
                : cvss !== null && cvss !== undefined
                ? `${cvss.toFixed(1)} ${cvssSev}`
                : 'CVSS UNKNOWN'}
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-accent)', marginTop: 2, fontFamily: 'var(--font-mono)' }}>
              Source: {isCleanComponent || isLookupIncomplete ? 'N/A' : cvssSource}
            </div>
            {finding.cvss_reason && (
              <div style={{ fontSize: 10, color: 'var(--color-warning)', marginTop: 4 }}>
                Reason: {finding.cvss_reason}
              </div>
            )}
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: 'var(--space-3)', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)' }}>EPSS EXPLOITATION PROBABILITY</div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#FFFFFF', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
              {isLookupIncomplete
                ? 'LOOKUP INCOMPLETE'
                : isCleanComponent
                ? 'N/A (No Known CVEs)'
                : epss !== null && epss !== undefined
                ? `${(epss * 100).toFixed(2)}% ${epssPct ? `(${Math.round(epssPct * 100)}th %tile)` : ''}`
                : 'UNAVAILABLE'}
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-accent)', marginTop: 2, fontFamily: 'var(--font-mono)' }}>
              Source: {isCleanComponent || isLookupIncomplete ? 'N/A' : epssSource}
            </div>
            {finding.epss_reason && (
              <div style={{ fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', marginTop: 4 }}>
                {finding.epss_reason}
              </div>
            )}
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: 'var(--space-3)', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)' }}>CISA KEV CATALOG STATUS</div>
            <div style={{ fontSize: 14, fontWeight: 700, color: finding.is_kev ? 'var(--color-critical)' : '#FFFFFF', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
              {finding.is_kev ? 'YES (Active KEV Listing)' : 'NO (Not in KEV Catalog)'}
            </div>
            {finding.kev_reason && (
              <div style={{ fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', marginTop: 4 }}>
                {finding.kev_reason}
              </div>
            )}
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: 'var(--space-3)', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)' }}>SHODAN EXPOSED HOSTS</span>
              <Globe size={12} color="#F97316" />
            </div>
            <div style={{
              fontSize: 14,
              fontWeight: 700,
              color: isLookupIncomplete || isCleanComponent
                ? '#94A3B8'
                : finding.shodan_exposed_hosts && finding.shodan_exposed_hosts > 0
                ? '#F97316'
                : '#10B981',
              marginTop: 4,
              fontFamily: 'var(--font-mono)'
            }}>
              {isLookupIncomplete || isCleanComponent
                ? 'N/A'
                : finding.shodan_exposed_hosts !== null && finding.shodan_exposed_hosts !== undefined
                ? `${finding.shodan_exposed_hosts} Exposed Hosts`
                : '0 Exposed Hosts'}
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-accent)', marginTop: 2, fontFamily: 'var(--font-mono)' }}>
              Source: Shodan Global Feed
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: 'var(--space-3)', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 10, color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)' }}>VIRUSTOTAL INTELLIGENCE</span>
              <ShieldAlert size={12} color={finding.virustotal_detections > 0 ? '#EF4444' : '#10B981'} />
            </div>
            <div style={{
              fontSize: 14,
              fontWeight: 700,
              color: isLookupIncomplete || isCleanComponent
                ? '#94A3B8'
                : finding.virustotal_detections && finding.virustotal_detections > 0
                ? '#EF4444'
                : '#10B981',
              marginTop: 4,
              fontFamily: 'var(--font-mono)'
            }}>
              {isLookupIncomplete || isCleanComponent
                ? 'N/A'
                : finding.virustotal_detections !== null && finding.virustotal_detections !== undefined
                ? (finding.virustotal_detections > 0 ? `${finding.virustotal_detections} Threat Detections` : 'Clean (0 Detections)')
                : 'Clean (0 Detections)'}
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-accent)', marginTop: 2, fontFamily: 'var(--font-mono)' }}>
              Source: VirusTotal v3 Analysis
            </div>
          </div>
        </div>

        {description && (
          <div style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.8)', lineHeight: 1.5, background: 'rgba(255, 255, 255, 0.02)', padding: 10, borderRadius: 6 }}>
            {description}
          </div>
        )}
      </div>

      {/* Section 3: Runtime & Loaded Module Evidence */}
      <div style={{ marginBottom: 'var(--space-5)' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 1.5, color: 'var(--color-accent)', marginBottom: 8, textTransform: 'uppercase', fontWeight: 700 }}>
          RUNTIME TELEMETRY & MODULE EVIDENCE
        </div>
        <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
            <ReachabilityBadge
              reachabilityStatus={reachability}
              evidenceSource={evidenceSource}
              loadedModule={finding.loaded_module}
              executablePath={finding.executable_path}
              isDetailView={true}
            />
          </div>

          <div style={{ fontSize: 11, color: '#FFFFFF', fontFamily: 'var(--font-mono)', background: 'rgba(0, 0, 0, 0.3)', padding: '10px 14px', borderRadius: 6, border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ color: 'rgba(255, 255, 255, 0.5)', fontSize: 10, marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.5 }}>Loaded Module & Process Details</div>
            <div><strong>Process Name:</strong> {compName} {finding.pid ? `(PID ${finding.pid})` : ''}</div>
            <div style={{ marginTop: 4 }}><strong>Loaded Module / Binary Path:</strong> <span style={{ color: 'var(--color-accent)', wordBreak: 'break-all' }}>{finding.executable_path || finding.loaded_module || 'N/A'}</span></div>
            <div style={{ marginTop: 4 }}><strong>Observation Time:</strong> {formatTimestamp(finding.detection_time || finding.timestamp)}</div>
            
            {finding.loaded_modules && finding.loaded_modules.length > 0 && (
              <div style={{ marginTop: 10, paddingTop: 8, borderTop: '1px dashed rgba(255, 255, 255, 0.1)' }}>
                <div style={{ color: 'rgba(255, 255, 255, 0.5)', fontSize: 10, marginBottom: 4, textTransform: 'uppercase' }}>
                  Child Runtime Modules & Resources ({finding.loaded_modules.length}):
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 4 }}>
                  {finding.loaded_modules.map((m, idx) => (
                    <span key={idx} style={{
                      fontSize: 10,
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-accent)',
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: 4,
                      padding: '2px 6px',
                    }}>
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Section 6: Analyst Action Bar */}
      <div style={{
        pt: 12,
        borderTop: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'rgba(255, 255, 255, 0.5)' }}>
          PERSISTENT ANALYST ACTIONS:
        </div>
        
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <button
            className="btn btn-sm"
            onClick={() => openActionDialog('UNDER_INVESTIGATION')}
            style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#F59E0B', border: '1px solid rgba(245, 158, 11, 0.4)' }}
          >
            Mark Under Investigation
          </button>
          <button
            className="btn btn-sm"
            onClick={() => openActionDialog('ACCEPT_RISK')}
            style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#A855F7', border: '1px solid rgba(168, 85, 247, 0.4)' }}
          >
            Accept Risk
          </button>
          <button
            className="btn btn-sm"
            onClick={() => openActionDialog('FALSE_POSITIVE')}
            style={{ background: 'rgba(100, 116, 139, 0.15)', color: '#64748B', border: '1px solid rgba(100, 116, 139, 0.4)' }}
          >
            False Positive
          </button>
          <button
            className="btn btn-sm"
            onClick={() => openActionDialog('MITIGATED')}
            style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10B981', border: '1px solid rgba(16, 185, 129, 0.4)' }}
          >
            Mitigated
          </button>
          {finding.job_id && (
            <button
              className="btn btn-sm btn-secondary"
              onClick={() => navigate(`/vex?jobId=${finding.job_id}&cveId=${cveId}`)}
            >
              Export VEX Report
            </button>
          )}
        </div>
      </div>

      {/* Analyst Action Modal */}
      {modalOpen && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
        }}>
          <div style={{
            ...GLASS_CARD_STYLE,
            width: 480, padding: 'var(--space-6)', borderRadius: 12,
          }}>
            <h3 style={{ margin: 0, fontSize: 16, color: '#FFFFFF', fontFamily: 'var(--font-heading)' }}>
              Update Analyst Triage Status
            </h3>
            <p style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.6)', marginTop: 4 }}>
              Setting status for <strong>{cveId}</strong> to <strong style={{ color: 'var(--color-accent)' }}>{targetAction.replace('_', ' ')}</strong>.
            </p>

            <div style={{ marginTop: 14 }}>
              <label style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'rgba(255, 255, 255, 0.6)' }}>
                ANALYST NOTES / JUSTIFICATION:
              </label>
              <textarea
                className="input"
                rows={4}
                value={actionNote}
                onChange={e => setActionNote(e.target.value)}
                placeholder="Enter audit justification or mitigation notes..."
                style={{ width: '100%', marginTop: 6, fontSize: 12, fontFamily: 'var(--font-mono)' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 18 }}>
              <button className="btn btn-sm btn-ghost" onClick={() => setModalOpen(false)}>Cancel</button>
              <button className="btn btn-sm btn-primary" onClick={handleActionSubmit} disabled={submitting}>
                {submitting ? 'Saving...' : 'Save Decision'}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

/* ── Main Findings Page Component ───────────────────────────── */
export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlJobId = searchParams.get('jobId');
  const urlFilter = searchParams.get('filter');

  const [activeTab, setActiveTab] = useState('uploaded'); // 'uploaded' | 'runtime'
  const [filter, setFilter] = useState('all'); // 'all' | 'vulnerable' | 'reachable'
  const [runtimeHistory, setRuntimeHistory] = useState('all'); // 'all' | 'today' | 'yesterday' | 'YYYY-MM-DD'
  const [availableDates, setAvailableDates] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [selectedJob, setSelectedJob] = useState(null);
  const [jobsLoading, setJobsLoading] = useState(true);


  // Paginated Findings State
  const [findings, setFindings] = useState([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [expandedIndex, setExpandedIndex] = useState(null);
  const [generatingCompliance, setGeneratingCompliance] = useState(false);
  const [complianceMsg, setComplianceMsg] = useState(null);

  const handleGenerateRuntimeCompliance = async () => {
    setGeneratingCompliance(true);
    setComplianceMsg(null);
    try {
      const dateVal = runtimeHistory || 'today';
      const res = await generateRuntimeComplianceReport(dateVal);
      setComplianceMsg({
        text: res.message || `Live Telemetry Compliance Report successfully generated for ${dateVal}.`,
        count: res.generated_count || 0,
        date: res.report_date || dateVal,
        jobId: res.job_id || '',
      });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to generate Live Telemetry Compliance Report.');
    } finally {
      setGeneratingCompliance(false);
    }
  };

  // Fetch Jobs List for dropdown
  useEffect(() => {
    listJobs()
      .then(res => {
        setJobs(res);
        if (res.length > 0) {
          const match = urlJobId ? res.find(j => j.job_id === urlJobId) : res.find(j => j.status === 'done') || res[0];
          setSelectedJob(match || res[0]);
        }
      })
      .catch(err => setError('Failed to load scans list.'))
      .finally(() => setJobsLoading(false));
  }, [urlJobId]);

  // Fetch distinct telemetry dates for runtime history dropdown
  useEffect(() => {
    if (activeTab === 'runtime') {
      getTelemetrySessions()
        .then(res => {
          if (res?.dates && Array.isArray(res.dates)) {
            setAvailableDates(res.dates);
          }
        })
        .catch(() => {});
    }
  }, [activeTab]);

  // Load findings with 25-item pagination
  const loadFindingsPage = async (pageNum, reset = false) => {
    if (reset) {
      setLoading(true);
    } else {
      setLoadingMore(true);
    }
    setError(null);

    try {
      const params = {
        finding_type: activeTab,
        page: pageNum,
        per_page: 25,
      };
      if (activeTab === 'uploaded' && selectedJob) {
        params.job_id = selectedJob.job_id;
        params.filter = filter;
      } else if (activeTab === 'runtime') {
        if (runtimeHistory === 'today' || runtimeHistory === 'TODAY') params.timeframe = 'today';
        else if (runtimeHistory === 'yesterday' || runtimeHistory === 'YESTERDAY') params.timeframe = 'yesterday';
        else if (runtimeHistory && runtimeHistory !== 'all' && runtimeHistory !== 'ALL HISTORY') params.date = runtimeHistory;
        else params.timeframe = 'all';
      }

      const res = await listFindings(params);
      if (reset) {
        setFindings(res.items || []);
      } else {
        setFindings(prev => [...prev, ...(res.items || [])]);
      }
      setTotal(res.total || 0);
      setHasMore(res.has_more || false);
      setPage(pageNum);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to fetch findings.');
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  // Re-fetch when activeTab, selectedJob, filter, or runtimeHistory changes
  useEffect(() => {
    loadFindingsPage(1, true);
    setExpandedIndex(null);
  }, [activeTab, selectedJob, filter, runtimeHistory]);

  const handleLoadMore = () => {
    if (hasMore && !loadingMore) {
      loadFindingsPage(page + 1, false);
    }
  };

  const handleStatusUpdateInList = (vulnId, newStatus, newNote) => {
    setFindings(prev => prev.map(f => {
      if (f.id === vulnId || f.vulnerability_id === vulnId) {
        return { ...f, analyst_status: newStatus, analyst_note: newNote };
      }
      return f;
    }));
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto' }}>
      
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 'var(--space-6)',
        paddingBottom: 'var(--space-4)',
        borderBottom: '1px solid var(--border-subtle)',
      }}>
        <div>
          <h1 style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 24,
            fontWeight: 700,
            color: '#FFFFFF',
            letterSpacing: '-0.5px',
            margin: 0,
          }}>
            Findings
          </h1>
        </div>

        {/* Scan Selector (for Uploaded view) */}
        {activeTab === 'uploaded' && !jobsLoading && jobs.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <label htmlFor="scan-select" style={{ fontSize: 12, color: 'rgba(255, 255, 255, 0.5)', fontFamily: 'var(--font-mono)' }}>
              SELECT SCAN:
            </label>
            <select
              id="scan-select"
              className="select"
              value={selectedJob?.job_id || ''}
              onChange={e => {
                const match = jobs.find(j => j.job_id === e.target.value);
                if (match) setSelectedJob(match);
              }}
              style={{ minWidth: 440, fontSize: 12, fontFamily: 'var(--font-mono)' }}
            >
              {jobs.map(j => {
                let dateStr = 'N/A';
                if (j.submitted_at) {
                  try {
                    const d = new Date(j.submitted_at);
                    if (!isNaN(d.getTime())) {
                      const yyyy = d.getFullYear();
                      const mm = String(d.getMonth() + 1).padStart(2, '0');
                      const dd = String(d.getDate()).padStart(2, '0');
                      const hh = String(d.getHours()).padStart(2, '0');
                      const min = String(d.getMinutes()).padStart(2, '0');
                      dateStr = `${yyyy}-${mm}-${dd} ${hh}:${min}`;
                    } else {
                      dateStr = j.submitted_at.replace('T', ' ').split('.')[0];
                    }
                  } catch {
                    dateStr = String(j.submitted_at);
                  }
                }
                const filename = j.sbom_filename || 'sbom.json';
                const count = j.component_count ?? 0;
                return (
                  <option key={j.job_id} value={j.job_id}>
                    {dateStr}   —   {filename} ({count} components)
                  </option>
                );
              })}
            </select>
          </div>
        )}
      </div>

      {/* Navigation Tabs + Component Filters */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 'var(--space-6)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        paddingBottom: 'var(--space-3)',
      }}>
        <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
          <button
            className={`btn ${activeTab === 'uploaded' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setActiveTab('uploaded')}
            style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}
          >
            <FileCode size={16} />
            Uploaded Scan Components & Findings ({total})
          </button>
          <button
            className={`btn ${activeTab === 'runtime' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setActiveTab('runtime')}
            style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}
          >
            <Activity size={16} />
            Live Runtime Findings (ETW / PSUTIL)
          </button>
        </div>

        {activeTab === 'runtime' ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <label htmlFor="history-date-select" style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
              SELECT HISTORY DATE:
            </label>
            <select
              id="history-date-select"
              className="select"
              value={runtimeHistory}
              onChange={e => setRuntimeHistory(e.target.value)}
              style={{ minWidth: 220, fontSize: 11, fontFamily: 'var(--font-mono)', padding: '4px 10px' }}
            >
              <option value="all">ALL HISTORY (ALL DATES)</option>
              <option value="today">TODAY</option>
              <option value="yesterday">YESTERDAY</option>
              {availableDates
                .filter(d => {
                  const todayStr = new Date().toISOString().split('T')[0];
                  const yestStr = new Date(Date.now() - 86400000).toISOString().split('T')[0];
                  return d !== todayStr && d !== yestStr;
                })
                .map(d => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
            </select>

            <button
              className="btn btn-primary btn-sm"
              onClick={handleGenerateRuntimeCompliance}
              disabled={generatingCompliance}
              title="Generate Compliance Report"
              style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: '6px 10px' }}
            >
              <FileText size={15} className={generatingCompliance ? 'spin' : ''} />
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 11, color: '#94a3b8', fontFamily: 'var(--font-mono)', marginRight: 4, letterSpacing: '0.05em' }}>FILTER:</span>
            <button
              className={`filter-chip ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
              style={{ fontSize: 11, padding: '3px 10px' }}
            >
              All Components ({selectedJob?.component_count ?? total})
            </button>
            <button
              className={`filter-chip ${filter === 'vulnerable' ? 'active' : ''}`}
              onClick={() => setFilter('vulnerable')}
              style={{ fontSize: 11, padding: '3px 10px', color: filter === 'vulnerable' ? '#FF4D4D' : undefined }}
            >
              Vulnerable Only
            </button>
            <button
              className={`filter-chip ${filter === 'reachable' ? 'active' : ''}`}
              onClick={() => setFilter('reachable')}
              style={{ fontSize: 11, padding: '3px 10px', color: filter === 'reachable' ? '#10B981' : undefined }}
            >
              Reachable Only
            </button>
          </div>
        )}
      </div>

      {complianceMsg && (
        <div className="alert alert-success" style={{ marginBottom: 'var(--space-4)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '10px 16px', borderRadius: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#10B981', fontSize: 13, fontWeight: 600 }}>
            <CheckCircle size={16} />
            <span>{complianceMsg.text} ({complianceMsg.count} VEX Compliance records created)</span>
          </div>
          <button
            className="btn btn-sm btn-ghost"
            onClick={() => {
              const qParams = new URLSearchParams();
              if (complianceMsg.date) qParams.set('date', complianceMsg.date);
              qParams.set('source', 'live_telemetry');
              navigate(`/app/vex?${qParams.toString()}`);
            }}
            style={{ color: '#38BDF8', textDecoration: 'underline', fontSize: 12, fontWeight: 600 }}
          >
            View in VEX / Compliance Tab →
          </button>
        </div>
      )}


      {error && (
        <div className="alert alert-error" style={{ marginBottom: 'var(--space-6)' }}>
          <AlertTriangle size={14} />
          {error}
        </div>
      )}



      {/* Findings List Table */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 'var(--space-12)', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
          Loading findings...
        </div>
      ) : findings.length === 0 ? (
        <EmptyState
          title={activeTab === 'runtime' ? 'No Live Runtime Telemetry Detections' : 'No Uploaded Findings Found'}
          description={activeTab === 'runtime' ? 'Enable ETW Runtime Monitoring to capture live image load events.' : 'Select a completed scan job or upload an SBOM file.'}
        />
      ) : (
        <div style={{ ...GLASS_CARD_STYLE, overflow: 'hidden' }}>
          <table className="table" style={{ width: '100%', tableLayout: 'fixed', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'rgba(255, 255, 255, 0.03)', borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <th style={{ width: 36, textAlign: 'center', padding: '12px 8px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, borderBottom: '1px solid rgba(255,255,255,0.05)' }}></th>
                <th style={{ textAlign: 'left', padding: '12px 16px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: activeTab === 'runtime' ? '18%' : '20%' }}>{activeTab === 'uploaded' ? 'VULNERABILITY' : 'THREAT / FINDING'}</th>
                <th style={{ textAlign: 'left', padding: '12px 16px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: activeTab === 'runtime' ? '20%' : '24%' }}>{activeTab === 'uploaded' ? 'COMPONENT' : 'PROCESS (PID)'}</th>
                {activeTab === 'uploaded' ? (
                  <>
                    <th style={{ textAlign: 'left', padding: '12px 12px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: '10%' }}>CVSS</th>
                    <th style={{ textAlign: 'left', padding: '12px 12px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: '10%' }}>EPSS</th>
                  </>
                ) : (
                  <th style={{ textAlign: 'left', padding: '12px 16px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: '14%' }}>THREAT JUDGMENT</th>
                )}
                <th style={{ textAlign: 'left', padding: '12px 16px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: activeTab === 'runtime' ? '12%' : '11%' }}>REACHABILITY</th>
                {activeTab === 'runtime' && (
                  <th style={{ textAlign: 'left', padding: '12px 16px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: '14%' }}>DETECTION TIME</th>
                )}
                <th style={{ textAlign: 'left', padding: '12px 16px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: activeTab === 'runtime' ? '12%' : '12%' }}>ANALYST STATUS</th>
                <th style={{ textAlign: 'right', padding: '12px 16px', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)', width: activeTab === 'runtime' ? '12%' : '13%', whiteSpace: 'nowrap' }}>CONTEXTUAL RISK</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((item, idx) => {
                const isExpanded = expandedIndex === idx;
                const rawCve = item.cve_id || item.threat_label;
                const isLookupIncomplete = rawCve === 'LOOKUP INCOMPLETE' || item.is_scannable === false || !!item.unscannable_reason;
                const isCleanComponent = rawCve === 'NO KNOWN CVES';
                const isMatchedCve = !isLookupIncomplete && !isCleanComponent && !!rawCve && rawCve !== '—';

                const threatLabel = isLookupIncomplete ? 'LOOKUP INCOMPLETE' : isCleanComponent ? 'NO KNOWN CVES' : (rawCve || '—');
                const compName = item.component_name || item.process_name || '—';
                const compVer = item.component_version || (item.pid ? `PID ${item.pid}` : '');
                const cvss = item.cvss;
                const epss = item.epss;
                const reach = (item.reachability_status || 'UNKNOWN').toUpperCase();

                const hasEvidence = (item.evidence_source && item.evidence_source !== 'none') ||
                                    (item.loaded_module && item.loaded_module !== 'N/A' && item.loaded_module !== '') ||
                                    (item.executable_path && item.executable_path !== 'N/A' && item.executable_path !== '');
                const isConfirmedSafe = (reach === 'NOT_REACHABLE' || reach === 'SAFE') && hasEvidence;
                const isUnknownReachability = item.is_unknown_reachability ?? (!(reach === 'REACHABLE' || reach === 'EXPOSED') && !isConfirmedSafe);

                return (
                  <React.Fragment key={`fnd-${item.id}-${idx}`}>
                    <tr
                      style={{
                        borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                        cursor: 'pointer',
                        background: isExpanded ? 'rgba(255, 255, 255, 0.04)' : 'transparent',
                      }}
                      onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                    >
                      <td style={{ padding: '14px 8px', textAlign: 'center' }}>
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td style={{
                        padding: '14px 16px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: 13,
                        fontWeight: 700,
                        color: isLookupIncomplete ? '#F59E0B' : '#f8fafc',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                          <span>{threatLabel}</span>
                          {item.shodan_exposed_hosts > 0 && (
                            <span
                              title={`${item.shodan_exposed_hosts} live exposed hosts indexed by Shodan`}
                              style={{
                                fontSize: 10,
                                padding: '1px 6px',
                                borderRadius: 4,
                                background: 'rgba(249, 115, 22, 0.15)',
                                color: '#F97316',
                                border: '1px solid rgba(249, 115, 22, 0.35)',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 3
                              }}
                            >
                              <Globe size={10} /> {item.shodan_exposed_hosts}
                            </span>
                          )}
                          {item.virustotal_detections > 0 && (
                            <span
                              title={`${item.virustotal_detections} malicious detections in VirusTotal`}
                              style={{
                                fontSize: 10,
                                padding: '1px 6px',
                                borderRadius: 4,
                                background: 'rgba(239, 68, 68, 0.15)',
                                color: '#EF4444',
                                border: '1px solid rgba(239, 68, 68, 0.35)',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 3
                              }}
                            >
                              VT: {item.virustotal_detections}
                            </span>
                          )}
                        </div>
                      </td>
                      <td style={{ padding: '14px 16px', fontSize: 13, color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <strong style={{ color: '#f8fafc' }}>{compName}</strong> {compVer ? `(${compVer})` : ''}
                      </td>

                      {activeTab === 'uploaded' ? (
                        <>
                          <td style={{ padding: '14px 12px', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                            {isLookupIncomplete ? (
                              <span style={{ color: '#F59E0B', fontWeight: 700 }}>INCOMPLETE</span>
                            ) : isCleanComponent || cvss === null || cvss === undefined ? (
                              <span style={{ color: 'rgba(255, 255, 255, 0.4)' }}>N/A</span>
                            ) : (
                              <strong style={{
                                color: Number(cvss) >= 9.0 ? '#EF4444' : Number(cvss) >= 7.0 ? '#F97316' : Number(cvss) >= 4.0 ? '#F59E0B' : '#10B981',
                                fontWeight: 700
                              }}>
                                {Number(cvss).toFixed(1)}
                              </strong>
                            )}
                          </td>
                          <td style={{ padding: '14px 12px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'rgba(255, 255, 255, 0.85)' }}>
                            {isLookupIncomplete || isCleanComponent || epss === null || epss === undefined ? (
                              <span style={{ color: 'rgba(255, 255, 255, 0.4)' }}>N/A</span>
                            ) : (
                              <span>{(Number(epss) * 100).toFixed(1)}%</span>
                            )}
                          </td>
                        </>
                      ) : (
                        <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                          <ThreatJudgmentBadge judgment={item.threat_judgment} />
                        </td>
                      )}

                      <td style={{ padding: '14px 16px' }}>
                        <ReachabilityBadge
                          reachabilityStatus={reach}
                          evidenceSource={item.evidence_source}
                          loadedModule={item.loaded_module}
                          executablePath={item.executable_path}
                          isDetailView={false}
                        />
                      </td>

                      {activeTab === 'runtime' && (
                        <td style={{ padding: '14px 16px', fontSize: 11, fontFamily: 'var(--font-mono)', color: '#94a3b8', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            <Clock size={12} color="var(--color-accent)" />
                            {formatTimestamp(item.detection_time || item.timestamp)}
                          </div>
                        </td>
                      )}

                      <td style={{ padding: '14px 16px' }}>
                        <AnalystStatusBadge status={item.analyst_status} />
                      </td>
                      <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                        <RiskBadge score={item.final_score} isUnknownReachability={isUnknownReachability} />
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={activeTab === 'runtime' ? 7 : 8} style={{ padding: 0 }}>
                          <FindingDetailPanel finding={item} onStatusUpdate={handleStatusUpdateInList} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>

          {/* 25-item Pagination Controls */}
          <div style={{
            padding: 'var(--space-4) var(--space-6)',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
            color: 'rgba(255, 255, 255, 0.6)',
          }}>
            <div>
              Showing {findings.length} of {total} findings (Page {page})
            </div>

            {hasMore && (
              <button
                className="btn btn-sm btn-secondary"
                onClick={handleLoadMore}
                disabled={loadingMore}
              >
                {loadingMore ? 'Loading next 25...' : 'Load More (Next 25)'}
              </button>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
