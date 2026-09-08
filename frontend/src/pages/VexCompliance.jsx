import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Key, RefreshCw, AlertOctagon, Filter, Download, AlertTriangle, ShieldCheck, Activity, FileText, Calendar } from 'lucide-react';
import { getVexDocuments, downloadVexDocument } from '../api/vex';
import { getTelemetrySessions } from '../api/telemetry';
import { formatTimestamp, formatJobId } from '../utils/formatters';

const ComplianceView = () => {
    const [searchParams, setSearchParams] = useSearchParams();
    const urlDate = searchParams.get('date');
    const urlSource = searchParams.get('source');

    const [docs, setDocs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [statusFilter, setStatusFilter] = useState('ALL');
    const [sourceFilter, setSourceFilter] = useState(urlSource || 'ALL'); // 'ALL' | 'uploaded' | 'live_telemetry'
    const [dateFilter, setDateFilter] = useState(urlDate || 'ALL'); // 'ALL' | 'today' | 'yesterday' | 'YYYY-MM-DD'
    const [availableDates, setAvailableDates] = useState([]);
    const [error, setError] = useState(null);

    // Sync from URL query parameters if they change
    useEffect(() => {
        if (urlDate) setDateFilter(urlDate);
        if (urlSource) setSourceFilter(urlSource);
    }, [urlDate, urlSource]);

    // Fetch telemetry dates for the Date filter dropdown
    useEffect(() => {
        getTelemetrySessions()
            .then(res => {
                if (res?.dates && Array.isArray(res.dates)) {
                    setAvailableDates(res.dates);
                }
            })
            .catch(() => {});
    }, []);

    const fetchDocs = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await getVexDocuments({
                status: statusFilter === 'ALL' ? undefined : statusFilter.toLowerCase().replace(/ /g, '_'),
                source_type: sourceFilter === 'ALL' ? undefined : sourceFilter,
                date: dateFilter === 'ALL' ? undefined : dateFilter,
            });
            setDocs(data || []);
        } catch (err) {
            console.error(err);
            setError(err.response?.data?.error || 'Failed to load VEX documents.');
        } finally {
            setLoading(false);
        }
    }, [statusFilter, sourceFilter, dateFilter]);

    useEffect(() => {
        fetchDocs();
    }, [fetchDocs]);

    // Combined unique dates from telemetry history + retrieved VEX records
    const allDates = Array.from(new Set([
        ...availableDates,
        ...docs.map(d => {
            if (d.evidence_summary) {
                const match = d.evidence_summary.match(/Date:\s*(\d{4}-\d{2}-\d{2})/);
                if (match) return match[1];
            }
            if (d.job_id && d.job_id.startsWith('job-rt-')) {
                const raw = d.job_id.replace('job-rt-', '');
                if (raw.length === 8) return `${raw.slice(0, 4)}-${raw.slice(4, 6)}-${raw.slice(6, 8)}`;
            }
            return (d.generated_at || '').slice(0, 10);
        }).filter(Boolean)
    ])).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort().reverse();

    // Client-side filtering double check
    const filteredDocs = docs.filter(doc => {
        if (sourceFilter !== 'ALL') {
            if (sourceFilter === 'live_telemetry' && doc.source_type !== 'live_telemetry') return false;
            if (sourceFilter === 'uploaded' && doc.source_type !== 'uploaded') return false;
        }
        if (dateFilter !== 'ALL') {
            const docGenDate = (doc.generated_at || '').slice(0, 10);
            const inEvidence = doc.evidence_summary && doc.evidence_summary.includes(dateFilter);
            const inJob = doc.job_id && doc.job_id.includes(dateFilter.replace(/-/g, ''));
            const inVexId = doc.vex_id && doc.vex_id.includes(dateFilter.replace(/-/g, ''));
            if (dateFilter !== 'today' && dateFilter !== 'yesterday') {
                if (docGenDate !== dateFilter && !inEvidence && !inJob && !inVexId) return false;
            }
        }
        return true;
    });

    const totalDocs = filteredDocs.length;
    const validSigs = filteredDocs.filter(d => d.signature_valid).length;
    const invalidSigs = totalDocs - validSigs;

    const getStatusStyle = (status) => {
        const s = (status || '').toUpperCase();
        if (s === 'UNDER_INVESTIGATION' || s === 'UNDER INVESTIGATION') {
            return { color: '#f8fafc', borderColor: 'rgba(255,255,255,0.1)', bg: 'rgba(255,255,255,0.03)', label: 'INVESTIGATING' };
        }
        if (s === 'NOT_AFFECTED' || s === 'NOT AFFECTED') {
            return { color: '#22c55e', borderColor: 'rgba(34,197,94,0.2)', bg: 'rgba(34,197,94,0.05)', label: 'NOT AFFECTED' };
        }
        if (s === 'AFFECTED') {
            return { color: '#ef4444', borderColor: 'rgba(239,68,68,0.2)', bg: 'rgba(239,68,68,0.05)', label: 'AFFECTED' };
        }
        if (s === 'FIXED') {
            return { color: '#38bdf8', borderColor: 'rgba(56,189,248,0.2)', bg: 'rgba(56,189,248,0.05)', label: 'FIXED' };
        }
        return { color: '#94a3b8', borderColor: 'rgba(255,255,255,0.1)', bg: 'rgba(255,255,255,0.03)', label: (status || 'UNKNOWN').toUpperCase().replace(/_/g, ' ') };
    };

    const formatDateCustom = (isoString) => {
        if (!isoString) return '';
        const d = new Date(isoString);
        return d.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }) + ', ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    };

    return (
        <div>
            {/* Page Header */}
            <div className="page-header">
                <div className="page-header-left">
                    <h1 className="page-header-title">VEX / Compliance</h1>
                    <div className="page-header-meta">
                        <span className="page-header-hud">CYCLONEDX VEX · ECDSA SIGNED</span>
                    </div>
                </div>
                <div className="page-header-actions">
                    <button className="btn btn-ghost btn-sm" onClick={fetchDocs}>
                        <RefreshCw size={13} /> Refresh
                    </button>
                </div>
            </div>

            {/* Error / Alert Box */}
            {error && (
                <div className="alert alert-error mb-6">
                    <AlertTriangle size={14} />
                    {error}
                </div>
            )}

            {invalidSigs > 0 && (
                <div className="alert alert-error mb-6" style={{ alignItems: 'flex-start' }}>
                    <div style={{ marginTop: '2px' }}><AlertOctagon size={16} /></div>
                    <div>
                        <div style={{ fontWeight: '600', marginBottom: '4px', letterSpacing: '0.5px' }}>SIGNATURE VERIFICATION FAILED</div>
                        <div style={{ opacity: 0.9 }}>{invalidSigs} VEX document(s) failed cryptographic signature check. These reports must not be treated as cryptographically verified.</div>
                    </div>
                </div>
            )}

            {/* Stats row */}
            <div className="stat-grid-3 mb-6">
                <div className="stat-card">
                    <div className="stat-card-label">TOTAL DOCUMENTS</div>
                    <div className="stat-card-value">{loading ? '—' : totalDocs}</div>
                    <div className="stat-card-sub">VEX statements generated</div>
                </div>
                <div className="stat-card">
                    <div className="stat-card-label">VALID SIGNATURES</div>
                    <div className="stat-card-value" style={{ color: 'var(--color-verified)' }}>
                        {loading ? '—' : validSigs}
                    </div>
                    <div className="stat-card-sub">ECDSA verified</div>
                </div>
                <div className="stat-card">
                    <div className="stat-card-label">INVALID SIGNATURES</div>
                    <div className="stat-card-value" style={{ color: 'var(--color-critical)' }}>
                        {loading ? '—' : invalidSigs}
                    </div>
                    <div className="stat-card-sub">Review required</div>
                </div>
            </div>

            {/* Filter Bar */}
            <div className="filter-bar mb-6" style={{ flexWrap: 'wrap', gap: 'var(--space-3)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <Filter size={13} style={{ color: 'var(--text-muted)' }} />
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase' }}>FILTER:</span>
                    {['ALL', 'NOT AFFECTED', 'AFFECTED', 'UNDER INVESTIGATION'].map(f => (
                        <button
                            key={f}
                            className={`filter-chip ${statusFilter === f ? 'active' : ''}`}
                            onClick={() => setStatusFilter(f)}
                        >
                            {f}
                        </button>
                    ))}
                </div>

                <div style={{ width: '1px', height: '24px', background: 'var(--border-subtle)', margin: '0 8px' }}></div>

                {/* Source Filter Dropdown (Live Telemetry vs Uploaded Ones) */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase' }}>SOURCE:</span>
                    <select
                        className="select"
                        value={sourceFilter}
                        onChange={e => setSourceFilter(e.target.value)}
                        style={{
                            minWidth: 170,
                            fontSize: 11,
                            fontFamily: 'var(--font-mono)',
                            color: sourceFilter === 'live_telemetry' ? '#c084fc' : '#F5F5F7',
                            backgroundColor: '#0E0E12',
                            colorScheme: 'dark',
                            borderColor: sourceFilter === 'live_telemetry' ? 'rgba(192, 132, 252, 0.4)' : 'rgba(255, 255, 255, 0.1)',
                        }}
                    >
                        <option value="ALL" style={{ backgroundColor: '#0E0E12', color: '#F5F5F7' }}>All Sources</option>
                        <option value="uploaded" style={{ backgroundColor: '#0E0E12', color: '#F5F5F7' }}>Uploaded ones</option>
                        <option value="live_telemetry" style={{ backgroundColor: '#0E0E12', color: '#c084fc' }}>Live Telemetry (ETW)</option>
                    </select>
                </div>

                {/* Date Filter Dropdown */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <Calendar size={13} style={{ color: dateFilter !== 'ALL' ? '#38BDF8' : 'var(--text-muted)' }} />
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: dateFilter !== 'ALL' ? '#38BDF8' : 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase' }}>DATE:</span>
                    <select
                        className="select"
                        value={dateFilter}
                        onChange={e => setDateFilter(e.target.value)}
                        style={{
                            minWidth: 160,
                            fontSize: 11,
                            fontFamily: 'var(--font-mono)',
                            color: dateFilter !== 'ALL' ? '#38BDF8' : '#F5F5F7',
                            borderColor: dateFilter !== 'ALL' ? 'rgba(56, 189, 248, 0.4)' : 'rgba(255, 255, 255, 0.1)',
                            backgroundColor: '#0E0E12',
                            colorScheme: 'dark',
                        }}
                    >
                        <option value="ALL" style={{ backgroundColor: '#0E0E12', color: '#F5F5F7' }}>All Dates</option>
                        <option value="today" style={{ backgroundColor: '#0E0E12', color: '#F5F5F7' }}>Today</option>
                        <option value="yesterday" style={{ backgroundColor: '#0E0E12', color: '#F5F5F7' }}>Yesterday</option>
                        {allDates
                            .filter(d => d !== 'today' && d !== 'yesterday')
                            .map(d => (
                                <option
                                    key={d}
                                    value={d}
                                    style={{
                                        backgroundColor: '#0E0E12',
                                        color: '#F5F5F7',
                                    }}
                                >
                                    {d}
                                </option>
                            ))}
                    </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginLeft: 'auto' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1 }}>
                        {totalDocs} DOCUMENTS
                    </span>
                </div>
            </div>

            {/* Table Card */}
            <div className="card">
                {loading ? (
                    <div style={{ padding: 'var(--space-6)', textAlign: 'center', color: 'var(--text-muted)' }}>
                        Loading VEX documents...
                    </div>
                ) : filteredDocs.length === 0 ? (
                    <div style={{ padding: 'var(--space-6)', textAlign: 'center', color: 'var(--text-muted)' }}>
                        No VEX documents found for the selected filter.
                    </div>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr>
                                    <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>VEX ID</th>
                                    <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>CVE ID</th>
                                    <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>JOB / SOURCE</th>
                                    <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>STATUS</th>
                                    <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>JUSTIFICATION</th>
                                    <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>SIGNATURE</th>
                                    <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>GENERATED</th>
                                    <th style={{ padding: '12px 16px', textAlign: 'right', fontSize: '11px', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>DOWNLOAD PDF</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredDocs.map((doc, idx) => {
                                    const styleInfo = getStatusStyle(doc.status);
                                    
                                    const formattedDate = formatDateCustom(doc.generated_at);
                                    const isInvalidSig = doc.signature_valid === false && doc.signature;
                                    const isLiveETW = doc.source_type === 'live_telemetry';

                                    return (
                                        <tr key={doc.vex_id || idx}>
                                             <td style={{ padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#94a3b8', fontSize: '12px', fontFamily: 'monospace' }}>
                                                {doc.vex_id?.slice(0, 16)}…
                                            </td>
                                            <td style={{ padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#f8fafc', fontSize: '13px', fontWeight: 600, fontFamily: 'monospace' }}>
                                                {doc.cve_id}
                                            </td>
                                            <td style={{ padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                                    <span style={{ padding: '4px 8px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.03)', color: '#94a3b8', fontSize: '12px', fontFamily: 'monospace' }}>
                                                        {formatJobId(doc.job_id)}
                                                    </span>
                                                    <span style={{
                                                        fontSize: '10px',
                                                        fontFamily: 'var(--font-mono)',
                                                        padding: '2px 6px',
                                                        borderRadius: '4px',
                                                        fontWeight: 600,
                                                        border: isLiveETW ? '1px solid rgba(168, 85, 247, 0.4)' : '1px solid rgba(34, 197, 94, 0.3)',
                                                        background: isLiveETW ? 'rgba(168, 85, 247, 0.1)' : 'rgba(34, 197, 94, 0.05)',
                                                        color: isLiveETW ? '#c084fc' : '#22c55e',
                                                        display: 'inline-flex',
                                                        alignItems: 'center',
                                                        gap: '3px',
                                                    }}>
                                                        {isLiveETW ? <Activity size={10} /> : <FileText size={10} />}
                                                        {isLiveETW ? 'LIVE ETW' : 'UPLOADED'}
                                                    </span>
                                                </div>
                                            </td>
                                            <td style={{ padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                                <span style={{ padding: '4px 8px', borderRadius: '4px', border: `1px solid ${styleInfo.borderColor}`, background: styleInfo.bg, color: styleInfo.color, fontSize: '11px', fontWeight: 600, letterSpacing: '0.05em' }}>
                                                    {styleInfo.label}
                                                </span>
                                            </td>
                                            <td style={{ padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#94a3b8', fontSize: '13px' }}>
                                                {doc.justification}
                                            </td>
                                            <td style={{ padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                                {doc.signature_valid ? (
                                                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#22c55e', fontSize: '10px', fontFamily: 'monospace', border: '1px solid rgba(34, 197, 94, 0.3)', background: 'rgba(34, 197, 94, 0.05)', padding: '4px 8px', borderRadius: '4px' }}>
                                                        <ShieldCheck size={12} /> ECDSA VALID
                                                    </span>
                                                ) : isInvalidSig ? (
                                                    <span style={{ display: 'inline-flex', alignItems: 'flex-start', gap: '4px', color: '#ef4444', fontSize: '10px', fontFamily: 'monospace', border: '1px solid rgba(239, 68, 68, 0.3)', background: 'rgba(239, 68, 68, 0.05)', padding: '4px 8px', borderRadius: '4px', lineHeight: 1.2 }}>
                                                        <AlertOctagon size={12} style={{ flexShrink: 0, marginTop: '1px' }} /> 
                                                        <span>SIGNATURE VERIFICATION<br/>FAILED</span>
                                                    </span>
                                                ) : (
                                                    <span style={{ color: '#94a3b8', fontSize: '11px' }}>UNSIGNED</span>
                                                )}
                                            </td>
                                            <td style={{ padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#94a3b8', fontSize: '12px', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                                                {formattedDate}
                                            </td>
                                            <td style={{ padding: '14px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', textAlign: 'right' }}>
                                                <button
                                                    onClick={() => downloadVexDocument(doc.vex_id)}
                                                    style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#38bdf8', fontSize: '12px', fontWeight: 600, background: 'rgba(56,189,248,0.08)', border: '1px solid rgba(56,189,248,0.25)', padding: '4px 10px', borderRadius: '4px', cursor: 'pointer' }}
                                                    title={`Download signed VEX PDF compliance report for ${isLiveETW ? 'Live ETW Telemetry' : 'Uploaded SBOM'}`}
                                                >
                                                    <Download size={13} /> PDF
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ComplianceView;
