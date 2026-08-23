import React, { useState, useEffect, useRef, useCallback } from 'react';
import { RefreshCw, Terminal, Search, Play } from 'lucide-react';

const RuntimeEvidenceView = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [autoScroll, setAutoScroll] = useState(true);
    const [filter, setFilter] = useState('ALL'); // 'ALL' | 'LOADED' | 'SUPPRESSED' | 'CVE'
    const [searchQuery, setSearchQuery] = useState('');
    const consoleEndRef = useRef(null);

    const loadTelemetry = useCallback(() => {
        fetch('http://localhost:5000/api/telemetry')
            .then(res => res.json())
            .then(data => {
                setLogs(data);
                setLoading(false);
            })
            .catch(err => {
                console.error("Error fetching telemetry:", err);
                setLoading(false);
            });
    }, []);

    const fetchLogs = useCallback(() => {
        setLoading(true);
        loadTelemetry();
    }, [loadTelemetry]);

    useEffect(() => {
        loadTelemetry();
        
        // Setup polling every 4 seconds to simulate active Windows Kernel ETW traces
        const timer = setInterval(() => {
            fetch('http://localhost:5000/api/telemetry')
                .then(res => res.json())
                .then(data => {
                    const now = new Date();
                    const updated = data.map((log, idx) => {
                        const time = new Date(now.getTime() - idx * 2000);
                        return {
                            ...log,
                            timestamp: time.toISOString().replace('T', ' ').substring(0, 19)
                        };
                    });
                    setLogs(prev => {
                        const combined = [...updated, ...prev].slice(0, 50);
                        return combined.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
                    });
                })
                .catch(err => console.error(err));
        }, 4000);

        const handleAgentChanged = () => {
            fetchLogs();
        };
        window.addEventListener('zenix_agent_state_changed', handleAgentChanged);

        return () => {
            clearInterval(timer);
            window.removeEventListener('zenix_agent_state_changed', handleAgentChanged);
        };
    }, [loadTelemetry, fetchLogs]);

    useEffect(() => {
        if (autoScroll && consoleEndRef.current) {
            consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs, autoScroll]);

    // Filters and search logic
    const filteredLogs = logs.filter(log => {
        const matchesFilter = 
            filter === 'ALL' ||
            (filter === 'LOADED' && log.status === 'LOADED') ||
            (filter === 'SUPPRESSED' && log.action.includes('SUPPRESSED')) ||
            (filter === 'CVE' && log.cve !== null);

        const matchesSearch = 
            searchQuery === '' ||
            log.process.toLowerCase().includes(searchQuery.toLowerCase()) ||
            log.image_path.toLowerCase().includes(searchQuery.toLowerCase()) ||
            (log.cve && log.cve.toLowerCase().includes(searchQuery.toLowerCase()));

        return matchesFilter && matchesSearch;
    });

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '16px', overflow: 'hidden', color: '#F5F5F5' }}>
            
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0 }}>
                <div>
                    <h2 style={{ fontSize: '24px', fontWeight: '600', color: '#F5F5F5', margin: 0, letterSpacing: '-0.5px' }}>
                        Runtime Evidence Visualizer
                    </h2>
                    <p style={{ fontSize: '13px', color: '#A1A1AA', margin: '4px 0 0 0' }}>
                        Live stream of image-load events captured via the Windows Kernel-Process ETW agent.
                    </p>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                        <Search size={14} style={{ position: 'absolute', left: '12px', color: '#71717A' }} />
                        <input 
                            type="text" 
                            placeholder="Filter by process, path, CVE..." 
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            style={{ background: '#1E1F23', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', padding: '8px 12px 8px 32px', fontSize: '12px', color: '#F5F5F5', outline: 'none', width: '220px' }}
                        />
                    </div>
                    <button 
                        onClick={fetchLogs}
                        style={{ background: '#DAFC6F', border: 'none', color: '#050807', padding: '8px 14px', borderRadius: '14px', fontSize: '12px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: '600' }}
                    >
                        <RefreshCw size={13} className={loading ? "spin" : ""} /> Refresh
                    </button>
                </div>
            </div>

            {/* Objective Details Banner */}
            <div style={{ background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)', backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', border: '1px solid rgba(255, 255, 255, 0.08)', boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)', borderRadius: '14px', padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ background: 'rgba(218, 252, 111, 0.1)', color: '#DAFC6F', width: '28px', height: '28px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <Terminal size={14} />
                    </div>
                    <div>
                        <div style={{ fontSize: '13px', color: '#F5F5F5', fontWeight: '600' }}>Microsoft-Windows-Kernel-Process Agent</div>
                        <div style={{ fontSize: '11px', color: '#A1A1AA', marginTop: '2px' }}>Subscribed to ImageLoad telemetry streams. Validating loaded SBOM nodes dynamically.</div>
                    </div>
                </div>

                {/* Filter Swappable Tabs */}
                <div style={{ display: 'flex', background: 'rgba(255, 255, 255, 0.02)', padding: '2px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                    {['ALL', 'LOADED', 'SUPPRESSED', 'CVE'].map(f => (
                        <button
                            key={f}
                            onClick={() => setFilter(f)}
                            style={{
                                background: filter === f ? 'rgba(218, 252, 111, 0.1)' : 'transparent',
                                border: 'none',
                                color: filter === f ? '#DAFC6F' : '#A1A1AA',
                                padding: '4px 12px',
                                borderRadius: '6px',
                                fontSize: '11px',
                                fontWeight: '500',
                                cursor: 'pointer',
                                transition: 'all 0.15s ease'
                            }}
                        >
                            {f}
                        </button>
                    ))}
                </div>
            </div>

            {/* Terminal Stream Console */}
            <div style={{ 
                flex: 1, 
                background: 'linear-gradient(135deg, rgba(16, 18, 17, 0.85) 0%, rgba(10, 12, 11, 0.75) 100%)', 
                backdropFilter: 'blur(16px)',
                WebkitBackdropFilter: 'blur(16px)',
                border: '1px solid rgba(255, 255, 255, 0.08)', 
                boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.4)',
                borderRadius: '18px', 
                padding: '24px', 
                display: 'flex', 
                flexDirection: 'column', 
                fontFamily: 'monospace',
                fontSize: '12px',
                overflow: 'hidden'
            }}>
                {/* Console Header Bar */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '12px', marginBottom: '16px', flexShrink: 0 }}>
                    <div style={{ display: 'flex', gap: '6px' }}>
                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#EF4444' }}></div>
                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#F59E0B' }}></div>
                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22C55E' }}></div>
                    </div>
                    <span style={{ color: '#71717A', fontSize: '11px', fontWeight: '500' }}>ETW Kernel Stream Monitor</span>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#A1A1AA', fontSize: '11px', cursor: 'pointer' }}>
                        <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} style={{ cursor: 'pointer' }} />
                        Autoscroll
                    </label>
                </div>

                {/* Telemetry rows scrollable container */}
                <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px', paddingRight: '8px' }}>
                    {filteredLogs.length === 0 ? (
                        <div style={{ margin: 'auto', color: '#71717A', fontSize: '12px' }}>
                            No matching image load traces found.
                        </div>
                    ) : (
                        filteredLogs.map((log, idx) => {
                            const isAlert = log.action.includes('ALERT');
                            const isSuppressed = log.action.includes('SUPPRESSED');
                            
                            return (
                                <div 
                                    key={idx} 
                                    style={{ 
                                        display: 'flex', 
                                        gap: '16px', 
                                        padding: '6px 12px', 
                                        borderRadius: '6px', 
                                        background: isAlert ? 'rgba(239, 68, 68, 0.04)' : 'transparent',
                                        border: `1px solid ${isAlert ? 'rgba(239, 68, 68, 0.1)' : 'transparent'}`,
                                        alignItems: 'center',
                                        fontSize: '11.5px',
                                        lineHeight: '1.4'
                                    }}
                                >
                                    <span style={{ color: '#71717A', width: '130px', flexShrink: 0 }}>[{log.timestamp}]</span>
                                    <span style={{ color: '#3B82F6', width: '60px', flexShrink: 0 }}>PID {log.pid}</span>
                                    <span style={{ color: '#F5F5F5', width: '100px', flexShrink: 0, fontWeight: '600' }}>{log.process}</span>
                                    <span style={{ color: '#71717A', flex: 1, wordBreak: 'break-all' }}>{log.image_path}</span>
                                    
                                    {log.cve && (
                                        <span style={{ color: '#EF4444', fontWeight: '700', width: '110px', flexShrink: 0 }}>{log.cve}</span>
                                    )}

                                    <span style={{ 
                                        color: isAlert ? '#EF4444' : isSuppressed ? '#22C55E' : '#71717A',
                                        fontWeight: '600',
                                        width: '130px',
                                        textAlign: 'right',
                                        flexShrink: 0
                                    }}>
                                        {log.action}
                                    </span>
                                </div>
                            );
                        })
                    )}
                    <div ref={consoleEndRef} />
                </div>
            </div>
            
        </div>
    );
};

export default RuntimeEvidenceView;
