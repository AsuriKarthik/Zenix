import React, { useState, useEffect } from 'react';
import StatsRow from './StatsRow';
import { Shield, ShieldAlert, ShieldCheck, Lock, Unlock, RotateCcw } from 'lucide-react';

const OverviewView = ({ findings, setFindings }) => {
    const [selectedCveId, setSelectedCveId] = useState('CVE-2021-44228');
    const [activeRightTab, setActiveRightTab] = useState('lifecycle');
    const [analysisStatus, setAnalysisStatus] = useState('idle'); // 'idle' | 'running' | 'completed'
    const [reportStatus, setReportStatus] = useState('idle'); // 'idle' | 'generating' | 'generated'

    // State for individual service isolation gates per CVE
    const [cveIsolatedNodes, setCveIsolatedNodes] = useState({
        'CVE-2021-44228': { api_gw: false, auth_svc: false, customer_db: false, analytics: false, cache_svr: true, search_idx: true },
        'CVE-2023-4863': { api_gw: false, auth_svc: false, customer_db: false, analytics: false, cache_svr: false, search_idx: false },
        'CVE-2023-44487': { api_gw: false, auth_svc: false, customer_db: false, analytics: false, cache_svr: false, search_idx: false },
        'CVE-2023-38545': { api_gw: false, auth_svc: false, customer_db: false, analytics: false, cache_svr: false, search_idx: false },
        'CVE-2023-38408': { api_gw: true, auth_svc: true, customer_db: true, analytics: true, cache_svr: true, search_idx: true }
    });

    const [hoveredNode, setHoveredNode] = useState(null);
    const [showAssignModal, setShowAssignModal] = useState(false);

    // List of CVEs available for focus
    const cves = [
        { id: 'CVE-2021-44228', name: 'CVE-2021-44228 (Log4Shell)', severity: 'Critical', color: '#fa4516' },
        { id: 'CVE-2023-4863', name: 'CVE-2023-4863 (libwebp heap buffer)', severity: 'High', color: '#fa4516' },
        { id: 'CVE-2023-44487', name: 'CVE-2023-44487 (HTTP/2 Rapid Reset)', severity: 'High', color: '#fa4516' },
        { id: 'CVE-2023-38545', name: 'CVE-2023-38545 (curl SOCKS5 overflow)', severity: 'Medium', color: '#eab308' },
        { id: 'CVE-2023-38408', name: 'CVE-2023-38408 (OpenSSH struct vuln)', severity: 'High', color: '#fa4516' }
    ];

    const [nodes, setNodes] = useState([
        { id: 'api_gw', name: 'API Gateway', role: 'Ingress Router', criticality: 'Critical', cx: 375, cy: 175, textAnchor: 'start' },
        { id: 'auth_svc', name: 'Auth Service', role: 'Identity Provider', criticality: 'Critical', cx: 310, cy: 265, textAnchor: 'start' },
        { id: 'customer_db', name: 'Customer DB', role: 'Database', criticality: 'Critical', cx: 190, cy: 265, textAnchor: 'end' },
        { id: 'analytics', name: 'Analytics Hub', role: 'BI Engine', criticality: 'Low', cx: 125, cy: 175, textAnchor: 'end' },
        { id: 'cache_svr', name: 'Cache Server', role: 'Redis Cache', criticality: 'Medium', cx: 190, cy: 85, textAnchor: 'end' },
        { id: 'search_idx', name: 'Search Index', role: 'Elasticsearch', criticality: 'Medium', cx: 310, cy: 85, textAnchor: 'start' },
    ]);

    const [cveTargets, setCveTargets] = useState({
        'CVE-2021-44228': { node_id: 'auth_svc', name: 'Auth Service', pid: 4824 },
        'CVE-2023-4863': { node_id: 'api_gw', name: 'API Gateway', pid: 9128 },
        'CVE-2023-44487': { node_id: 'search_idx', name: 'Search Index', pid: 1102 },
        'CVE-2023-38545': { node_id: 'customer_db', name: 'Customer DB', pid: 5844 },
        'CVE-2023-38408': { node_id: 'cache_svr', name: 'Cache Server', pid: 7724 }
    });

    const [activeThreatsList, setActiveThreatsList] = useState([]);
    const [authorized, setAuthorized] = useState(false);

    const fetchNodes = () => {
        fetch('http://localhost:5000/api/nodes')
            .then(res => res.json())
            .then(data => {
                if (data.nodes && data.cve_targets) {
                    setNodes(data.nodes);
                    setCveTargets(data.cve_targets);
                    setActiveThreatsList(data.active_threats || []);
                    setAuthorized(data.authorized || false);
                }
            })
            .catch(err => console.error("Error fetching dynamic nodes:", err));
    };


    useEffect(() => {
        fetchNodes();
        window.addEventListener('zenix_agent_state_changed', fetchNodes);
        return () => window.removeEventListener('zenix_agent_state_changed', fetchNodes);
    }, []);



    // Analyst mapping details consistent with Kanban Board
    const analysts = [
        { init: 'NM', name: 'Nandini Mahesh', role: 'Threat Analyst', color: '#eab308', title: 'Security Lead' },
        { init: 'MV', name: 'Monisha Varma', role: 'Compliance Officer', color: '#22c55e', title: 'Compliance' },
        { init: 'KK', name: 'Kushal Kumar', role: 'Security Engineer', color: '#eab308', title: 'SecOps' },
        { init: 'DK', name: 'Divyansha Kaushik', role: 'Incident Responder', color: '#ef4444', title: 'IR Specialist' },
        { init: 'AR', name: 'Arjun Reddy', role: 'DevOps Security', color: '#3b82f6', title: 'DevSecOps' }
    ];

    // Derive isolation states based on active CVE
    const isolatedNodes = cveIsolatedNodes[selectedCveId] || { api_gw: false, auth_svc: false, customer_db: false, analytics: false, cache_svr: false, search_idx: false };

    // Fetch isolation state from backend for selectedCveId on change
    useEffect(() => {
        fetch(`http://localhost:5000/api/findings/get-isolation?cve_id=${selectedCveId}`)
            .then(res => res.json())
            .then(data => {
                setCveIsolatedNodes(prev => ({
                    ...prev,
                    [selectedCveId]: data
                }));
            })
            .catch(err => console.error("Error fetching isolation:", err));
    }, [selectedCveId]);

    const syncIsolation = (cveId, state) => {
        fetch('http://localhost:5000/api/findings/isolate-batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cve_id: cveId, state })
        })
        .then(() => {
            // Re-fetch findings in parent to update risk scores
            fetch('http://localhost:5000/api/findings')
                .then(res => res.json())
                .then(data => setFindings(data));
        })
        .catch(err => console.error("Error syncing isolation:", err));
    };

    const toggleNode = (id) => {
        const nextState = {
            ...isolatedNodes,
            [id]: !isolatedNodes[id]
        };
        setCveIsolatedNodes(prev => ({
            ...prev,
            [selectedCveId]: nextState
        }));
        syncIsolation(selectedCveId, nextState);
    };

    const setIsolatedNodes = (newVal) => {
        let nextState;
        if (typeof newVal === 'function') {
            nextState = newVal(isolatedNodes);
        } else {
            nextState = newVal;
        }
        setCveIsolatedNodes(prev => ({
            ...prev,
            [selectedCveId]: nextState
        }));
        syncIsolation(selectedCveId, nextState);
    };

    // Compute assignee and current column dynamically from findings prop in React memory for the selected CVE
    let assignee = null;
    let selectedCveColumn = '';
    if (findings) {
        Object.entries(findings).forEach(([colId, col]) => {
            const found = col.items.find(item => item.id === selectedCveId);
            if (found) {
                assignee = found.init;
                selectedCveColumn = colId;
            }
        });
    }

    // Determine if the selected CVE is in findings 'resolved' column
    const isResolvedColumn = selectedCveColumn === 'resolved';
    const effectiveAnalysisStatus = isResolvedColumn ? 'completed' : analysisStatus;
    const effectiveReportStatus = isResolvedColumn ? 'generated' : reportStatus;

    // Escalate to findings board and assign selected analyst
    const handleAssign = (analyst) => {
        let updated = false;
        const nextCols = { ...findings };

        // Scan all columns for the active card and update assignee
        Object.keys(nextCols).forEach(colId => {
            nextCols[colId] = {
                ...nextCols[colId],
                items: nextCols[colId].items.map(item => {
                    if (item.id === selectedCveId) {
                        updated = true;
                        return {
                            ...item,
                            init: analyst.init,
                            initBg: analyst.color
                        };
                    }
                    return item;
                })
            };
        });

        // Add back if missing
        if (!updated) {
            const nameMap = {
                'CVE-2021-44228': { subtitle: 'Log4Shell • log4j-core', badge: 'CRIT', badgeColor: '#ef4444', dot: '#ef4444' },
                'CVE-2023-4863': { subtitle: 'libwebp heap buffer', badge: 'HIGH', badgeColor: '#fa4516', dot: '#fa4516' },
                'CVE-2023-44487': { subtitle: 'HTTP/2 Rapid Reset', badge: 'HIGH', badgeColor: '#fa4516', dot: '#fa4516' },
                'CVE-2023-38545': { subtitle: 'curl SOCKS5 overflow', badge: 'MED', badgeColor: '#eab308', dot: '#eab308' },
                'CVE-2023-38408': { subtitle: 'OpenSSH struct vuln', badge: 'HIGH', badgeColor: '#fa4516', dot: '#fa4516' }
            };
            const info = nameMap[selectedCveId] || nameMap['CVE-2021-44228'];

            nextCols['triaged'].items.push({
                id: selectedCveId,
                subtitle: info.subtitle,
                date: '2025-11-20',
                init: analyst.init,
                initBg: analyst.color,
                hasImg: selectedCveId === 'CVE-2021-44228',
                dot: info.dot,
                badge: info.badge,
                badgeColor: info.badgeColor
            });
            nextCols['triaged'].count = nextCols['triaged'].items.length;
        }

        setFindings(nextCols);
        setShowAssignModal(false);
    };

    // Auto-move card to 'resolved' when report attestation completes
    const handleMoveToResolved = () => {
        const nextCols = { ...findings };
        let cardToMove = null;

        Object.keys(nextCols).forEach(colId => {
            const index = nextCols[colId].items.findIndex(item => item.id === selectedCveId);
            if (index !== -1) {
                [cardToMove] = nextCols[colId].items.splice(index, 1);
                nextCols[colId].count = nextCols[colId].items.length;
            }
        });

        if (cardToMove) {
            cardToMove.badge = 'VEX Signed';
            cardToMove.badgeColor = '#3b82f6';
            nextCols['resolved'].items.push(cardToMove);
            nextCols['resolved'].count = nextCols['resolved'].items.length;
            setFindings(nextCols);
        }
    };

    // Quick Action Functions matching dashboard colors
    const isolateAll = () => {
        setIsolatedNodes({
            api_gw: true,
            auth_svc: true,
            customer_db: true,
            analytics: true,
            cache_svr: true,
            search_idx: true,
        });
    };

    const exposeAll = () => {
        setIsolatedNodes({
            api_gw: false,
            auth_svc: false,
            customer_db: false,
            analytics: false,
            cache_svr: false,
            search_idx: false,
        });
    };

    const resetGates = () => {
        setIsolatedNodes({
            api_gw: false,
            auth_svc: false,
            customer_db: false,
            analytics: false,
            cache_svr: true,
            search_idx: true,
        });
    };

    // Computations
    const totalNodes = nodes.length;
    const isolatedCount = Object.values(isolatedNodes).filter(Boolean).length;

    const criticalExposed = nodes.some(n => n.criticality === 'Critical' && !isolatedNodes[n.id]);
    const anyExposed = Object.values(isolatedNodes).some(v => !v);

    // Color Palette matching the Zenix stats row widgets
    const greenMatch = '#37b250'; // Zenix stats green
    const redMatch = '#fa4516';   // Zenix stats red/orange
    const amberMatch = '#f59e0b'; // Zenix stats amber

    const activeCveObj = cves.find(c => c.id === selectedCveId) || cves[0];
    const activeCveColor = activeCveObj.color;

    const isCveActiveOnHost = !authorized || activeThreatsList.includes(selectedCveId);
    const containmentPercentage = !isCveActiveOnHost ? 100 : Math.round((isolatedCount / totalNodes) * 100);

    let statusText = '';
    let statusColor = '';
    let statusBg = '';
    let statusIcon = null;
    let narrative = '';

    if (!isCveActiveOnHost) {
        statusText = 'SYSTEM SECURE';
        statusColor = greenMatch;
        statusBg = 'rgba(55, 178, 80, 0.05)';
        statusIcon = <ShieldCheck size={18} style={{ color: greenMatch }} />;
        narrative = `The host is fully secure. No active threat signature for ${selectedCveId} was found in the running processes or memory maps. Continuous ETW monitoring is active.`;
    } else if (!anyExposed) {
        statusText = 'FULLY SECURED';
        statusColor = greenMatch;
        statusBg = 'rgba(55, 178, 80, 0.04)';
        statusIcon = <ShieldCheck size={18} style={{ color: greenMatch }} />;
        narrative = `All isolation gates are active. The threat ${selectedCveId} is completely quarantined within the isolated core. Horizontal escalation is mitigated, protecting all production workloads.`;
    } else if (criticalExposed) {
        statusText = 'CRITICAL PROPAGATION RISK';
        statusColor = redMatch;
        statusBg = 'rgba(250, 69, 22, 0.04)';
        statusIcon = <ShieldAlert size={18} style={{ color: redMatch }} />;
        narrative = `Active lateral pathways detected. One or more critical systems (API Gateway, Auth Service, Customer DB) are exposed to the compromised core, posing a severe risk of horizontal escalation for ${selectedCveId}.`;
    } else {
        statusText = 'PARTIALLY CONTAINED';
        statusColor = amberMatch;
        statusBg = 'rgba(245, 158, 11, 0.04)';
        statusIcon = <Shield size={18} style={{ color: amberMatch }} />;
        narrative = `Core threat ${selectedCveId} is partially contained. High-priority transaction databases and access servers are isolated, though peripheral search clusters and cache nodes remain exposed.`;
    }

    const selectedAnalystObj = analysts.find(a => a.init === assignee);
    const assigneeName = selectedAnalystObj ? selectedAnalystObj.name : 'Unassigned';

    // Auto reset interactive flow steps if prerequisites are cleared
    useEffect(() => {
        if (selectedCveColumn !== 'resolved' && (!assignee || isolatedCount < 3)) {
            setAnalysisStatus('idle');
            setReportStatus('idle');
        }
    }, [assignee, isolatedCount, selectedCveColumn]);

    const glassStyle = {
        background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)',
        transition: 'all 0.25s ease'
    };


    // Render helper for incident lifecycle stepper
    const renderLifecycleStep = (num, title, status, statusColor, desc, actionElement, isCompleted, isActive) => {
        return (
            <div style={{ display: 'flex', gap: '12px', position: 'relative', marginBottom: '14px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <div style={{ 
                        width: '20px', 
                        height: '20px', 
                        borderRadius: '50%', 
                        background: isCompleted ? 'rgba(55, 178, 80, 0.12)' : isActive ? 'rgba(59, 130, 246, 0.12)' : 'rgba(255, 255, 255, 0.01)', 
                        border: `1.2px solid ${isCompleted ? greenMatch : isActive ? '#3b82f6' : 'rgba(255, 255, 255, 0.08)'}`,
                        display: 'flex', 
                        alignItems: 'center', 
                        justifyContent: 'center',
                        fontSize: '9.5px',
                        fontWeight: 'bold',
                        color: isCompleted ? greenMatch : isActive ? '#3b82f6' : '#78716c',
                        boxShadow: isCompleted ? '0 0 8px rgba(55, 178, 80, 0.15)' : isActive ? '0 0 8px rgba(59, 130, 246, 0.15)' : 'none',
                        zIndex: 1,
                        transition: 'all 0.3s'
                    }}>
                        {isCompleted ? '✓' : num}
                    </div>
                    {num !== 5 && (
                        <div style={{ 
                            width: '1px', 
                            flex: 1, 
                            background: isCompleted ? greenMatch : 'rgba(255, 255, 255, 0.04)', 
                            marginTop: '4px', 
                            marginBottom: '-4px',
                            transition: 'background 0.3s'
                        }}></div>
                    )}
                </div>
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '2px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '12px', fontWeight: '600', color: isCompleted || isActive ? '#ffffff' : '#78716c' }}>
                            {title}
                        </span>
                        <span style={{ 
                            fontSize: '8.5px', 
                            fontWeight: 'bold', 
                            color: statusColor, 
                            background: `${statusColor}08`, 
                            padding: '1px 5px', 
                            borderRadius: '3px',
                            border: `1.2px solid ${statusColor}15` 
                        }}>
                            {status}
                        </span>
                    </div>
                    <p style={{ fontSize: '10.5px', color: '#78716c', margin: 0, lineHeight: '1.3' }}>
                        {desc}
                    </p>
                    {actionElement && (
                        <div style={{ marginTop: '6px' }}>
                            {actionElement}
                        </div>
                    )}
                </div>
            </div>
        );
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '16px', overflowY: 'auto', paddingRight: '8px' }}>
            <StatsRow />
            <div style={{ display: 'flex', gap: '16px', flex: 1, minHeight: '620px', position: 'relative' }}>
                {/* BLAST RADIUS CARD */}
                <div style={{ ...glassStyle, flex: '2.2', display: 'flex', flexDirection: 'column', borderRadius: '16px', padding: '24px 32px 32px 32px', position: 'relative' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div style={{ width: '8px', height: '8px', background: isCveActiveOnHost ? activeCveColor : greenMatch, borderRadius: '50%', boxShadow: `0 0 8px ${isCveActiveOnHost ? activeCveColor : greenMatch}` }}></div>
                            <h3 style={{ fontSize: '16px', color: '#e7e5e4', fontWeight: '500', margin: 0 }}>Blast Radius Summary</h3>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <button 
                                onClick={isolateAll} 
                                style={{ background: '#DAFC6F', border: 'none', color: '#050807', fontSize: '11px', padding: '6px 12px', borderRadius: '14px', cursor: 'pointer', transition: 'all 0.15s ease', fontWeight: '600' }}
                                onMouseOver={(e) => e.currentTarget.style.background = '#E6FF85'}
                                onMouseOut={(e) => e.currentTarget.style.background = '#DAFC6F'}
                            >
                                Isolate All
                            </button>
                            <button 
                                onClick={exposeAll} 
                                style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', color: '#EF4444', fontSize: '11px', padding: '6px 12px', borderRadius: '14px', cursor: 'pointer', transition: 'all 0.15s ease', fontWeight: '600' }}
                                onMouseOver={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)'}
                                onMouseOut={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'}
                            >
                                Expose All
                            </button>
                            <button 
                                onClick={resetGates} 
                                style={{ background: 'transparent', border: '1px solid rgba(255, 255, 255, 0.08)', color: '#A1A1AA', fontSize: '11px', padding: '6px 12px', borderRadius: '14px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', transition: 'all 0.15s ease' }}
                                onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)'}
                                onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}
                            >
                                <RotateCcw size={10} /> Reset
                            </button>
                        </div>
                    </div>

                    {/* TWO-COLUMN LAYOUT */}
                    <div style={{ display: 'flex', gap: '24px', flex: 1, alignItems: 'stretch' }}>
                        {/* LEFT COLUMN: SVG NETWORK BLUEPRINT */}
                        <div style={{ 
                            flex: '1.3', 
                            display: 'flex', 
                            flexDirection: 'column', 
                            justifyContent: 'center', 
                            alignItems: 'center', 
                            background: 'rgba(0, 0, 0, 0.25)', 
                            borderRadius: '12px', 
                            border: '1px solid rgba(255, 255, 255, 0.04)', 
                            position: 'relative', 
                            overflow: 'hidden', 
                            padding: '16px' 
                        }}>
                            <svg 
                                width="100%" 
                                height="100%" 
                                viewBox="0 0 500 350" 
                                style={{ maxHeight: '350px', userSelect: 'none' }}
                            >
                                <defs>
                                    <pattern id="blueprint-grid" width="20" height="20" patternUnits="userSpaceOnUse">
                                        <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(255, 255, 255, 0.012)" strokeWidth="1" />
                                    </pattern>
                                    <radialGradient id="red-radial" cx="50%" cy="50%" r="50%">
                                        <stop offset="0%" stopColor={activeCveColor} stopOpacity="0.25" />
                                        <stop offset="100%" stopColor={activeCveColor} stopOpacity="0" />
                                    </radialGradient>
                                    <radialGradient id="green-radial" cx="50%" cy="50%" r="50%">
                                        <stop offset="0%" stopColor={greenMatch} stopOpacity="0.12" />
                                        <stop offset="100%" stopColor={greenMatch} stopOpacity="0" />
                                    </radialGradient>
                                </defs>

                                {/* Grid Background */}
                                <rect width="100%" height="100%" fill="url(#blueprint-grid)" />

                                {/* Substructure Blueprint circles */}
                                <circle cx="250" cy="175" r="110" fill="none" stroke="rgba(255, 255, 255, 0.02)" strokeWidth="1" strokeDasharray="6 4" />
                                <circle cx="250" cy="175" r="55" fill="none" stroke="rgba(255, 255, 255, 0.01)" strokeWidth="1" />

                                {/* Connection paths (Corridors) */}
                                {nodes.map((node) => {
                                    const isIsolated = isolatedNodes[node.id];
                                    return (
                                        <g key={`path-${node.id}`}>
                                            <line 
                                                x1="250" 
                                                y1="175" 
                                                x2={node.cx} 
                                                y2={node.cy} 
                                                stroke={!isCveActiveOnHost ? "rgba(55, 178, 80, 0.4)" : (isIsolated ? "rgba(55, 178, 80, 0.15)" : "rgba(250, 69, 22, 0.45)")} 
                                                strokeWidth={!isCveActiveOnHost ? "1.5" : (isIsolated ? "1.5" : "2.5")} 
                                                strokeDasharray={isIsolated ? "4 4" : "none"}
                                                style={{ transition: 'stroke 0.3s, stroke-width 0.3s' }}
                                            />
                                            {!isIsolated && isCveActiveOnHost && (
                                                <line 
                                                    x1="250" 
                                                    y1="175" 
                                                    x2={node.cx} 
                                                    y2={node.cy} 
                                                    stroke={activeCveColor} 
                                                    strokeWidth="1.2" 
                                                    opacity="0.8"
                                                />
                                            )}
                                        </g>
                                    );
                                })}

                                {/* Central Compromised Node - Larger Sizing */}
                                <g>
                                    <circle cx="250" cy="175" r="32" fill="#1E1F23" stroke={isCveActiveOnHost ? "#EF4444" : "#22C55E"} strokeWidth="1.5" />
                                    <circle cx="250" cy="175" r="24" fill="#050807" stroke="rgba(255,255,255,0.08)" strokeWidth="1" />
                                    {isCveActiveOnHost ? (
                                        <circle cx="250" cy="175" r="4" fill="#EF4444" />
                                    ) : (
                                        <path d="M 247 175 L 249 177 L 253 173" fill="none" stroke="#22C55E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                    )}
                                    <text x="250" y="222" textAnchor="middle" fill={isCveActiveOnHost ? "#EF4444" : "#22C55E"} fontSize="11" fontWeight="600" letterSpacing="0.5">
                                        {isCveActiveOnHost ? selectedCveId : "SYSTEM SECURE"}
                                    </text>
                                </g>

                                {/* Surrounding Nodes - Larger Sizing (Radius 18) */}
                                {nodes.map((node) => {
                                    const isIsolated = isolatedNodes[node.id];
                                    const isHovered = hoveredNode === node.id;
                                    const isTarget = cveTargets[selectedCveId]?.node_id === node.id;
                                    
                                    // Professional color hierarchy
                                    const color = isIsolated 
                                        ? "#22C55E" 
                                        : (isTarget ? "#EF4444" : "rgba(255,255,255,0.15)");
                                        
                                    const borderStroke = isIsolated 
                                        ? "#22C55E" 
                                        : (isTarget ? "#EF4444" : "rgba(255,255,255,0.08)");

                                    return (
                                        <g 
                                            key={node.id} 
                                            style={{ cursor: 'pointer' }}
                                            onClick={() => toggleNode(node.id)}
                                            onMouseEnter={() => setHoveredNode(node.id)}
                                            onMouseLeave={() => setHoveredNode(null)}
                                        >
                                            {/* Subdued hover circle indicator */}
                                            {isHovered && <circle cx={node.cx} cy={node.cy} r="24" fill="rgba(255, 255, 255, 0.03)" />}

                                            {/* Node boundary circle (r = 18) */}
                                            <circle 
                                                cx={node.cx} 
                                                cy={node.cy} 
                                                r={isHovered ? "20" : "18"} 
                                                fill="#25272B" 
                                                stroke={borderStroke} 
                                                strokeWidth={isTarget || isHovered ? "2.2" : "1.2"} 
                                                style={{ transition: 'all 0.15s ease' }}
                                            />

                                            {/* Security State Label / Icon placeholder inside node */}
                                            <text 
                                                x={node.cx} 
                                                y={node.cy + 3.5} 
                                                textAnchor="middle" 
                                                fill={color} 
                                                fontSize="9.5" 
                                                fontWeight="600"
                                            >
                                                {node.criticality[0]}
                                            </text>

                                            {/* Label Texts */}
                                            <text 
                                                x={node.textAnchor === 'start' ? node.cx + 25 : node.cx - 25} 
                                                y={node.cy - 1} 
                                                textAnchor={node.textAnchor} 
                                                fill={isHovered ? "#ffffff" : "#F5F5F5"} 
                                                fontSize="11.5" 
                                                fontWeight="500"
                                                style={{ transition: 'fill 0.15s ease' }}
                                            >
                                                {node.name}
                                            </text>
                                            <text 
                                                x={node.textAnchor === 'start' ? node.cx + 25 : node.cx - 25} 
                                                y={node.cy + 10} 
                                                textAnchor={node.textAnchor} 
                                                fill={isIsolated ? "#22C55E" : (isTarget ? "#EF4444" : "#71717A")} 
                                                fontSize="9.5"
                                            >
                                                {isIsolated ? "Isolated" : (isTarget ? "Vulnerable" : node.role)}
                                            </text>
                                        </g>
                                    );
                                })}

                                {/* Isolation Gate triggers on the line midpoints */}
                                {nodes.map((node) => {
                                    const isIsolated = isolatedNodes[node.id];
                                    const mx = (250 + node.cx) / 2;
                                    const my = (175 + node.cy) / 2;
                                    const color = !isCveActiveOnHost ? greenMatch : (isIsolated ? greenMatch : activeCveColor);

                                    return (
                                        <g 
                                            key={`gate-${node.id}`} 
                                            style={{ cursor: 'pointer' }}
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                toggleNode(node.id);
                                            }}
                                        >
                                            <rect 
                                                x={mx - 9} 
                                                y={my - 9} 
                                                width="18" 
                                                height="18" 
                                                rx="4" 
                                                fill="#05070f" 
                                                stroke={color} 
                                                strokeWidth="1.2" 
                                                style={{ transition: 'stroke 0.2s' }}
                                            />
                                            {(!isCveActiveOnHost || isIsolated) ? (
                                                <path 
                                                    d={`M ${mx - 3.5} ${my - 1} h 7 v 4.5 h -7 z M ${mx - 2} ${my - 1} v -2 a 2 2 0 0 1 4 0 v 2`} 
                                                    fill="none" 
                                                    stroke={greenMatch} 
                                                    strokeWidth="0.8" 
                                                />
                                            ) : (
                                                <path 
                                                    d={`M ${mx - 3.5} ${my - 1} h 7 v 4.5 h -7 z M ${mx - 2} ${my - 1} v -2.2 a 2 2 0 0 1 3.5 -1.2`} 
                                                    fill="none" 
                                                    stroke={activeCveColor} 
                                                    strokeWidth="0.8" 
                                                />
                                            )}
                                        </g>
                                    );
                                })}
                            </svg>
                        </div>

                        {/* RIGHT COLUMN: STATUS CONSOLE */}
                        <div style={{ flex: '0.8', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '10px' }}>
                            {/* CONTAINMENT PERCENTAGE GAUGE */}
                            <div style={{ background: 'rgba(0, 0, 0, 0.2)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '12px', padding: '14px 18px', display: 'flex', alignItems: 'center', gap: '16px' }}>
                                <div style={{ position: 'relative', width: '50px', height: '50px' }}>
                                    <svg viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                                        <circle cx="18" cy="18" r="16" fill="none" stroke="rgba(255, 255, 255, 0.05)" strokeWidth="3" />
                                        <circle 
                                            cx="18" 
                                            cy="18" 
                                            r="16" 
                                            fill="none" 
                                            stroke={statusColor} 
                                            strokeWidth="3" 
                                            strokeDasharray={`${containmentPercentage}, 100`} 
                                            style={{ transition: 'stroke-dasharray 0.3s, stroke 0.3s' }}
                                        />
                                    </svg>
                                    <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', fontSize: '11px', color: '#ffffff', fontWeight: 'bold' }}>
                                        {containmentPercentage}%
                                    </div>
                                </div>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontSize: '10.5px', color: '#78716c', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Containment Ratio</div>
                                    <div style={{ fontSize: '14.5px', color: '#ffffff', fontWeight: '500' }}>
                                        {!isCveActiveOnHost ? "System Protected" : `${isolatedCount} of ${totalNodes} Isolated`}
                                    </div>
                                </div>
                            </div>

                            {/* CURRENT THREAT STATUS BOX */}
                            <div style={{ background: statusBg, border: `1px solid rgba(${statusColor === redMatch ? '250, 69, 22' : statusColor === amberMatch ? '245, 158, 11' : '55, 178, 80'}, 0.2)`, borderRadius: '12px', padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: '8px', transition: 'all 0.3s' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    {statusIcon}
                                    <span style={{ fontSize: '11.5px', fontWeight: '700', color: statusColor, letterSpacing: '0.5px' }}>{statusText}</span>
                                </div>
                                <p style={{ fontSize: '12px', color: '#a8a29e', margin: 0, lineHeight: '1.5' }}>
                                    {narrative}
                                </p>
                            </div>

                            {/* CORE INCIDENT ESCALATION & ANALYST ASSIGNMENT */}
                            <div style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '12px', padding: '14px 18px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div style={{ fontSize: '11px', color: '#78716c', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: '600' }}>Incident Escalation</div>
                                    <span style={{ fontSize: '9px', color: isCveActiveOnHost ? activeCveColor : greenMatch, background: isCveActiveOnHost ? `${activeCveColor}1A` : 'rgba(55, 178, 80, 0.1)', padding: '2px 6px', borderRadius: '4px', fontWeight: 'bold' }}>{selectedCveId}</span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                                        <span style={{ fontSize: '12.5px', color: '#e7e5e4', fontWeight: '500' }}>
                                            {!isCveActiveOnHost ? 'Host Fully Secure' : (assignee ? `Assigned: ${assigneeName}` : 'Core Breach Escalated')}
                                        </span>
                                        <span style={{ fontSize: '10px', color: '#78716c', marginTop: '1px' }}>
                                            {!isCveActiveOnHost ? 'No mitigation workflow required' : (assignee ? `Status active in Findings Board (${selectedCveColumn})` : 'Unassigned • Backlog inactive')}
                                        </span>
                                    </div>
                                    {isCveActiveOnHost && (
                                        <button 
                                            onClick={() => setShowAssignModal(true)}
                                            style={{ 
                                                background: 'rgba(59, 130, 246, 0.1)', 
                                                border: '1px solid rgba(59, 130, 246, 0.25)', 
                                                color: '#3b82f6', 
                                                fontSize: '11px', 
                                                padding: '5px 12px', 
                                                borderRadius: '6px', 
                                                cursor: 'pointer', 
                                                transition: 'all 0.2s',
                                                fontWeight: '600'
                                            }}
                                            onMouseOver={(e) => e.currentTarget.style.background = 'rgba(59, 130, 246, 0.2)'}
                                            onMouseOut={(e) => e.currentTarget.style.background = 'rgba(59, 130, 246, 0.1)'}
                                        >
                                            {assignee ? 'Reassign' : 'Assign & Move'}
                                        </button>
                                    )}
                                </div>
                            </div>

                            {/* LIVE NODE SUMMARY CHECKLIST */}
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '110px', overflowY: 'auto' }}>
                                {nodes.map((node) => {
                                    const isIsolated = isolatedNodes[node.id];
                                    const dotColor = !isCveActiveOnHost ? greenMatch : (node.criticality === 'Critical' ? activeCveColor : '#78716c');
                                    const stateText = !isCveActiveOnHost ? '🔒 Secured' : (isIsolated ? '🔒 Secured' : '🔓 Exposed');
                                    const stateColor = !isCveActiveOnHost ? greenMatch : (isIsolated ? greenMatch : activeCveColor);
                                    return (
                                        <div 
                                            key={`summary-${node.id}`} 
                                            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255, 255, 255, 0.02)', padding: '5px 10px', borderRadius: '6px', fontSize: '11px', border: '1px solid rgba(255, 255, 255, 0.02)' }}
                                        >
                                            <span style={{ color: '#e7e5e4', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                <span style={{ width: '4px', height: '4px', background: dotColor, borderRadius: '50%' }}></span>
                                                {node.name}
                                                <span style={{ fontSize: '9px', color: '#78716c', background: 'rgba(255, 255, 255, 0.05)', padding: '1px 4px', borderRadius: '3px' }}>
                                                    {node.criticality}
                                                </span>
                                            </span>
                                            <span style={{ 
                                                color: stateColor, 
                                                fontWeight: '600',
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: '4px'
                                            }}>
                                                {stateText}
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>

                    {/* ASSIGNMENT MODAL OVERLAY */}
                    {showAssignModal && (
                        <div style={{
                            position: 'absolute',
                            top: 0,
                            left: 0,
                            right: 0,
                            bottom: 0,
                            background: 'rgba(9, 13, 22, 0.96)',
                            backdropFilter: 'blur(16px)',
                            WebkitBackdropFilter: 'blur(16px)',
                            borderRadius: '16px',
                            padding: '32px',
                            display: 'flex',
                            flexDirection: 'column',
                            justifyContent: 'space-between',
                            zIndex: 10,
                            border: '1px solid rgba(255, 255, 255, 0.08)'
                        }}>
                            <div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                                    <h4 style={{ margin: 0, fontSize: '15px', color: '#ffffff', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        <Shield size={16} color="#3b82f6" /> Escalate Core Breach & Assign Analyst
                                    </h4>
                                    <button 
                                        onClick={() => setShowAssignModal(false)}
                                        style={{ background: 'transparent', border: 'none', color: '#78716c', cursor: 'pointer', fontSize: '16px' }}
                                    >
                                        ✕
                                    </button>
                                </div>
                                <p style={{ fontSize: '12px', color: '#a8a29e', margin: '0 0 20px 0', lineHeight: '1.5' }}>
                                    Moving the compromised core **{selectedCveId}** to the findings backlog. Choose an analyst to take ownership of containment, patch verification, and VEX signature tasks.
                                </p>
                                
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                    {analysts.map((analyst) => (
                                        <div 
                                            key={analyst.init}
                                            onClick={() => handleAssign(analyst)}
                                            style={{ 
                                                display: 'flex', 
                                                alignItems: 'center', 
                                                justifyContent: 'space-between',
                                                background: 'rgba(255, 255, 255, 0.02)', 
                                                border: '1px solid rgba(255, 255, 255, 0.05)', 
                                                padding: '8px 12px', 
                                                borderRadius: '8px', 
                                                cursor: 'pointer',
                                                transition: 'all 0.2s' 
                                            }}
                                            onMouseOver={(e) => {
                                                e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)';
                                                e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.25)';
                                            }}
                                            onMouseOut={(e) => {
                                                e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)';
                                                e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.05)';
                                            }}
                                        >
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                                <div style={{ width: '28px', height: '28px', borderRadius: '4px', background: analyst.color, color: '#ffffff', fontSize: '11px', fontWeight: 'bold', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                                    {analyst.init}
                                                </div>
                                                <div style={{ display: 'flex', flexDirection: 'column' }}>
                                                    <span style={{ fontSize: '13px', color: '#e7e5e4', fontWeight: '500' }}>{analyst.name}</span>
                                                    <span style={{ fontSize: '10px', color: '#78716c' }}>{analyst.role}</span>
                                                </div>
                                            </div>
                                            <span style={{ fontSize: '10px', color: '#3b82f6', background: 'rgba(59, 130, 246, 0.1)', padding: '2px 6px', borderRadius: '4px', fontWeight: 'bold' }}>
                                                {analyst.title}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '20px' }}>
                                <button 
                                    onClick={() => setShowAssignModal(false)}
                                    style={{ background: 'transparent', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#a8a29e', fontSize: '12px', padding: '6px 16px', borderRadius: '6px', cursor: 'pointer' }}
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    )}
                </div>

                {/* RIGHT CARD: INCIDENT LIFECYCLE & ACTIVITY */}
                <div style={{ ...glassStyle, flex: '1.2', display: 'flex', flexDirection: 'column', borderRadius: '16px', padding: '24px 28px' }}>
                    <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)', marginBottom: '18px', paddingBottom: '2px', gap: '16px' }}>
                        <div 
                            onClick={() => setActiveRightTab('lifecycle')}
                            style={{ 
                                fontSize: '13.5px', 
                                color: activeRightTab === 'lifecycle' ? '#ffffff' : '#78716c', 
                                fontWeight: '600', 
                                paddingBottom: '8px', 
                                borderBottom: activeRightTab === 'lifecycle' ? `2px solid #3b82f6` : '2px solid transparent',
                                cursor: 'pointer',
                                transition: 'all 0.2s',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '6px'
                            }}
                        >
                            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: activeRightTab === 'lifecycle' ? '#3b82f6' : 'transparent', display: 'inline-block' }}></span>
                            Incident Lifecycle
                        </div>
                        <div 
                            onClick={() => setActiveRightTab('activity')}
                            style={{ 
                                fontSize: '13.5px', 
                                color: activeRightTab === 'activity' ? '#ffffff' : '#78716c', 
                                fontWeight: '600', 
                                paddingBottom: '8px', 
                                borderBottom: activeRightTab === 'activity' ? `2px solid #3b82f6` : '2px solid transparent',
                                cursor: 'pointer',
                                transition: 'all 0.2s'
                            }}
                        >
                            Context Activity
                        </div>
                    </div>

                    {activeRightTab === 'lifecycle' ? (() => {
                        const activeTarget = cveTargets[selectedCveId] || { name: 'Auth Service', pid: 4824, node_id: 'auth_svc' };
                        
                        if (!isCveActiveOnHost) {
                            return (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', flex: 1 }}>
                                    {/* CVE Switcher Dropdown */}
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '8px', padding: '8px 12px', marginBottom: '16px' }}>
                                        <span style={{ fontSize: '10.5px', color: '#78716c', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Focus Incident</span>
                                        <select 
                                            value={selectedCveId} 
                                            onChange={(e) => {
                                                setSelectedCveId(e.target.value);
                                                setAnalysisStatus('idle');
                                                setReportStatus('idle');
                                            }}
                                            style={{ 
                                                background: '#090d16', 
                                                color: '#e7e5e4', 
                                                border: '1px solid rgba(255, 255, 255, 0.1)', 
                                                borderRadius: '6px', 
                                                fontSize: '11.5px', 
                                                padding: '4px 8px', 
                                                cursor: 'pointer',
                                                outline: 'none'
                                            }}
                                        >
                                            {cves.map(cve => {
                                                const isActive = !authorized || activeThreatsList.includes(cve.id);
                                                return (
                                                    <option key={cve.id} value={cve.id}>
                                                        {cve.id} {isActive ? `(${cve.severity})` : '(SECURE)'}
                                                    </option>
                                                );
                                            })}
                                        </select>
                                    </div>

                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', flex: 1, justifyContent: 'center', alignItems: 'center', textAlign: 'center', padding: '24px', background: 'rgba(255, 255, 255, 0.01)', border: '1px solid rgba(255, 255, 255, 0.03)', borderRadius: '12px' }}>
                                        <div style={{ 
                                            width: '56px', 
                                            height: '56px', 
                                            borderRadius: '50%', 
                                            background: 'rgba(55, 178, 80, 0.08)', 
                                            border: `1px solid rgba(55, 178, 80, 0.2)`, 
                                            display: 'flex', 
                                            alignItems: 'center', 
                                            justifyContent: 'center',
                                            marginBottom: '4px',
                                            boxShadow: '0 0 20px rgba(55, 178, 80, 0.1)'
                                        }}>
                                            <ShieldCheck size={28} color={greenMatch} />
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                            <h4 style={{ margin: 0, fontSize: '15px', color: '#ffffff', fontWeight: '600' }}>Host System Secure</h4>
                                            <p style={{ margin: 0, fontSize: '12px', color: '#a8a29e', lineHeight: '1.6', maxWidth: '300px' }}>
                                                No active process signature or behavior matching <strong style={{ color: '#ffffff' }}>{selectedCveId}</strong> was detected on the Windows host.
                                            </p>
                                        </div>
                                        
                                        <div style={{ 
                                            background: 'rgba(0, 0, 0, 0.15)', 
                                            border: '1px solid rgba(255, 255, 255, 0.04)', 
                                            borderRadius: '8px', 
                                            padding: '10px 14px', 
                                            width: '100%', 
                                            maxWidth: '320px',
                                            display: 'flex',
                                            flexDirection: 'column',
                                            gap: '6px',
                                            textAlign: 'left'
                                        }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <span style={{ fontSize: '10.5px', color: '#78716c' }}>Host Agent status</span>
                                                <span style={{ fontSize: '10.5px', color: greenMatch, fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                    <span style={{ width: '5px', height: '5px', background: greenMatch, borderRadius: '50%' }}></span>
                                                    Connected
                                                </span>
                                            </div>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <span style={{ fontSize: '10.5px', color: '#78716c' }}>Vulnerability Scan</span>
                                                <span style={{ fontSize: '10.5px', color: '#e7e5e4' }}>Clean (0 hits)</span>
                                            </div>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <span style={{ fontSize: '10.5px', color: '#78716c' }}>ETW Telemetry</span>
                                                <span style={{ fontSize: '10.5px', color: greenMatch, fontWeight: 'bold' }}>Monitoring Active</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                        }

                        return (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', overflowY: 'auto', flex: 1, paddingRight: '4px' }}>
                                {/* CVE Switcher Dropdown */}
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '8px', padding: '8px 12px', marginBottom: '16px' }}>
                                    <span style={{ fontSize: '10.5px', color: '#78716c', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Focus Incident</span>
                                    <select 
                                        value={selectedCveId} 
                                        onChange={(e) => {
                                            setSelectedCveId(e.target.value);
                                            setAnalysisStatus('idle');
                                            setReportStatus('idle');
                                        }}
                                        style={{ 
                                            background: '#090d16', 
                                            color: '#e7e5e4', 
                                            border: '1px solid rgba(255, 255, 255, 0.1)', 
                                            borderRadius: '6px', 
                                            fontSize: '11.5px', 
                                            padding: '4px 8px', 
                                            cursor: 'pointer',
                                            outline: 'none'
                                        }}
                                    >
                                        {cves.map(cve => {
                                            const isActive = !authorized || activeThreatsList.includes(cve.id);
                                            return (
                                                <option key={cve.id} value={cve.id}>
                                                    {cve.id} {isActive ? `(${cve.severity})` : '(SECURE)'}
                                                </option>
                                            );
                                        })}
                                    </select>
                                </div>

                                {renderLifecycleStep(
                                    1,
                                    "Threat Detected",
                                    "Breach Active",
                                    activeCveColor,
                                    `Critical vulnerability ${selectedCveId} identified in active process ${activeTarget.name} (PID ${activeTarget.pid}).`,
                                    null,
                                    true,
                                    false
                                )}
                                
                                {renderLifecycleStep(
                                    2,
                                    "Core Isolation",
                                    isolatedCount >= 3 ? "Quarantined" : "Exposed",
                                    isolatedCount >= 3 ? greenMatch : activeCveColor,
                                    `Isolate exposed process pathways on the network topology map to quarantine ${activeTarget.name} (PID ${activeTarget.pid}).`,
                                    isolatedCount >= 3 ? (
                                        <div style={{ fontSize: '10px', color: greenMatch, background: 'rgba(55, 178, 80, 0.05)', padding: '4px 8px', borderRadius: '4px', border: `1px solid ${greenMatch}22` }}>
                                            🔒 {isolatedCount} of {totalNodes} processes successfully isolated.
                                        </div>
                                    ) : (
                                        <div style={{ fontSize: '10px', color: activeCveColor, background: `${activeCveColor}0F`, padding: '4px 8px', borderRadius: '4px', border: `1px solid ${activeCveColor}22` }}>
                                            ⚠️ Critical process exposed. Isolate ${activeTarget.name} and neighboring nodes.
                                        </div>
                                    ),
                                    isolatedCount >= 3,
                                    isolatedCount < 3
                                )}

                                {renderLifecycleStep(
                                    3,
                                    "Analyst Assignment",
                                    assignee ? "Assigned" : "Pending",
                                    assignee ? greenMatch : '#f59e0b',
                                    "Assign an incident responder to direct mitigation, verification, and compliance logging.",
                                    !assignee ? (
                                        <button 
                                            onClick={() => setShowAssignModal(true)}
                                            disabled={isolatedCount < 3}
                                            style={{ 
                                                background: isolatedCount >= 3 ? 'rgba(59, 130, 246, 0.1)' : 'rgba(255, 255, 255, 0.02)', 
                                                border: `1px solid ${isolatedCount >= 3 ? 'rgba(59, 130, 246, 0.3)' : 'rgba(255, 255, 255, 0.05)'}`, 
                                                color: isolatedCount >= 3 ? '#3b82f6' : '#78716c', 
                                                padding: '4px 10px', 
                                                borderRadius: '4px', 
                                                fontSize: '10.5px', 
                                                fontWeight: '600', 
                                                cursor: isolatedCount >= 3 ? 'pointer' : 'not-allowed'
                                            }}
                                        >
                                            Assign Security Lead
                                        </button>
                                    ) : (
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#e7e5e4' }}>
                                            <div style={{ background: selectedAnalystObj?.color || '#3b82f6', color: '#ffffff', width: '18px', height: '18px', borderRadius: '3px', fontSize: '9px', fontWeight: 'bold', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                                {assignee}
                                            </div>
                                            <span>Lead: {assigneeName}</span>
                                        </div>
                                    ),
                                    assignee !== null,
                                    isolatedCount >= 3 && assignee === null
                                )}

                                {renderLifecycleStep(
                                    4,
                                    "Call-Graph Analysis",
                                    effectiveAnalysisStatus === 'completed' ? "Analyzed" : effectiveAnalysisStatus === 'running' ? "Analyzing..." : "Locked",
                                    effectiveAnalysisStatus === 'completed' ? greenMatch : effectiveAnalysisStatus === 'running' ? '#3b82f6' : '#78716c',
                                    `Evaluate runtime call trees and control flow pathways to verify vulnerability reachability in ${activeTarget.name}.`,
                                    effectiveAnalysisStatus === 'idle' ? (
                                        <button 
                                            onClick={() => {
                                                setAnalysisStatus('running');
                                                setTimeout(() => {
                                                    setAnalysisStatus('completed');
                                                }, 2500);
                                            }}
                                            disabled={!assignee || isolatedCount < 3}
                                            style={{ 
                                                background: (assignee && isolatedCount >= 3) ? 'rgba(59, 130, 246, 0.1)' : 'rgba(255, 255, 255, 0.02)', 
                                                border: `1px solid ${(assignee && isolatedCount >= 3) ? 'rgba(59, 130, 246, 0.3)' : 'rgba(255, 255, 255, 0.05)'}`, 
                                                color: (assignee && isolatedCount >= 3) ? '#3b82f6' : '#78716c', 
                                                padding: '4px 10px', 
                                                borderRadius: '4px', 
                                                fontSize: '10.5px', 
                                                fontWeight: '600', 
                                                cursor: (assignee && isolatedCount >= 3) ? 'pointer' : 'not-allowed'
                                            }}
                                        >
                                            Execute Runtime Trace
                                        </button>
                                    ) : effectiveAnalysisStatus === 'running' ? (
                                        <div style={{ width: '100%', background: 'rgba(255,255,255,0.05)', height: '5px', borderRadius: '3px', overflow: 'hidden', marginTop: '4px' }}>
                                            <div style={{ background: 'linear-gradient(90deg, #3b82f6, #37b250)', height: '100%', width: '100%', animation: 'scanProgress 2.5s linear forwards' }}></div>
                                        </div>
                                    ) : (
                                        <div style={{ fontSize: '10px', color: '#a8a29e', background: 'rgba(255,255,255,0.02)', padding: '6px 8px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.04)' }}>
                                            <span style={{ color: greenMatch, fontWeight: 'bold' }}>✓ Analysis Success.</span> Verified DLL entry-points of {activeTarget.name} (PID {activeTarget.pid}). Target functions protected.
                                        </div>
                                    ),
                                    effectiveAnalysisStatus === 'completed',
                                    assignee !== null && isolatedCount >= 3 && effectiveAnalysisStatus === 'idle'
                                )}

                                {renderLifecycleStep(
                                    5,
                                    "VEX & Report Publish",
                                    effectiveReportStatus === 'generated' ? "Published" : effectiveReportStatus === 'generating' ? "Compiling..." : "Locked",
                                    effectiveReportStatus === 'generated' ? greenMatch : effectiveReportStatus === 'generating' ? '#3b82f6' : '#78716c',
                                    "Formally sign VEX (Vulnerability Exploit eXchange) compliance statement and export security logs.",
                                    effectiveReportStatus === 'idle' ? (
                                        <button 
                                            onClick={() => {
                                                setReportStatus('generating');
                                                setTimeout(() => {
                                                    setReportStatus('generated');
                                                    handleMoveToResolved();
                                                }, 2000);
                                            }}
                                            disabled={effectiveAnalysisStatus !== 'completed'}
                                            style={{ 
                                                background: effectiveAnalysisStatus === 'completed' ? 'rgba(55, 178, 80, 0.1)' : 'rgba(255, 255, 255, 0.02)', 
                                                border: `1px solid ${effectiveAnalysisStatus === 'completed' ? 'rgba(55, 178, 80, 0.3)' : 'rgba(255, 255, 255, 0.05)'}`, 
                                                color: effectiveAnalysisStatus === 'completed' ? greenMatch : '#78716c', 
                                                padding: '4px 10px', 
                                                borderRadius: '4px', 
                                                fontSize: '10.5px', 
                                                fontWeight: '600', 
                                                cursor: effectiveAnalysisStatus === 'completed' ? 'pointer' : 'not-allowed'
                                            }}
                                        >
                                            Sign VEX & Export
                                        </button>
                                    ) : effectiveReportStatus === 'generating' ? (
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '10px', color: '#3b82f6', marginTop: '4px' }}>
                                            <div style={{ width: '10px', height: '10px', border: '1.5px solid rgba(59,130,246,0.2)', borderTopColor: '#3b82f6', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }}></div>
                                            Attesting and packaging security report...
                                        </div>
                                    ) : (
                                        <div style={{ display: 'flex', gap: '6px' }}>
                                            <button 
                                                onClick={() => {
                                                    const reportData = {
                                                        incidentId: selectedCveId,
                                                        vulnerability: activeCveObj.name,
                                                        status: 'RESOLVED_MITIGATED',
                                                        analyst: assigneeName,
                                                        mitigationTime: new Date().toISOString(),
                                                        nodesIsolated: Object.keys(isolatedNodes).filter(k => isolatedNodes[k]),
                                                        vexSignature: 'SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
                                                    };
                                                    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
                                                    const downloadAnchor = document.createElement('a');
                                                    downloadAnchor.setAttribute("href", dataStr);
                                                    downloadAnchor.setAttribute("download", `zenix_security_report_${selectedCveId}.json`);
                                                    document.body.appendChild(downloadAnchor);
                                                    downloadAnchor.click();
                                                    downloadAnchor.remove();
                                                }}
                                                style={{ background: 'rgba(55, 178, 80, 0.1)', border: '1px solid rgba(55, 178, 80, 0.3)', color: greenMatch, padding: '4px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: '600', cursor: 'pointer' }}
                                            >
                                                💾 Download Report
                                            </button>
                                            <button 
                                                onClick={() => {
                                                    setAnalysisStatus('idle');
                                                    setReportStatus('idle');
                                                    resetGates();
                                                    // Reset analyst in findings to open
                                                    const nextCols = { ...findings };
                                                    let cardObj = null;
                                                    Object.keys(nextCols).forEach(colId => {
                                                        const idx = nextCols[colId].items.findIndex(item => item.id === selectedCveId);
                                                        if (idx !== -1) {
                                                            [cardObj] = nextCols[colId].items.splice(idx, 1);
                                                            nextCols[colId].count = nextCols[colId].items.length;
                                                        }
                                                    });
                                                    if (cardObj) {
                                                        cardObj.init = 'NM';
                                                        cardObj.initBg = '#eab308';
                                                        cardObj.badge = selectedCveId === 'CVE-2021-44228' ? 'CRIT' : 'HIGH';
                                                        cardObj.badgeColor = selectedCveId === 'CVE-2021-44228' ? '#ef4444' : '#fa4516';
                                                        nextCols['open'].items.push(cardObj);
                                                        nextCols['open'].count = nextCols['open'].items.length;
                                                        setFindings(nextCols);
                                                    }
                                                }}
                                                style={{ background: 'rgba(255, 255, 255, 0.04)', border: '1px solid rgba(255, 255, 255, 0.08)', color: '#a8a29e', padding: '4px 8px', borderRadius: '4px', fontSize: '10px', cursor: 'pointer' }}
                                            >
                                                Reset Flow
                                            </button>
                                        </div>
                                    ),
                                    effectiveReportStatus === 'generated',
                                    effectiveAnalysisStatus === 'completed' && effectiveReportStatus === 'idle'
                                )}
                            </div>
                        );
                    })() : (

                        // Standard activity list
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', overflowY: 'auto', flex: 1 }}>
                            {[
                                { icon: 'shield', title: 'VEX Attestation Signed for log4j-core', sub: 'Automated compliance check • 8 mins ago' },
                                { icon: 'alert', title: 'SLA breach on Incident #4453', sub: 'Response time exceeded by • 2 hours' },
                                { icon: 'bug', title: 'Critical vulnerability detected: CVE-2025-1234 in nginx server', sub: 'Found in nginx server • (CVE-2025-1234)' },
                                { icon: 'scan', title: 'Compliance scan started', sub: 'Manual trigger • by John.D' },
                                { icon: 'report', title: 'Report scheduled: "Monthly Summary"', sub: 'Set to run on May 2, • 10:00 UTC' },
                                { icon: 'export', title: 'Export completed: Findings (CSV)', sub: '45 records downloaded' },
                                { icon: 'check', title: 'Remediation task marked complete', sub: 'Resolved by admin • (Task #942)' },
                            ].map((item, idx) => (
                                <div key={idx} style={{ background: 'rgba(0, 0, 0, 0.2)', padding: '12px 16px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer', transition: 'background 0.2s', border: '1px solid rgba(255, 255, 255, 0.02)' }}
                                    onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)'}
                                    onMouseOut={(e) => e.currentTarget.style.background = 'rgba(0, 0, 0, 0.2)'}
                                >
                                    <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                        <div style={{ width: '12px', height: '12px', border: '1px solid #a8a29e', borderRadius: item.icon === 'shield' || item.icon === 'bug' ? '2px' : '50%' }}></div>
                                    </div>
                                    <div style={{ flex: 1 }}>
                                        <div style={{ fontSize: '13px', color: '#e7e5e4', fontWeight: '500', marginBottom: '2px' }}>{item.title}</div>
                                        <div style={{ fontSize: '11px', color: '#78716c' }}>{item.sub}</div>
                                    </div>
                                    <div style={{ fontSize: '14px', color: '#78716c' }}>↗</div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Glassmorphic Lockscreen Overlay if Unauthorized */}
                {!authorized && (
                    <div style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        background: 'rgba(9, 13, 22, 0.45)',
                        backdropFilter: 'blur(20px)',
                        WebkitBackdropFilter: 'blur(20px)',
                        borderRadius: '16px',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'center',
                        alignItems: 'center',
                        gap: '20px',
                        zIndex: 100,
                        border: '1px solid rgba(255, 255, 255, 0.05)',
                        textAlign: 'center',
                        padding: '40px'
                    }}>
                        <div style={{ 
                            width: '72px', 
                            height: '72px', 
                            borderRadius: '50%', 
                            background: 'rgba(250, 69, 22, 0.08)', 
                            border: '1px solid rgba(250, 69, 22, 0.2)', 
                            display: 'flex', 
                            alignItems: 'center', 
                            justifyContent: 'center',
                            boxShadow: '0 0 40px rgba(250, 69, 22, 0.15)',
                            marginBottom: '4px'
                        }}>
                            <Lock size={32} color="#fa4516" />
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <h3 style={{ margin: 0, fontSize: '20px', color: '#ffffff', fontWeight: '600', letterSpacing: '0.5px' }}>Device Authentication Required</h3>
                            <p style={{ margin: 0, fontSize: '13.5px', color: '#94a3b8', lineHeight: '1.6', maxWidth: '380px' }}>
                                Zenix requires authorization to access system-level telemetry. Click the settings profile icon in the top-right and select <strong>Authenticate Host</strong> to connect Zenix to your local Windows agent.
                            </p>
                        </div>
                    </div>
                )}
            </div>
            <style>{`
                @keyframes scanProgress {
                    0% { width: 0%; }
                    100% { width: 100%; }
                }
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            `}</style>
        </div>
    );
};

export default OverviewView;
