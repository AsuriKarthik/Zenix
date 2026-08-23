import React, { useState, useEffect, useCallback } from 'react';
import { DragDropContext, Droppable, Draggable } from '@hello-pangea/dnd';
import { 
    Shield, 
    ShieldCheck, 
    ShieldAlert, 
    Lock, 
    Unlock, 
    Download, 
    User, 
    Bug, 
    Activity, 
    Play, 
    RefreshCw, 
    Layers, 
    Copy, 
    Check, 
    FileText, 
    AlertTriangle, 
    AlertCircle, 
    ExternalLink 
} from 'lucide-react';

const CVE_META = {
    'CVE-2021-44228': {
        incidentId: 'INC-5552',
        title: 'CVE-2021-44228 (Log4Shell)',
        severity: 'Critical',
        cvss: 9.8,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        desc: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints, allowing remote code execution.'
    },
    'CVE-2023-4863': {
        incidentId: 'INC-4863',
        title: 'CVE-2023-4863 (libwebp heap buffer)',
        severity: 'High',
        cvss: 8.8,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        desc: 'Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 allowed an out-of-bounds memory write.'
    },
    'CVE-2023-44487': {
        incidentId: 'INC-4448',
        title: 'CVE-2023-44487 (HTTP/2 Rapid Reset)',
        severity: 'High',
        cvss: 7.5,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        desc: 'The HTTP/2 protocol allows a denial of service (resource consumption) via rapid stream creation and reset.'
    },
    'CVE-2023-38545': {
        incidentId: 'INC-3854',
        title: 'CVE-2023-38545 (curl SOCKS5 overflow)',
        severity: 'Medium',
        cvss: 5.9,
        vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        desc: 'SOCKS5 heap buffer overflow in curl prior to 8.4.0 when resolving names via proxy.'
    },
    'CVE-2023-38408': {
        incidentId: 'INC-3840',
        title: 'CVE-2023-38408 (OpenSSH struct vuln)',
        severity: 'High',
        cvss: 8.1,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        desc: 'Remote code execution in ssh-agent in OpenSSH prior to 9.3p2 via forwarding to compromised host.'
    }
};

const ANALYSTS = [
    { init: 'NM', name: 'Nandini Mahesh', color: '#EF4444', role: 'Security Lead' },
    { init: 'MV', name: 'Monisha Varma', color: '#22C55E', role: 'Compliance Officer' },
    { init: 'KK', name: 'Kushal Kumar', color: '#F59E0B', role: 'SecOps Engineer' },
    { init: 'DK', name: 'Divyansha Kaushik', color: '#EF4444', role: 'IR Specialist' },
    { init: 'AR', name: 'Arjun Reddy', color: '#3B82F6', role: 'DevSecOps Specialist' }
];

const InvestigationWorkspace = ({ columns, setColumns }) => {
    const [selectedCveId, setSelectedCveId] = useState('CVE-2021-44228');
    const [isolationState, setIsolationState] = useState({
        api_gw: false, auth_svc: false, customer_db: false, analytics: false, cache_svr: false, search_idx: false
    });
    const [shadowDeps, setShadowDeps] = useState([]);
    const [telemetryLogs, setTelemetryLogs] = useState([]);
    const [copiedVex, setCopiedVex] = useState(false);
    const [isAssigning, setIsAssigning] = useState(false);

    // Fetch details for selected CVE
    const fetchCveDetails = useCallback(() => {
        // Fetch current isolation state
        fetch(`http://localhost:5000/api/findings/get-isolation?cve_id=${selectedCveId}`)
            .then(res => res.json())
            .then(data => setIsolationState(data))
            .catch(err => console.warn("Failed to fetch isolation status:", err));
    }, [selectedCveId]);

    // Fetch shared static dependencies and logs
    useEffect(() => {
        fetch('http://localhost:5000/api/shadow-dependencies')
            .then(res => res.json())
            .then(data => setShadowDeps(data))
            .catch(err => console.warn(err));

        fetch('http://localhost:5000/api/telemetry')
            .then(res => res.json())
            .then(data => setTelemetryLogs(data))
            .catch(err => console.warn(err));
    }, []);

    useEffect(() => {
        fetchCveDetails();
    }, [selectedCveId, fetchCveDetails]);

    // Drag-and-drop handler for Kanban columns
    const onDragEnd = (result) => {
        const { source, destination } = result;
        if (!destination) return;
        if (source.droppableId === destination.droppableId && source.index === destination.index) return;

        const sourceCol = { ...columns[source.droppableId] };
        const destCol = source.droppableId === destination.droppableId ? sourceCol : { ...columns[destination.droppableId] };

        const sourceItems = [...sourceCol.items];
        const destItems = source.droppableId === destination.droppableId ? sourceItems : [...destCol.items];

        const [movedItem] = sourceItems.splice(source.index, 1);
        destItems.splice(destination.index, 0, movedItem);

        const nextColumns = {
            ...columns,
            [source.droppableId]: { ...sourceCol, items: sourceItems, count: sourceItems.length },
            [destination.droppableId]: { ...destCol, items: destItems, count: destItems.length }
        };

        setColumns(nextColumns);
    };

    // Toggle a service isolation gate
    const toggleGate = (nodeId) => {
        const nextState = !isolationState[nodeId];
        setIsolationState(prev => ({ ...prev, [nodeId]: nextState }));
        
        fetch('http://localhost:5000/api/findings/isolate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cve_id: selectedCveId, node_id: nodeId, isolated: nextState })
        })
        .then(() => {
            // Re-fetch findings in parent to update risk calculations
            fetch('http://localhost:5000/api/findings')
                .then(res => res.json())
                .then(data => setColumns(data));
        })
        .catch(err => console.error("Error setting isolation:", err));
    };

    // Assign analyst
    const handleAssignAnalyst = (analyst) => {
        setIsAssigning(false);
        fetch('http://localhost:5000/api/findings/assign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cve_id: selectedCveId, analyst })
        })
        .then(() => {
            fetch('http://localhost:5000/api/findings')
                .then(res => res.json())
                .then(data => setColumns(data));
        })
        .catch(err => console.error("Error assigning analyst:", err));
    };

    // Quick Actions
    const handleMoveToResolved = () => {
        const nextCols = { ...columns };
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
            cardToMove.badgeColor = '#3B82F6';
            cardToMove.is_reachable = false;
            nextCols['resolved'].items.push(cardToMove);
            nextCols['resolved'].count = nextCols['resolved'].items.length;
            setColumns(nextCols);

            // Sync to backend
            fetch('http://localhost:5000/api/findings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(nextCols)
            }).catch(err => console.error(err));
        }
    };

    // Export findings to JSON
    const handleExport = () => {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(columns, null, 2));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", `zenix_findings_${selectedCveId}.json`);
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    };

    // Extract active card metrics
    let activeCard = null;
    let currentColumnId = 'open';
    if (columns) {
        Object.entries(columns).forEach(([colId, col]) => {
            const item = col.items.find(i => i.id === selectedCveId);
            if (item) {
                activeCard = item;
                currentColumnId = colId;
            }
        });
    }

    const metadata = CVE_META[selectedCveId] || CVE_META['CVE-2021-44228'];
    const activeAnalyst = ANALYSTS.find(a => a.init === activeCard?.init) || ANALYSTS[0];
    const isReachable = activeCard ? activeCard.is_reachable : true;
    const isolatedCount = Object.values(isolationState).filter(Boolean).length;

    // Generate VEX JSON Preview payload
    const vexPreviewData = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "id": `https://zenix.security/vex/doc/2026-${selectedCveId.split('-')[2]}`,
        "author": "Zenix Antigravity Engine",
        "timestamp": new Date().toISOString().substring(0, 10),
        "statements": [
            {
                "vulnerability": { "name": selectedCveId },
                "products": [{ "subcomponents": [{ "name": "com.zenix.runtime:active-process" }] }],
                "status": isReachable ? "not_affected" : "not_affected",
                "justification": isReachable ? "vulnerable_code_loaded_in_memory" : "vulnerable_code_not_reachable",
                "impact_statement": isReachable 
                    ? "Dynamic telemetry detects active execution of vulnerable modules."
                    : "ETW telemetry confirms library present on disk but inactive in RAM. Quarantined via network isolation gates."
            }
        ],
        "verification": {
            "confidence_score": isReachable ? "42%" : "98%",
            "attested_by": activeCard?.init || "System"
        }
    };

    const copyVexJson = () => {
        navigator.clipboard.writeText(JSON.stringify(vexPreviewData, null, 2));
        setCopiedVex(true);
        setTimeout(() => setCopiedVex(false), 2000);
    };

    const renderColumnIcon = (type, color) => {
        switch (type) {
            case 'circle': return <div style={{ width: '10px', height: '10px', borderRadius: '50%', border: `1.5px solid ${color}` }}></div>;
            case 'target': return <div style={{ width: '10px', height: '10px', borderRadius: '50%', border: `1.5px dotted ${color}` }}></div>;
            case 'play': return <div style={{ width: '10px', height: '10px', borderRadius: '50%', border: `1.5px solid ${color}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><div style={{ width: '3px', height: '3px', background: color, borderRadius: '50%' }}></div></div>;
            case 'check': return <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: color, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><span style={{ color: '#050807', fontSize: '8px', fontWeight: 'bold' }}>✓</span></div>;
            default: return null;
        }
    };

    return (
        <div style={{ display: 'flex', gap: '24px', height: '100%', overflow: 'hidden', color: '#F5F5F5' }}>
            
            {/* LEFT PANEL (40%): Reachable Risks (Kanban columns stacked vertically) */}
            <div style={{ flex: '0.40', display: 'flex', flexDirection: 'column', gap: '16px', height: '100%', overflowY: 'auto', paddingRight: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>Reachable Risks</h3>
                    <span style={{ fontSize: '11px', color: '#71717A' }}>Drag cards to triage</span>
                </div>

                <DragDropContext onDragEnd={onDragEnd}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        {Object.entries(columns).map(([colId, col]) => (
                            <div 
                                key={colId} 
                                style={{ 
                                    background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)', 
                                    backdropFilter: 'blur(16px)',
                                    WebkitBackdropFilter: 'blur(16px)',
                                    border: '1px solid rgba(255, 255, 255, 0.08)', 
                                    boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)',
                                    borderRadius: '14px', 
                                    padding: '14px' 
                                }}
                            >
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                                    {renderColumnIcon(col.iconType, col.iconColor)}
                                    <span style={{ fontSize: '13px', fontWeight: '600', color: '#F5F5F5' }}>{col.title}</span>
                                    <span style={{ fontSize: '11px', color: '#71717A' }}>({col.count})</span>
                                </div>

                                <Droppable droppableId={colId}>
                                    {(provided) => (
                                        <div
                                            {...provided.droppableProps}
                                            ref={provided.innerRef}
                                            style={{ display: 'flex', flexDirection: 'column', gap: '8px', minHeight: '30px' }}
                                        >
                                            {col.items.map((item, index) => {
                                                const isSelected = selectedCveId === item.id;
                                                const riskColor = item.risk_score >= 7.0 ? '#EF4444' : item.risk_score >= 4.0 ? '#F59E0B' : '#22C55E';
                                                
                                                return (
                                                    <Draggable key={item.id} draggableId={item.id} index={index}>
                                                        {(provided, snapshot) => (
                                                            <div
                                                                ref={provided.innerRef}
                                                                {...provided.draggableProps}
                                                                {...provided.dragHandleProps}
                                                                onClick={() => setSelectedCveId(item.id)}
                                                                style={{
                                                                    ...provided.draggableProps.style,
                                                                    background: isSelected 
                                                                        ? 'linear-gradient(135deg, rgba(34, 211, 238, 0.12) 0%, rgba(34, 211, 238, 0.04) 100%)' 
                                                                        : 'linear-gradient(135deg, rgba(37, 39, 45, 0.65) 0%, rgba(22, 24, 28, 0.45) 100%)',
                                                                    backdropFilter: 'blur(12px)',
                                                                    WebkitBackdropFilter: 'blur(12px)',
                                                                    border: isSelected 
                                                                        ? '1px solid rgba(34, 211, 238, 0.5)' 
                                                                        : '1px solid rgba(255, 255, 255, 0.08)',
                                                                    boxShadow: isSelected
                                                                        ? '0 0 20px rgba(34, 211, 238, 0.18), inset 0 1px 0 0 rgba(255, 255, 255, 0.12)'
                                                                        : 'inset 0 1px 0 0 rgba(255, 255, 255, 0.06)',
                                                                    transition: 'all 0.25s ease',

                                                                    borderRadius: '10px',
                                                                    padding: '12px',
                                                                    cursor: 'pointer',
                                                                    display: 'flex',
                                                                    flexDirection: 'column',
                                                                    gap: '8px',
                                                                    transition: 'border-color 0.15s ease',
                                                                    opacity: snapshot.isDragging ? 0.8 : 1,
                                                                    boxShadow: snapshot.isDragging ? '0 10px 20px rgba(0,0,0,0.5)' : 'none'
                                                                }}
                                                            >
                                                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                                    <span style={{ fontSize: '13px', fontWeight: '600', color: isSelected ? '#DAFC6F' : '#F5F5F5' }}>
                                                                        {item.id}
                                                                    </span>
                                                                    {item.badge && (
                                                                        <span style={{ 
                                                                            background: 'rgba(239, 68, 68, 0.12)', 
                                                                            border: '1px solid rgba(239, 68, 68, 0.25)', 
                                                                            color: '#EF4444', 
                                                                            fontSize: '10px', 
                                                                            padding: '2px 6px', 
                                                                            borderRadius: '4px' 
                                                                        }}>
                                                                            {item.badge}
                                                                        </span>
                                                                    )}
                                                                </div>

                                                                <div style={{ fontSize: '12px', color: '#A1A1AA' }}>
                                                                    {item.subtitle}
                                                                </div>

                                                                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '2px' }}>
                                                                    {item.risk_score !== undefined && (
                                                                        <span style={{ background: `${riskColor}1A`, color: riskColor, border: `1px solid ${riskColor}25`, fontSize: '10px', padding: '1px 5px', borderRadius: '4px', fontWeight: 'bold' }}>
                                                                            Risk: {item.risk_score}
                                                                        </span>
                                                                    )}
                                                                    {item.epss !== undefined && (
                                                                        <span style={{ background: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.15)', color: '#3B82F6', fontSize: '10px', padding: '1px 5px', borderRadius: '4px' }}>
                                                                            EPSS: {Math.round(item.epss * 100)}%
                                                                        </span>
                                                                    )}
                                                                    {item.kev && (
                                                                        <span style={{ background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.25)', color: '#F59E0B', fontSize: '10px', fontWeight: 'bold', padding: '1px 5px', borderRadius: '4px' }}>
                                                                            KEV
                                                                        </span>
                                                                    )}
                                                                    <span style={{ background: item.is_reachable ? 'rgba(239, 68, 68, 0.08)' : 'rgba(34, 197, 94, 0.08)', border: `1px solid ${item.is_reachable ? 'rgba(239, 68, 68, 0.15)' : 'rgba(34, 197, 94, 0.15)'}`, color: item.is_reachable ? '#EF4444' : '#22C55E', fontSize: '10px', padding: '1px 5px', borderRadius: '4px' }}>
                                                                        {item.is_reachable ? 'Reachable' : 'Quarantined'}
                                                                    </span>
                                                                </div>
                                                            </div>
                                                        )}
                                                    </Draggable>
                                                );
                                            })}
                                            {provided.placeholder}
                                        </div>
                                    )}
                                </Droppable>
                            </div>
                        ))}
                    </div>
                </DragDropContext>
            </div>

            {/* MIDDLE PANEL (35%): Case Investigation (Vulnerability triage detail) */}
            <div style={{ flex: '0.35', display: 'flex', flexDirection: 'column', gap: '16px', height: '100%', overflowY: 'auto', paddingRight: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>Incident Triage</h3>
                    <span style={{ fontSize: '11px', color: '#71717A' }}>{metadata.incidentId}</span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    
                    {/* Header Summary */}
                    <div style={{ background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)', backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', border: '1px solid rgba(255, 255, 255, 0.08)', boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)', borderRadius: '14px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        <div>
                            <h4 style={{ fontSize: '16px', fontWeight: '600', color: '#F5F5F5', margin: '0 0 4px 0' }}>{metadata.title}</h4>
                            <p style={{ fontSize: '13px', color: '#A1A1AA', margin: 0, lineHeight: '1.4' }}>{metadata.desc}</p>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', background: '#25272B', borderRadius: '8px', padding: '10px 12px', border: '1px solid rgba(255,255,255,0.04)' }}>
                            <div>
                                <div style={{ fontSize: '10px', color: '#71717A', textTransform: 'uppercase' }}>CVSS Core</div>
                                <div style={{ fontSize: '18px', fontWeight: '700', color: '#EF4444', marginTop: '2px' }}>{metadata.cvss} <span style={{ fontSize: '11px', color: '#A1A1AA', fontWeight: 'normal' }}>/ 10</span></div>
                            </div>
                            <div>
                                <div style={{ fontSize: '10px', color: '#71717A', textTransform: 'uppercase' }}>Assignee</div>
                                <div style={{ position: 'relative', marginTop: '2px' }}>
                                    <button 
                                        onClick={() => setIsAssigning(!isAssigning)}
                                        style={{ background: 'transparent', border: 'none', color: '#F5F5F5', fontSize: '13px', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', padding: 0 }}
                                    >
                                        <div style={{ width: '16px', height: '16px', borderRadius: '3px', background: activeAnalyst.color, color: '#050807', fontSize: '9px', fontWeight: 'bold', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                            {activeAnalyst.init}
                                        </div>
                                        {activeAnalyst.name}
                                    </button>

                                    {isAssigning && (
                                        <div style={{ position: 'absolute', top: '100%', left: 0, background: '#1E1F23', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '8px', padding: '4px', zIndex: 1000, width: '160px', marginTop: '6px', boxShadow: '0 4px 12px rgba(0,0,0,0.5)' }}>
                                            {ANALYSTS.map(a => (
                                                <div 
                                                    key={a.init}
                                                    onClick={() => handleAssignAnalyst(a)}
                                                    style={{ padding: '6px 10px', fontSize: '12px', cursor: 'pointer', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}
                                                    onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
                                                    onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}
                                                >
                                                    <span style={{ display: 'inline-block', width: '12px', height: '12px', borderRadius: '2px', background: a.color, color: '#050807', fontSize: '8px', fontWeight: 'bold', textAlign: 'center', lineHeight: '12px' }}>{a.init}</span>
                                                    {a.name}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Service Isolation Gates */}
                    <div style={{ background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)', backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', border: '1px solid rgba(255, 255, 255, 0.08)', boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)', borderRadius: '14px', padding: '16px' }}>
                        <div style={{ fontSize: '12px', color: '#A1A1AA', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px' }}>
                            Service Isolation Gates
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                            {Object.entries(isolationState).map(([nodeId, isIsolated]) => {
                                const names = { api_gw: 'API Gateway', auth_svc: 'Auth Service', customer_db: 'Customer DB', analytics: 'Analytics Hub', cache_svr: 'Cache Server', search_idx: 'Search Index' };
                                return (
                                    <div 
                                        key={nodeId}
                                        onClick={() => toggleGate(nodeId)}
                                        style={{ 
                                            background: '#25272B', 
                                            border: '1px solid rgba(255,255,255,0.04)', 
                                            borderRadius: '8px', 
                                            padding: '8px 12px', 
                                            display: 'flex', 
                                            justifyContent: 'space-between', 
                                            alignItems: 'center', 
                                            cursor: 'pointer',
                                            transition: 'border-color 0.15s ease' 
                                        }}
                                        onMouseOver={(e) => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'}
                                        onMouseOut={(e) => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.04)'}
                                    >
                                        <span style={{ fontSize: '12.5px', color: '#F5F5F5' }}>{names[nodeId] || nodeId}</span>
                                        <span style={{ fontSize: '11px', fontWeight: '600', color: isIsolated ? '#22C55E' : '#EF4444' }}>
                                            {isIsolated ? "Isolated" : "Exposed"}
                                        </span>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Threat Intelligence API Feeds */}
                    {activeCard && (
                        <div style={{ background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)', backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', border: '1px solid rgba(255, 255, 255, 0.08)', boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)', borderRadius: '14px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            <div style={{ fontSize: '12px', color: '#A1A1AA', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                                Threat Intelligence Feeds
                            </div>

                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                    <span style={{ color: '#71717A' }}>VirusTotal Search:</span>
                                    <span style={{ color: '#F5F5F5', fontWeight: '500' }}>
                                        {activeCard.virustotal_detections} detections ({activeCard.virustotal_source})
                                    </span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                    <span style={{ color: '#71717A' }}>Shodan Vulnerable Hosts:</span>
                                    <span style={{ color: '#F5F5F5', fontWeight: '500' }}>
                                        {activeCard.shodan_hosts?.toLocaleString()} devices ({activeCard.shodan_source})
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* AI Semantic Triage: Shadow Dependencies */}
                    <div style={{ background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)', backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', border: '1px solid rgba(255, 255, 255, 0.08)', boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)', borderRadius: '14px', padding: '16px' }}>
                        <div style={{ fontSize: '12px', color: '#A1A1AA', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <AlertCircle size={14} style={{ color: '#DAFC6F' }} /> AI Shadow Dependency Detection
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            {shadowDeps.slice(0, 2).map((dep, idx) => (
                                <div key={idx} style={{ background: '#25272B', borderRadius: '8px', padding: '10px', border: '1px solid rgba(255,255,255,0.04)' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontWeight: '600', color: '#F5F5F5', marginBottom: '4px' }}>
                                        <span>{dep.title}</span>
                                        <span style={{ color: '#DAFC6F', fontSize: '10px' }}>{dep.detected_pkg}</span>
                                    </div>
                                    <div style={{ fontSize: '11px', color: '#71717A', fontFamily: 'monospace' }}>
                                        {dep.file}:{dep.line}
                                    </div>
                                    <div style={{ fontSize: '11.5px', color: '#A1A1AA', marginTop: '6px', lineHeight: '1.4' }}>
                                        {dep.ai_analysis}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                </div>
            </div>

            {/* RIGHT PANEL (25%): Context Panel & Actions */}
            <div style={{ flex: '0.25', display: 'flex', flexDirection: 'column', gap: '16px', height: '100%', overflowY: 'auto', paddingRight: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>Context Details</h3>
                    <span style={{ fontSize: '11px', color: isReachable ? '#EF4444' : '#22C55E', fontWeight: '600' }}>
                        {isReachable ? "Exposed Graph" : "Quarantined"}
                    </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

                    {/* Micro Exploit Path Trace SVG */}
                    <div style={{ background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)', backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', border: '1px solid rgba(255, 255, 255, 0.08)', boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)', borderRadius: '14px', padding: '16px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                        <div style={{ width: '100%', fontSize: '12px', color: '#A1A1AA', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px', alignSelf: 'flex-start' }}>
                            Exploit Path Trace
                        </div>
                        
                        {/* Compact trace visualization */}
                        <svg width="100%" height="60" viewBox="0 0 240 60" style={{ overflow: 'visible' }}>
                            <g transform="translate(10, 30)">
                                {/* Node 1: Input */}
                                <circle cx="10" cy="0" r="10" fill="#25272B" stroke="#3B82F6" strokeWidth="1.5" />
                                <text x="10" y="3" textAnchor="middle" fill="#3B82F6" fontSize="7" fontWeight="bold">IN</text>
                                
                                {/* Line 1 */}
                                <line x1="20" y1="0" x2="80" y2="0" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5" strokeDasharray={!isReachable ? "3 3" : "none"} />
                                
                                {/* Node 2: Entry point */}
                                <circle cx="90" cy="0" r="12" fill="#25272B" stroke={isReachable ? "#EF4444" : "#22C55E"} strokeWidth="1.5" />
                                <text x="90" y="3" textAnchor="middle" fill={isReachable ? "#EF4444" : "#22C55E"} fontSize="7" fontWeight="bold">LOAD</text>
                                
                                {/* Line 2 */}
                                <line x1="102" y1="0" x2="168" y2="0" stroke="rgba(255,255,255,0.08)" strokeWidth="1.5" strokeDasharray={!isReachable ? "3 3" : "none"} />

                                {/* Node 3: Sink */}
                                <circle cx="180" cy="0" r="10" fill="#25272B" stroke={isReachable ? "#EF4444" : "rgba(255,255,255,0.08)"} strokeWidth="1.5" />
                                <text x="180" y="3" textAnchor="middle" fill={isReachable ? "#EF4444" : "#71717A"} fontSize="7" fontWeight="bold">SINK</text>
                            </g>
                        </svg>
                        
                        <div style={{ fontSize: '11px', color: '#71717A', width: '100%', textAlign: 'center', marginTop: '6px' }}>
                            {isReachable ? "Vulnerable path active in memory map." : "Call graph path disconnected via quarantine."}
                        </div>
                    </div>

                    {/* VEX Evidence Preview JSON Box */}
                    <div style={{ background: 'linear-gradient(135deg, rgba(30, 31, 37, 0.65) 0%, rgba(14, 15, 18, 0.45) 100%)', backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', border: '1px solid rgba(255, 255, 255, 0.08)', boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)', borderRadius: '14px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '12px', color: '#A1A1AA', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px' }}>VEX Proof Preview</span>
                            <button 
                                onClick={copyVexJson}
                                style={{ background: 'transparent', border: 'none', color: '#DAFC6F', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}
                            >
                                {copiedVex ? <Check size={12} /> : <Copy size={12} />}
                                {copiedVex ? "Copied" : "Copy"}
                            </button>
                        </div>
                        <textarea
                            readOnly
                            value={JSON.stringify(vexPreviewData, null, 2)}
                            style={{
                                width: '100%',
                                height: '140px',
                                background: '#050807',
                                border: '1px solid rgba(255,255,255,0.04)',
                                borderRadius: '8px',
                                padding: '10px',
                                color: '#DAFC6F',
                                fontFamily: 'monospace',
                                fontSize: '10.5px',
                                resize: 'none',
                                outline: 'none',
                                lineHeight: '1.4'
                            }}
                        />
                    </div>

                    {/* Context stats (Processes, DLLs count) */}
                    <div style={{ background: '#1E1F23', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '12px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <div style={{ fontSize: '12px', color: '#A1A1AA', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                            Telemetry Context Audit
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span style={{ color: '#71717A' }}>Running Processes:</span>
                                <span style={{ color: '#F5F5F5', fontWeight: '500' }}>32 active processes</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span style={{ color: '#71717A' }}>Target Executable:</span>
                                <span style={{ color: '#F5F5F5', fontWeight: '500' }}>java.exe</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span style={{ color: '#71717A' }}>Loaded DLL Signature:</span>
                                <span style={{ color: '#DAFC6F', fontWeight: '500', fontFamily: 'monospace', fontSize: '11px' }}>log4j-core-2.14.1.jar</span>
                            </div>
                        </div>
                    </div>

                    {/* Quick Actions buttons */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                        {currentColumnId !== 'resolved' && (
                            <button
                                onClick={handleMoveToResolved}
                                style={{ width: '100%', height: '38px', background: '#DAFC6F', border: 'none', borderRadius: '14px', color: '#050807', fontSize: '13px', fontWeight: '600', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                            >
                                <ShieldCheck size={14} /> Resolve & Sign VEX
                            </button>
                        )}
                        <button
                            onClick={handleExport}
                            style={{ width: '100%', height: '38px', background: '#25272B', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '14px', color: '#F5F5F5', fontSize: '13px', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', transition: 'background-color 0.15s ease' }}
                            onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.04)'}
                            onMouseOut={(e) => e.currentTarget.style.backgroundColor = '#25272B'}
                        >
                            <Download size={14} /> Export Dataset
                        </button>
                    </div>

                </div>
            </div>

        </div>
    );
};

export default InvestigationWorkspace;
