import React, { useState } from 'react';
import { DragDropContext, Droppable, Draggable } from '@hello-pangea/dnd';
import { Home, ChevronRight, Menu, Grid, Download, SlidersHorizontal, MoreHorizontal, Calendar, X, Info, FileText, Clock } from 'lucide-react';
import styles from './KanbanBoard.module.css';

const KanbanBoard = ({ initialFocusCardId, initialFocusCardColumn, onCheckEvidence }) => {
    const [selectedCard, setSelectedCard] = useState(null);
    const [activeFilter, setActiveFilter] = useState('Team is Cyfocus primary');
    const [viewMode, setViewMode] = useState('kanban');

    const [columns, setColumns] = useState({
        'open': {
            title: 'Identified',
            count: 2,
            iconColor: '#e7e5e4',
            iconType: 'circle',
            items: [
                { id: 'CVE-2023-44487', subtitle: 'HTTP/2 Rapid Reset', date: '2025-05-17', init: 'MV', initBg: '#22c55e', hasImg: false, dot: '#eab308' },
                { id: 'CVE-2023-38545', subtitle: 'curl SOCKS5 overflow', date: '2025-05-09', init: 'KK', initBg: '#eab308', hasImg: false, dot: '#eab308' }
            ]
        },
        'triaged': {
            title: 'Validated',
            count: 1,
            iconColor: '#a8a29e',
            iconType: 'target',
            items: [
                { id: 'CVE-2021-44228', subtitle: 'Log4Shell • log4j-core', date: '2025-11-20', init: 'NM', initBg: '#eab308', hasImg: true, dot: '#ef4444', badge: 'CRIT', badgeColor: '#ef4444' }
            ]
        },
        'inprogress': {
            title: 'Repairing',
            count: 1,
            iconColor: '#eab308',
            iconType: 'play',
            items: [
                { id: 'CVE-2023-4863', subtitle: 'libwebp heap buffer', date: '2025-05-21', init: 'DK', initBg: '#ef4444', hasImg: false, dot: '#fa4516', badge: 'HIGH', badgeColor: '#fa4516' }
            ]
        },
        'resolved': {
            title: 'Resolved',
            count: 1,
            iconColor: '#22c55e',
            iconType: 'check',
            items: [
                { id: 'CVE-2023-38408', subtitle: 'OpenSSH struct vuln', date: '2025-05-16', init: 'AR', initBg: '#3b82f6', hasImg: false, dot: '#22c55e', badge: 'VEX Signed', badgeColor: '#3b82f6' }
            ]
        }
    });

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

        setColumns({
            ...columns,
            [source.droppableId]: { ...sourceCol, items: sourceItems, count: sourceItems.length },
            [destination.droppableId]: { ...destCol, items: destItems, count: destItems.length }
        });
    };

    const handleExport = () => {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(columns, null, 2));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", "findings_export.json");
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    };

    const renderColumnIcon = (type, color) => {
        switch (type) {
            case 'circle': return <div style={{ width: '12px', height: '12px', borderRadius: '50%', border: `1.5px solid ${color}` }}></div>;
            case 'target': return <div style={{ width: '12px', height: '12px', borderRadius: '50%', border: `1.5px dotted ${color}` }}></div>;
            case 'play': return <div style={{ width: '12px', height: '12px', borderRadius: '50%', border: `1.5px solid ${color}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><div style={{ width: '4px', height: '4px', background: color, borderRadius: '50%' }}></div></div>;
            case 'check': return <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: color, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><span style={{ color: '#131110', fontSize: '10px', fontWeight: 'bold' }}>✓</span></div>;
            case 'x': return <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: color, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><span style={{ color: '#131110', fontSize: '10px', fontWeight: 'bold' }}>✕</span></div>;
            default: return null;
        }
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', position: 'relative' }}>
            {/* Findinds Header Top */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a8a29e', fontSize: '12px', marginBottom: '8px' }}>
                        <Home size={14} /> <ChevronRight size={14} /> Findings
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        <h2 style={{ fontSize: '24px', fontWeight: '500', color: '#e7e5e4', margin: 0 }}>Findings</h2>
                    </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div 
                        onClick={() => setViewMode('list')}
                        style={{ background: viewMode === 'list' ? '#292524' : '#1c1917', border: '1px solid #292524', padding: '8px', borderRadius: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', transition: 'background 0.2s' }}
                    >
                        <Menu size={16} color={viewMode === 'list' ? "#ffffff" : "#d6d3d1"} />
                    </div>
                    <div 
                        onClick={() => setViewMode('kanban')}
                        style={{ background: viewMode === 'kanban' ? '#292524' : '#1c1917', border: '1px solid #292524', padding: '8px', borderRadius: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', transition: 'background 0.2s' }}
                    >
                        <Grid size={16} color={viewMode === 'kanban' ? "#ffffff" : "#d6d3d1"} />
                    </div>
                    <button 
                        onClick={handleExport}
                        style={{ background: '#1c1917', border: '1px solid #292524', color: '#e7e5e4', padding: '8px 16px', borderRadius: '6px', fontSize: '13px', fontWeight: '500', cursor: 'pointer', transition: 'background 0.2s' }}
                        onMouseOver={(e) => e.currentTarget.style.background = '#292524'}
                        onMouseOut={(e) => e.currentTarget.style.background = '#1c1917'}
                    >
                        Export
                    </button>
                    <div 
                        onClick={handleExport}
                        style={{ background: '#1c1917', border: '1px solid #292524', padding: '8px', borderRadius: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', transition: 'background 0.2s' }}
                        onMouseOver={(e) => e.currentTarget.style.background = '#292524'}
                        onMouseOut={(e) => e.currentTarget.style.background = '#1c1917'}
                    >
                        <Download size={16} color="#d6d3d1" />
                    </div>
                </div>
            </div>

            {/* Filter Bar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
                {activeFilter && (
                    <div style={{ display: 'flex', alignItems: 'center', background: '#1c1917', border: '1px solid #292524', padding: '8px 12px', borderRadius: '6px', fontSize: '12px', color: '#e7e5e4' }}>
                        <span style={{ color: '#a8a29e', marginRight: '4px' }}>Team</span> is Cyfocus primary
                        <X size={14} style={{ marginLeft: '12px', color: '#a8a29e', cursor: 'pointer' }} onClick={() => setActiveFilter(null)} />
                    </div>
                )}
                <div 
                    onClick={() => setActiveFilter(activeFilter ? null : 'Team is Cyfocus primary')}
                    style={{ background: '#1c1917', border: '1px solid #292524', padding: activeFilter ? '8px' : '8px 12px', borderRadius: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', color: '#d6d3d1', fontSize: '12px', gap: '6px', transition: 'background 0.2s' }}
                    onMouseOver={(e) => e.currentTarget.style.background = '#292524'}
                    onMouseOut={(e) => e.currentTarget.style.background = '#1c1917'}
                >
                    <SlidersHorizontal size={14} color="#d6d3d1" /> { !activeFilter && 'Add Filter' }
                </div>
            </div>

            {/* Kanban Board Area */}
            <DragDropContext onDragEnd={onDragEnd}>
                <div className={styles['kanban-board']} style={{ display: 'flex', flex: 1, paddingBottom: '16px' }}>
                    {Object.entries(columns).map(([colId, col]) => (
                        <div key={colId} className={styles['kanban-col']} style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', borderRadius: '12px', padding: '12px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px', fontSize: '13px', fontWeight: 'bold', color: col.iconColor }}>
                                {renderColumnIcon(col.iconType, col.iconColor)}
                                <span style={{ color: '#e7e5e4' }}>{col.title}</span>
                                <span style={{ color: '#78716c', fontWeight: 'normal' }}>({col.count})</span>
                            </div>

                            <Droppable droppableId={colId}>
                                {(provided, snapshot) => (
                                    <div
                                        {...provided.droppableProps}
                                        ref={provided.innerRef}
                                        style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}
                                    >
                                        {col.items.map((item, index) => (
                                            <Draggable key={item.id} draggableId={item.id} index={index}>
                                                {(provided, snapshot) => (
                                                    <div
                                                        ref={provided.innerRef}
                                                        {...provided.draggableProps}
                                                        {...provided.dragHandleProps}
                                                        onClick={() => setSelectedCard(item)}
                                                        className={styles['kanban-card']}
                                                        style={{
                                                            ...provided.draggableProps.style,
                                                            display: 'flex',
                                                            flexDirection: 'column',
                                                            gap: '12px',
                                                            boxShadow: snapshot.isDragging ? '0 8px 16px rgba(0,0,0,0.5)' : 'none',
                                                        }}
                                                    >
                                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', color: '#e7e5e4', fontWeight: '500' }}>
                                                                <div style={{ width: '6px', height: '6px', background: item.dot, borderRadius: '1px' }}></div>
                                                                {item.id}
                                                                {item.badge && <span style={{ background: item.badgeColor || '#ef4444', color: '#fff', fontSize: '10px', padding: '2px 6px', borderRadius: '4px', marginLeft: '6px' }}>{item.badge}</span>}
                                                            </div>
                                                            <MoreHorizontal size={14} color="#78716c" />
                                                        </div>
                                                        <div style={{ fontSize: '12px', color: '#a8a29e' }}>
                                                            {item.subtitle}
                                                        </div>

                                                        {item.hasImg && (
                                                            <div style={{ width: '100%', height: '80px', borderRadius: '6px', border: '1px solid #292524', overflow: 'hidden', position: 'relative' }}>
                                                                {/* Faux graph image mimicking the specific graph visualizations */}
                                                                <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(circle at center, #292524 0%, #1c1917 100%)' }}></div>
                                                                <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '40px', height: '40px', border: '1px solid #fa4516', borderRadius: '50%', opacity: 0.5 }}></div>
                                                                <div style={{ position: 'absolute', top: '40%', left: '60%', width: '16px', height: '16px', background: '#fa4516', borderRadius: '50%' }}></div>
                                                                <div style={{ position: 'absolute', top: '60%', left: '40%', width: '12px', height: '12px', background: '#fa4516', borderRadius: '50%' }}></div>
                                                                <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
                                                                    <line x1="40%" y1="60%" x2="60%" y2="40%" stroke="#fa4516" strokeDasharray="2 2" />
                                                                </svg>
                                                            </div>
                                                        )}

                                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#78716c' }}>
                                                                <Calendar size={12} /> {item.date}
                                                            </div>
                                                            <div style={{ width: '22px', height: '22px', borderRadius: '4px', background: item.initBg, color: '#fff', fontSize: '10px', fontWeight: 'bold', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                                                {item.init}
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                            </Draggable>
                                        ))}
                                        {provided.placeholder}
                                    </div>
                                )}
                            </Droppable>
                        </div>
                    ))}
                </div>
            </DragDropContext>

            {/* Details Overlay Drawer */}
            {selectedCard && (() => {
                const currentColumnEntry = Object.entries(columns).find(([_, col]) => col.items.some(i => i.id === selectedCard.id));
                const currentColumn = currentColumnEntry ? currentColumnEntry[1] : Object.values(columns)[0];
                let parsedCvssStr = selectedCard.subtitle?.split(' • ')[1];
                let cvssStr = parsedCvssStr && !isNaN(parseFloat(parsedCvssStr)) ? parsedCvssStr : (selectedCard.badge === 'CRIT' ? '9.8' : (selectedCard.badge === 'HIGH' ? '8.8' : '5.0'));
                const cvss = parseFloat(cvssStr);
                const severity = cvss >= 9.0 ? 'Critical' : (cvss >= 7.0 ? 'High' : (cvss >= 4.0 ? 'Medium' : 'Low'));
                const severityColor = cvss >= 9.0 ? '#ef4444' : (cvss >= 7.0 ? '#fa4516' : (cvss >= 4.0 ? '#eab308' : '#22c55e'));
                const initialsMap = { 'MV': 'Monisha varma', 'KK': 'Kushal Kumar', 'DK': 'Divyansha Kaushik', 'NM': 'Nandini Mahesh', 'NA': 'Nina Adams', 'IS': 'Ilaya Sanders', 'AR': 'Arjun Reddy', 'LL': 'Liam Lee', 'MS': 'Mike Stern', 'WF': 'Will Ford' };
                const assigneeName = initialsMap[selectedCard.init] || 'Unknown Assignee';

                return (
                <div style={{
                    position: 'absolute',
                    top: 0,
                    right: 0,
                    width: '380px',
                    height: '100%',
                    background: 'rgba(28, 25, 23, 0.8)',
                    backdropFilter: 'blur(20px)',
                    WebkitBackdropFilter: 'blur(20px)',
                    borderLeft: '1px solid rgba(255, 255, 255, 0.05)',
                    padding: '24px',
                    display: 'flex',
                    flexDirection: 'column',
                    color: '#e7e5e4',
                    overflowY: 'auto',
                    zIndex: 100,
                    boxShadow: '-10px 0 30px rgba(0,0,0,0.5)',
                    borderTopLeftRadius: '16px',
                    borderBottomLeftRadius: '16px',
                    animation: 'slideIn 0.3s ease-out forwards'
                }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
                        <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '400' }}>{selectedCard.id}</h3>
                        <button onClick={() => setSelectedCard(null)} style={{ background: 'transparent', border: 'none', color: '#a8a29e', cursor: 'pointer', padding: '4px' }}>
                            <X size={18} />
                        </button>
                    </div>

                    <div style={{ display: 'flex', gap: '12px', marginBottom: '32px' }}>
                        <button style={{ flex: 1, background: '#fa4516', color: 'white', border: 'none', padding: '10px 0', borderRadius: '6px', fontSize: '13px', fontWeight: '600', cursor: 'pointer' }}>
                            Resolved
                        </button>
                        <button style={{ flex: 1, background: 'transparent', color: '#e7e5e4', border: '1px solid #3f3f46', padding: '10px 0', borderRadius: '6px', fontSize: '13px', fontWeight: '500', cursor: 'pointer' }}
                            onMouseOver={(e) => { e.currentTarget.style.borderColor = '#52525b'; e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                            onMouseOut={(e) => { e.currentTarget.style.borderColor = '#3f3f46'; e.currentTarget.style.background = 'transparent'; }}
                        >
                            Request Retest
                        </button>
                    </div>

                    <div style={{ marginBottom: '32px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#e7e5e4', fontSize: '14px', fontWeight: '600', marginBottom: '20px' }}>
                            <Info size={16} color="#a8a29e" /> Summary
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '12px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ color: '#78716c', fontWeight: '600', letterSpacing: '0.5px' }}>STATUS:</span>
                                <span style={{ color: '#d6d3d1', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <div style={{ width: '12px', height: '12px', borderRadius: '50%', border: `1.5px solid ${currentColumn.iconColor}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><div style={{ width: '4px', height: '4px', background: currentColumn.iconColor, borderRadius: '50%' }}></div></div>
                                    {currentColumn.title} <span style={{ fontSize: '10px', color: '#78716c' }}>▼</span>
                                </span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ color: '#78716c', fontWeight: '600', letterSpacing: '0.5px' }}>ASSET:</span>
                                <span style={{ color: '#d6d3d1' }}>{selectedCard.subtitle?.split(' • ')[0] || selectedCard.id}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ color: '#78716c', fontWeight: '600', letterSpacing: '0.5px' }}>SEVERITY:</span>
                                <span style={{ color: '#d6d3d1', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <div style={{ width: '8px', height: '8px', background: severityColor, borderRadius: '1px' }}></div> {severity}
                                </span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ color: '#78716c', fontWeight: '600', letterSpacing: '0.5px' }}>CVSS:</span>
                                <span style={{ color: '#d6d3d1' }}>{cvssStr}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ color: '#78716c', fontWeight: '600', letterSpacing: '0.5px' }}>ASSIGNED TO:</span>
                                <span style={{ color: '#d6d3d1', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <div style={{ background: '#713f12', color: '#fcd34d', borderRadius: '4px', fontSize: '10px', fontWeight: 'bold', padding: '2px 4px' }}>{selectedCard.init || 'IS'}</div> {assigneeName}
                                </span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ color: '#78716c', fontWeight: '600', letterSpacing: '0.5px' }}>FIX DATE:</span>
                                <span style={{ color: '#d6d3d1' }}>{selectedCard.date}</span>
                            </div>
                            <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)', marginTop: '8px' }}></div>
                        </div>
                    </div>

                    <div style={{ marginBottom: '32px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#e7e5e4', fontSize: '14px', fontWeight: '600', marginBottom: '20px' }}>
                            <FileText size={16} color="#a8a29e" /> Evidence
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            {[
                                { name: 'pii-scan.csv', size: '0.75 MB' },
                                { name: 'dsar-log.csv', size: '1.7 MB' },
                                { name: 'breach-note.docx', size: '1.8 MB' }
                            ].map((file, idx) => (
                                <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                                        <div style={{ marginTop: '2px', color: '#78716c' }}><FileText size={16} /></div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                            <span style={{ fontSize: '13px', color: '#a8a29e' }}>{file.name}</span>
                                            <span style={{ fontSize: '10px', color: '#78716c' }}>{file.size}</span>
                                        </div>
                                    </div>
                                    <MoreHorizontal size={14} color="#78716c" style={{ cursor: 'pointer' }} />
                                </div>
                            ))}
                            <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)', marginTop: '8px' }}></div>
                            <button style={{ width: '100%', marginTop: '8px', background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', border: '1px solid rgba(59, 130, 246, 0.3)', padding: '10px 0', borderRadius: '6px', fontSize: '13px', fontWeight: '500', cursor: 'pointer', transition: 'all 0.2s' }}
                                onMouseOver={(e) => { e.currentTarget.style.background = 'rgba(59, 130, 246, 0.15)'; }}
                                onMouseOut={(e) => { e.currentTarget.style.background = 'rgba(59, 130, 246, 0.1)'; }}
                                onClick={() => onCheckEvidence && onCheckEvidence(selectedCard)}
                            >
                                Check the runtime evidence
                            </button>
                        </div>
                    </div>

                    <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#e7e5e4', fontSize: '14px', fontWeight: '600', marginBottom: '20px' }}>
                            <Clock size={16} color="#a8a29e" /> History
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                            {[
                                { action: `Status changed to ${currentColumn.title}`, user: assigneeName, time: '2 hours ago', iconColor: currentColumn.iconColor },
                                { action: `Assigned to ${assigneeName}`, user: 'System', time: '1 day ago', iconColor: '#3f3f46' },
                                { action: 'Vulnerability Detected', user: 'Scanner Tool', time: '3 days ago', iconColor: '#ef4444' }
                            ].map((event, idx) => (
                                <div key={idx} style={{ display: 'flex', gap: '12px' }}>
                                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                                        <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: event.iconColor, marginTop: '4px', zIndex: 1, boxShadow: `0 0 8px ${event.iconColor}40` }}></div>
                                        {idx !== 2 && <div style={{ width: '2px', flex: 1, background: '#292524', marginTop: '4px', marginBottom: '-4px' }}></div>}
                                    </div>
                                    <div style={{ display: 'flex', flexDirection: 'column', paddingBottom: idx !== 2 ? '20px' : '0' }}>
                                        <span style={{ fontSize: '13px', color: '#e7e5e4', fontWeight: '500' }}>{event.action}</span>
                                        <span style={{ fontSize: '11px', color: '#78716c', marginTop: '2px' }}>{event.user} • {event.time}</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
                );
            })()}

            <style>{`
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `}</style>
        </div>
    );
};

export default KanbanBoard;
