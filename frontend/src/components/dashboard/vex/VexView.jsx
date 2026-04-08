import React, { useState } from 'react';
import { Download, FileCheck, FileCode, Home, ChevronRight, CheckCircle2, X, AlertTriangle } from 'lucide-react';

const ComplianceView = () => {
    const [selectedDoc, setSelectedDoc] = useState(null);

    const compData = [
        { 
            id: 'VEX-2026-0142', cve: 'CVE-2026-2144', just: 'Vulnerable_Code_Not_Reachable', date: '2026-03-14', icon: <FileCheck size={14} style={{color: '#22c55e'}} />,
            extraInfo: { desc: 'A remote code execution vulnerability exists in the serialization module.', package: 'com.fasterxml.jackson.core:jackson-databind' }
        },
        { 
            id: 'VEX-2026-0138', cve: 'CVE-2026-1882', just: 'Inline_Mitigations_Already_Exist', date: '2026-03-12', icon: <FileCode size={14} style={{color: '#eab308'}} />,
            extraInfo: { desc: 'Denial of Service (DoS) vulnerability due to improper input validation.', package: 'org.yaml:snakeyaml' }
        },
        { 
            id: 'VEX-2026-0135', cve: 'CVE-2025-4752', just: 'Component_Not_Present', date: '2026-03-10', icon: <FileCheck size={14} style={{color: '#22c55e'}} />,
            extraInfo: { desc: 'Path traversal vulnerability leading to unauthorized file access.', package: 'org.apache.tomcat.embed:tomcat-embed-core' }
        },
        { 
            id: 'VEX-2026-0129', cve: 'CVE-2026-1033', just: 'Vulnerable_Code_Not_In_Execute_Path', date: '2026-03-08', icon: <FileCode size={14} style={{color: '#eab308'}} />,
            extraInfo: { desc: 'Cross-Site Scripting (XSS) vulnerability in the rendering engine.', package: 'org.springframework:spring-webmvc' }
        },
        { 
            id: 'VEX-2026-0112', cve: 'CVE-2026-3401', just: 'Vulnerable_Code_Cannot_Be_Controlled_By_Adversary', date: '2026-03-02', icon: <FileCheck size={14} style={{color: '#22c55e'}} />,
            extraInfo: { desc: 'Information disclosure vulnerability due to improper error handling.', package: 'io.netty:netty-codec-http' }
        },
    ];

    return (
        <div className="view-section" style={{ display: 'block', position: 'relative' }}>
            <div className="view-header" style={{ marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a8a29e', fontSize: '12px', marginBottom: '8px' }}>
                    <Home size={14} /> <ChevronRight size={14} /> Compliance
                </div>
                <h2 style={{ fontSize: '24px', fontWeight: '500', color: '#e7e5e4', margin: 0 }}>VEX Compliance Proofs</h2>
            </div>
            
            <div className="glass-panel" style={{ padding: '20px', borderRadius: '12px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr>
                            <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', fontSize: '0.85rem', fontWeight: '500' }}>VEX ID</th>
                            <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', fontSize: '0.85rem', fontWeight: '500' }}>CVE</th>
                            <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', fontSize: '0.85rem', fontWeight: '500' }}>Justification</th>
                            <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', fontSize: '0.85rem', fontWeight: '500' }}>Date</th>
                            <th style={{ textAlign: 'left', padding: '10px 12px', borderBottom: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', fontSize: '0.85rem', fontWeight: '500' }}>Proof</th>
                        </tr>
                    </thead>
                    <tbody>
                        {compData.map((item, i) => (
                            <tr 
                                key={i} 
                                style={{ cursor: 'pointer', transition: 'background 0.2s' }}
                                onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                                onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}
                                onClick={() => setSelectedDoc(item)}
                            >
                                <td style={{ padding: '14px 12px', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', gap: '8px', color: '#e2e8f0', fontSize: '14px' }}>
                                    {item.icon} <span style={{ fontFamily: 'monospace' }}>{item.id}</span>
                                </td>
                                <td style={{ padding: '14px 12px', borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#cbd5e1', fontSize: '14px' }}>{item.cve}</td>
                                <td style={{ padding: '14px 12px', borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#cbd5e1', fontSize: '14px' }}>{item.just}</td>
                                <td style={{ padding: '14px 12px', borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#cbd5e1', fontSize: '14px' }}>{item.date}</td>
                                <td style={{ padding: '14px 12px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                    <button 
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(item, null, 2));
                                            const downloadAnchorNode = document.createElement('a');
                                            downloadAnchorNode.setAttribute("href", dataStr);
                                            downloadAnchorNode.setAttribute("download", `${item.id}_proof.json`);
                                            document.body.appendChild(downloadAnchorNode);
                                            downloadAnchorNode.click();
                                            downloadAnchorNode.remove();
                                        }}
                                        style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px', borderRadius: '6px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#e2e8f0', cursor: 'pointer', transition: 'all 0.2s' }}
                                        onMouseOver={(e) => {
                                            e.currentTarget.style.background = 'rgba(255,255,255,0.1)';
                                            e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)';
                                        }}
                                        onMouseOut={(e) => {
                                            e.currentTarget.style.background = 'rgba(255,255,255,0.05)';
                                            e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)';
                                        }}
                                    >
                                        <Download size={14} /> JSON
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {selectedDoc && (
                <div style={{
                    position: 'fixed',
                    top: 0, left: 0, right: 0, bottom: 0,
                    background: 'rgba(0,0,0,0.6)',
                    backdropFilter: 'blur(4px)',
                    zIndex: 1000,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '20px'
                }} onClick={() => setSelectedDoc(null)}>
                    <div style={{
                        background: '#0f172a', /* Dark slate background matching the site */
                        border: '1px solid #1e293b',
                        borderRadius: '16px',
                        padding: '24px',
                        width: '100%',
                        maxWidth: '540px',
                        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
                        display: 'flex',
                        flexDirection: 'column'
                    }} onClick={(e) => e.stopPropagation()}>
                        
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
                            <div>
                                <h3 style={{ fontSize: '20px', fontWeight: '600', margin: 0, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    VEX Report
                                </h3>
                                <p style={{ fontSize: '13px', color: '#94a3b8', margin: '4px 0 0 0', fontFamily: 'monospace' }}>{selectedDoc.id}</p>
                            </div>
                            <button 
                                onClick={() => setSelectedDoc(null)}
                                style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px', borderRadius: '4px' }}
                                onMouseOver={(e) => e.currentTarget.style.color = '#f8fafc'}
                                onMouseOut={(e) => e.currentTarget.style.color = '#94a3b8'}
                            >
                                <X size={20} />
                            </button>
                        </div>

                        <div style={{ 
                            background: '#1e293b', 
                            borderRadius: '12px', 
                            padding: '20px', 
                            marginBottom: '16px',
                            border: '1px solid #334155'
                        }}>
                            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '16px', alignItems: 'center', marginBottom: '16px' }}>
                                <span style={{ color: '#94a3b8', fontWeight: '500', fontSize: '14px' }}>CVE</span>
                                <span style={{ color: '#f8fafc', fontSize: '14px', fontWeight: '500' }}>{selectedDoc.cve}</span>
                            </div>
                            
                            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '16px', alignItems: 'center', marginBottom: '16px' }}>
                                <span style={{ color: '#94a3b8', fontWeight: '500', fontSize: '14px' }}>Status</span>
                                <span style={{ 
                                    display: 'inline-flex', 
                                    alignItems: 'center', 
                                    gap: '6px', 
                                    padding: '4px 10px', 
                                    background: 'rgba(59, 130, 246, 0.1)', 
                                    border: '1px solid rgba(59, 130, 246, 0.2)', 
                                    borderRadius: '16px', 
                                    color: '#60a5fa', 
                                    fontSize: '13px', 
                                    fontWeight: '500', 
                                    width: 'max-content',
                                }}>
                                    <CheckCircle2 size={14} /> Not_Affected
                                </span>
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '16px', alignItems: 'start', marginBottom: '16px' }}>
                                <span style={{ color: '#94a3b8', fontWeight: '500', fontSize: '14px', marginTop: '2px' }}>Justification</span>
                                <span style={{ color: '#e2e8f0', fontSize: '14px', lineHeight: '1.5' }}>{selectedDoc.just.replace(/_/g, ' ')}</span>
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '16px', alignItems: 'center' }}>
                                <span style={{ color: '#94a3b8', fontWeight: '500', fontSize: '14px' }}>Format</span>
                                <span style={{ color: '#e2e8f0', fontSize: '14px' }}>Machine-readable (JSON) / {selectedDoc.date}</span>
                            </div>
                        </div>

                        {/* Extra Vulnerability Details Section */}
                        <div style={{ 
                            background: 'rgba(239, 68, 68, 0.05)', 
                            borderRadius: '12px', 
                            padding: '16px 20px', 
                            marginBottom: '24px',
                            border: '1px solid rgba(239, 68, 68, 0.1)'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                                <AlertTriangle size={16} color="#f87171" />
                                <h4 style={{ color: '#f87171', fontSize: '14px', fontWeight: '600', margin: 0 }}>Vulnerability Details</h4>
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                <div>
                                    <span style={{ color: '#94a3b8', fontSize: '12px', display: 'block', marginBottom: '4px' }}>Description</span>
                                    <span style={{ color: '#cbd5e1', fontSize: '13px', lineHeight: '1.5', display: 'block' }}>{selectedDoc.extraInfo?.desc}</span>
                                </div>
                                <div>
                                    <span style={{ color: '#94a3b8', fontSize: '12px', display: 'block', marginBottom: '4px' }}>Affected Package</span>
                                    <span style={{ color: '#e2e8f0', fontSize: '13px', fontFamily: 'monospace', background: 'rgba(0,0,0,0.2)', padding: '2px 6px', borderRadius: '4px' }}>{selectedDoc.extraInfo?.package}</span>
                                </div>
                            </div>
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', color: '#64748b', fontSize: '12px', lineHeight: '1.4', maxWidth: '280px' }}>
                                <div style={{
                                    width: '16px',
                                    height: '16px',
                                    borderRadius: '50%',
                                    background: '#334155',
                                    color: '#94a3b8',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    fontSize: '10px',
                                    fontWeight: 'bold',
                                    flexShrink: 0,
                                    marginTop: '2px'
                                }}>i</div>
                                <span>Export for auditors and platforms; stays linked to runtime evidence.</span>
                            </div>

                            <button 
                                onClick={() => {
                                    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(selectedDoc, null, 2));
                                    const downloadAnchorNode = document.createElement('a');
                                    downloadAnchorNode.setAttribute("href", dataStr);
                                    downloadAnchorNode.setAttribute("download", `${selectedDoc.id}_proof.json`);
                                    document.body.appendChild(downloadAnchorNode);
                                    downloadAnchorNode.click();
                                    downloadAnchorNode.remove();
                                }}
                                style={{ 
                                    padding: '8px 16px', 
                                    background: '#3b82f6', 
                                    border: 'none', 
                                    borderRadius: '8px', 
                                    fontSize: '13px', 
                                    fontWeight: '500', 
                                    color: '#ffffff',
                                    display: 'flex', 
                                    alignItems: 'center', 
                                    gap: '6px',
                                    cursor: 'pointer',
                                    transition: 'background 0.2s ease',
                                    boxShadow: '0 4px 6px -1px rgba(59, 130, 246, 0.2), 0 2px 4px -1px rgba(59, 130, 246, 0.1)'
                                }}
                                onMouseOver={(e) => e.currentTarget.style.background = '#2563eb'}
                                onMouseOut={(e) => e.currentTarget.style.background = '#3b82f6'}
                                title="Download JSON Proof"
                            >
                                <Download size={16} /> Export JSON
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ComplianceView;
