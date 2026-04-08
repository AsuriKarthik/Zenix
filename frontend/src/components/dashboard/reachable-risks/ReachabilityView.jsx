import React, { useState } from 'react';
import { User, Code, Bug, ShieldCheck, Flame, Info, AlertTriangle, CheckCircle2, Home, ChevronRight, X, Plus } from 'lucide-react';

const ReachabilityView = ({ vulnerabilityId }) => {
    const [selectedNode, setSelectedNode] = useState(null);

    const nodeDetails = {
        'input': { title: 'User Input', type: 'HTTP Request', desc: 'Untrusted payload injected via HTTP POST body.', raw: 'POST /api/v1/data HTTP/1.1\nHost: example.com' },
        'main': { title: 'main()', type: 'Entry Point', desc: 'Initializes the application and routes the request to the Spring handler.', raw: 'public static void main(String[] args)' },
        'funcA': { title: 'Function A', type: 'Data Parse', desc: 'Deserializes the incoming JSON body without sanitization.', raw: 'ObjectMapper.readValue(req.body)' },
        'safe': { title: 'Safe Path', type: 'Input Sanitized', desc: 'A separate branch where data is validated against a strict schema. No exploit found.', raw: 'if (isValid(userInput)) { ... }' },
        'sink': { title: vulnerabilityId || 'CVE-2023-4863', type: 'Vulnerable Sink', desc: 'The payload triggers remote code execution during the unsafe deserialization step.', raw: 'java.lang.Runtime.exec(payload)' },
    };
    
    // Function details mapped to the user's new icons and statuses
    const reachData = [
        { sig: 'org.apache.log4j.Logger.error', status: 'Exploitable', icon: <Flame size={14} color="#ef4444" />, depth: 3, suppressed: 'No' },
        { sig: 'com.fasterxml.jackson.databind.ObjectMapper', status: 'Vulnerable', icon: <Bug size={14} color="#f97316" />, depth: 2, suppressed: 'No' },
        { sig: 'org.springframework.boot.SpringApplication', status: 'Safe', icon: <ShieldCheck size={14} color="#10b981" />, depth: 0, suppressed: 'Yes (VEX)' },
        { sig: 'io.netty.channel.ChannelHandlerContext', status: 'Exploitable', icon: <Flame size={14} color="#ef4444" />, depth: 5, suppressed: 'No' },
        { sig: 'org.yaml.snakeyaml.Yaml.load', status: 'Safe', icon: <ShieldCheck size={14} color="#10b981" />, depth: 0, suppressed: 'Yes (VEX)' },
    ];

    return (
        <div className="view-section" style={{ display: 'flex', flexDirection: 'column', gap: '8px', paddingBottom: '8px' }}>
            <div className="view-header" style={{ marginBottom: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a8a29e', fontSize: '12px', marginBottom: '4px' }}>
                        <Home size={14} /> <ChevronRight size={14} /> Reachability
                    </div>
                    <h2 style={{ fontSize: '24px', fontWeight: '500', color: '#e7e5e4', margin: 0 }}>
                        Runtime Evidence Visualization Concept
                    </h2>
                </div>
                <button 
                    onClick={() => prompt('generate a report of the final output in which form')}
                    style={{ background: 'rgba(255,255,255,0.1)', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '50%', width: '36px', height: '36px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: '#e2e8f0', transition: 'background 0.2s' }}
                    onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.2)'}
                    onMouseOut={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.1)'}
                    title="Generate Report"
                >
                    <Plus size={20} />
                </button>
            </div>
            
            {/* 1. Top-Level Summary Card */}
            <div style={{ background: 'rgba(15, 15, 25, 0.4)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)', padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <h3 style={{ fontSize: '16px', color: '#e2e8f0', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <AlertTriangle size={18} color="#eab308" /> Runtime Evidence Summary
                </h3>
                <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                    <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '8px', padding: '12px', flex: 1, minWidth: '200px' }}>
                        <div style={{ color: '#94a3b8', fontSize: '11px', letterSpacing: '0.5px' }}>VULNERABLE FUNCTIONS</div>
                        <div style={{ fontSize: '20px', color: '#f97316', fontWeight: '600', marginTop: '4px' }}>7</div>
                        <div style={{ color: '#64748b', fontSize: '11px', marginTop: '2px' }}>observed in runtime</div>
                    </div>
                    <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '8px', padding: '12px', flex: 1, minWidth: '200px' }}>
                        <div style={{ color: '#ef4444', fontSize: '11px', letterSpacing: '0.5px' }}>EXPLOIT PATHS</div>
                        <div style={{ fontSize: '20px', color: '#ef4444', fontWeight: '600', marginTop: '4px' }}>3</div>
                        <div style={{ color: '#ef4444', opacity: 0.8, fontSize: '11px', marginTop: '2px' }}>confirmed</div>
                    </div>
                    <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.2)', borderRadius: '8px', padding: '12px', flex: 1, minWidth: '200px' }}>
                        <div style={{ color: '#10b981', fontSize: '11px', letterSpacing: '0.5px' }}>SUPPRESSED</div>
                        <div style={{ fontSize: '20px', color: '#10b981', fontWeight: '600', marginTop: '4px' }}>2</div>
                        <div style={{ color: '#10b981', opacity: 0.8, fontSize: '11px', marginTop: '2px' }}>via VEX</div>
                    </div>
                </div>
            </div>

            <div style={{ position: 'relative', background: 'rgba(15, 15, 25, 0.4)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)', padding: '12px 16px', display: 'flex', flexDirection: 'column' }}>
                <h3 style={{ fontSize: '16px', color: '#e2e8f0', margin: '0 0 8px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Info size={18} color="#0ea5e9" /> Exploit Path Trace
                </h3>
                
                <style>{`
                    @keyframes flowDash {
                        to { stroke-dashoffset: -24; }
                    }
                    @keyframes alertPulse {
                        0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.5); border-color: rgba(239, 68, 68, 0.8); }
                        70% { box-shadow: 0 0 0 16px rgba(239, 68, 68, 0); border-color: rgba(239, 68, 68, 0.3); }
                        100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); border-color: rgba(239, 68, 68, 0.8); }
                    }
                    @keyframes slideUp {
                        from { transform: translateY(10px); opacity: 0; }
                        to { transform: translateY(0); opacity: 1; }
                    }
                    .custom-trace-node {
                        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                        cursor: pointer;
                    }
                    .custom-trace-node:hover {
                        transform: translateY(-4px);
                        filter: brightness(1.2);
                        z-index: 10;
                    }
                `}</style>

                <div style={{ position: 'relative', width: '100%', padding: '24px 0 32px 0', background: 'radial-gradient(circle at center, rgba(30, 41, 59, 0.4) 0%, transparent 70%)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.02)', display: 'flex', alignItems: 'center', overflow: 'hidden', gap: '4px' }}>
                    <div style={{ margin: 'auto' }} />

                    <div className="custom-trace-node" onClick={() => setSelectedNode('input')} style={{ background: 'linear-gradient(145deg, #1e2433, #0f131c)', border: '1px solid #3b82f640', borderRadius: '12px', width: '130px', padding: '16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 2 }}>
                        <div style={{ background: '#3b82f620', padding: '8px', borderRadius: '50%', color: '#3b82f6' }}><User size={18} /></div>
                        <div style={{ textAlign: 'center' }}>
                            <div style={{ color: '#f1f5f9', fontSize: '13px', fontWeight: '600' }}>User Input</div>
                            <div style={{ color: '#94a3b8', fontSize: '10px', marginTop: '2px' }}>HTTP Request</div>
                        </div>
                    </div>

                    <svg width="40" height="40" viewBox="0 0 40 40" style={{ overflow: 'visible', flexShrink: 0 }}>
                        <line x1="0" y1="20" x2="40" y2="20" stroke="#3b82f6" strokeWidth="2.5" strokeDasharray="6 4" style={{ animation: 'flowDash 1s linear infinite' }} />
                        <circle cx="40" cy="20" r="3" fill="#3b82f6" />
                    </svg>

                    <div className="custom-trace-node" onClick={() => setSelectedNode('main')} style={{ background: 'linear-gradient(145deg, #1e2433, #0f131c)', border: '1px solid #3b82f640', borderRadius: '12px', width: '130px', padding: '16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 2 }}>
                        <div style={{ background: '#3b82f620', padding: '8px', borderRadius: '50%', color: '#3b82f6' }}><Code size={18} /></div>
                        <div style={{ textAlign: 'center' }}>
                            <div style={{ color: '#f1f5f9', fontSize: '13px', fontWeight: '600' }}>main()</div>
                            <div style={{ color: '#94a3b8', fontSize: '10px', marginTop: '2px' }}>Entry Point</div>
                        </div>
                    </div>

                    <svg width="50" height="124" viewBox="0 -5 50 134" style={{ overflow: 'visible', flexShrink: 0 }}>
                        <path d="M 0 62 C 25 62, 25 0, 50 0" fill="none" stroke="#f97316" strokeWidth="2.5" strokeDasharray="6 4" style={{ animation: 'flowDash 1s linear infinite' }} />
                        <path d="M 0 62 C 25 62, 25 124, 50 124" fill="none" stroke="#10b981" strokeWidth="2.5" />
                        <circle cx="0" cy="62" r="3" fill="#3b82f6" />
                        <circle cx="50" cy="0" r="3" fill="#f97316" />
                        <circle cx="50" cy="124" r="3" fill="#10b981" />
                    </svg>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', flexShrink: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <div className="custom-trace-node" onClick={() => setSelectedNode('funcA')} style={{ background: 'linear-gradient(145deg, #2a1b18, #160f0d)', border: '1px solid #f9731640', borderRadius: '12px', width: '130px', padding: '16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 2 }}>
                                <div style={{ background: '#f9731620', padding: '8px', borderRadius: '50%', color: '#f97316' }}><Code size={18} /></div>
                                <div style={{ textAlign: 'center' }}>
                                    <div style={{ color: '#f1f5f9', fontSize: '13px', fontWeight: '600' }}>Function A</div>
                                    <div style={{ color: '#94a3b8', fontSize: '10px', marginTop: '2px' }}>Data Parse</div>
                                </div>
                            </div>

                            <svg width="40" height="40" viewBox="0 0 40 40" style={{ overflow: 'visible', flexShrink: 0 }}>
                                <line x1="0" y1="20" x2="40" y2="20" stroke="#ef4444" strokeWidth="2.5" />
                                <circle cx="20" cy="20" r="4" fill="#ef4444" style={{ animation: 'alertPulse 1.5s infinite' }} />
                                <circle cx="40" cy="20" r="3" fill="#ef4444" />
                            </svg>

                            <div className="custom-trace-node" onClick={() => setSelectedNode('sink')} style={{ background: 'linear-gradient(145deg, #301618, #190a0c)', border: '1px solid #ef444480', borderRadius: '12px', width: '140px', padding: '16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', animation: 'alertPulse 2s infinite', zIndex: 2 }}>
                                <div style={{ background: '#ef444420', padding: '8px', borderRadius: '50%', color: '#ef4444' }}><Bug size={18} /></div>
                                <div style={{ textAlign: 'center' }}>
                                    <div style={{ color: '#f1f5f9', fontSize: '13px', fontWeight: '600' }}>{vulnerabilityId || 'CVE-2023-4863'}</div>
                                    <div style={{ color: '#ef4444', fontSize: '10px', marginTop: '2px', fontWeight: '500' }}>Vulnerable Sink</div>
                                </div>
                            </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <div className="custom-trace-node" onClick={() => setSelectedNode('safe')} style={{ background: 'linear-gradient(145deg, #15251d, #0b1510)', border: '1px solid #10b98140', borderRadius: '12px', width: '130px', padding: '16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', zIndex: 2 }}>
                                <div style={{ background: '#10b98120', padding: '8px', borderRadius: '50%', color: '#10b981' }}><ShieldCheck size={18} /></div>
                                <div style={{ textAlign: 'center' }}>
                                    <div style={{ color: '#f1f5f9', fontSize: '13px', fontWeight: '600' }}>Safe Path</div>
                                    <div style={{ color: '#94a3b8', fontSize: '10px', marginTop: '2px' }}>Input Sanitized</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div style={{ margin: 'auto' }} />
                </div>

                {selectedNode && (() => {
                    const info = nodeDetails[selectedNode];
                    const nodeColors = {
                        'input': '#3b82f6',
                        'main': '#3b82f6',
                        'funcA': '#f97316',
                        'safe': '#10b981',
                        'sink': '#ef4444'
                    };
                    const primaryColor = nodeColors[selectedNode] || '#0ea5e9';
                    
                    return (
                        <div style={{ position: 'absolute', bottom: '24px', right: '24px', width: '360px', background: 'rgba(9, 10, 15, 0.85)', backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', border: `1px solid ${primaryColor}40`, borderRadius: '16px', padding: '24px', boxShadow: `0 20px 40px rgba(0,0,0,0.6), 0 0 20px ${primaryColor}15`, zIndex: 50, animation: 'slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1)' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <div style={{ background: `${primaryColor}20`, padding: '8px', borderRadius: '8px', color: primaryColor, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                        <Info size={18} />
                                    </div>
                                    <div>
                                        <div style={{ color: '#f8fafc', fontWeight: '600', fontSize: '15px', letterSpacing: '0.3px' }}>{info.title}</div>
                                        <div style={{ color: primaryColor, fontSize: '11px', fontWeight: '600', letterSpacing: '0.5px', marginTop: '4px', textTransform: 'uppercase' }}>{info.type}</div>
                                    </div>
                                </div>
                                <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: '50%', padding: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'background 0.2s' }} onClick={() => setSelectedNode(null)} onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.1)'} onMouseOut={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}>
                                    <X size={14} color="#e2e8f0" />
                                </div>
                            </div>
                            
                            <div style={{ height: '1px', background: 'linear-gradient(to right, rgba(255,255,255,0.1) 0%, transparent 100%)', width: '100%', marginBottom: '16px' }} />

                            <p style={{ color: '#cbd5e1', fontSize: '13px', lineHeight: '1.6', margin: '0 0 16px 0', fontWeight: '400' }}>{info.desc}</p>
                            
                            <div style={{ background: '#020617', padding: '12px', borderRadius: '8px', fontSize: '12px', color: '#38bdf8', fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', border: '1px solid rgba(255,255,255,0.05)', boxShadow: 'inset 0 4px 6px rgba(0,0,0,0.5)' }}>
                                {info.raw}
                            </div>
                        </div>
                    );
                })()}

                <div style={{ marginTop: '16px', display: 'flex', gap: '20px', fontSize: '11px', color: '#94a3b8', justifyContent: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div style={{ width: '16px', height: '2px', background: '#3b82f6', borderBottom: '2px dashed #3b82f6' }}></div> Runtime Data Flow</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div style={{ width: '16px', height: '2px', background: '#ef4444' }}></div> Confirmed Exploit Hit</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div style={{ width: '16px', height: '2px', background: '#10b981' }}></div> Validated Safe Route</div>
                </div>
            </div>

            {/* 3. Proof of Context */}
            <div style={{ background: 'rgba(15, 15, 25, 0.4)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <h3 style={{ fontSize: '16px', color: '#e2e8f0', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <CheckCircle2 size={18} color="#0ea5e9" /> Proof of Context (SOC L1)
                </h3>
                
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
                    {/* Static Path */}
                    <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '8px', padding: '16px' }}>
                        <div style={{ color: '#0ea5e9', fontSize: '12px', fontWeight: 'bold' }}>STATIC PATH</div>
                        <div style={{ fontFamily: 'monospace', color: '#e2e8f0', fontSize: '13px', marginTop: '8px', wordBreak: 'break-all' }}>
                            app.go -&gt; net/http -&gt; nghttp2
                        </div>
                    </div>

                    {/* Runtime Reality */}
                    <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '8px', padding: '16px' }}>
                         <div style={{ color: '#f97316', fontSize: '12px', fontWeight: 'bold' }}>RUNTIME REALITY (eBPF)</div>
                         <div style={{ fontFamily: 'monospace', color: '#e2e8f0', fontSize: '13px', marginTop: '8px', wordBreak: 'break-all' }}>
                             PID: 8492 | SYSCALL: sys_connect | DEST: 10.0.4.52:80
                         </div>
                    </div>

                    {/* VEX Attestation */}
                    <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '8px', padding: '16px' }}>
                         <div style={{ color: '#10b981', fontSize: '12px', fontWeight: 'bold' }}>VEX ATTESTATION</div>
                         <div style={{ fontFamily: 'monospace', color: '#e2e8f0', fontSize: '13px', marginTop: '8px', wordBreak: 'break-all' }}>
                             &quot;Vulnerable_Code_Not_Reachable&quot;
                         </div>
                    </div>
                </div>
            </div>

            {/* 4. Function Detail Table */}
            <div style={{ background: 'rgba(15, 15, 25, 0.4)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)', padding: '24px', display: 'flex', flexDirection: 'column' }}>
                <h3 style={{ fontSize: '16px', color: '#e2e8f0', margin: '0 0 16px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Code size={18} color="#8b5cf6" /> Function Details
                </h3>
                <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                        <thead>
                            <tr>
                                <th style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#94a3b8', fontWeight: '500' }}>Function Signature</th>
                                <th style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#94a3b8', fontWeight: '500' }}>Status</th>
                                <th style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#94a3b8', fontWeight: '500' }}>Depth</th>
                                <th style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#94a3b8', fontWeight: '500' }}>Suppression</th>
                            </tr>
                        </thead>
                        <tbody>
                            {reachData.map((item, i) => (
                                <tr key={i} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)', transition: 'background 0.2s', cursor: 'pointer' }} onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'} onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}>
                                    <td style={{ padding: '14px 16px', fontFamily: 'monospace', color: '#e2e8f0' }} title="Click to view full stack trace">{item.sig}</td>
                                    <td style={{ padding: '14px 16px' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: item.status === 'Safe' ? '#10b981' : item.status === 'Vulnerable' ? '#f97316' : '#ef4444', fontWeight: '500' }}>
                                            {item.icon} {item.status}
                                        </div>
                                    </td>
                                    <td style={{ padding: '14px 16px', color: '#94a3b8' }}>{item.depth || '-'}</td>
                                    <td style={{ padding: '14px 16px', color: item.suppressed.includes('Yes') ? '#10b981' : '#94a3b8' }}>{item.suppressed}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default ReachabilityView;
