import React, { useState } from 'react';

const Toggle = ({ active, onChange }) => (
    <div 
        onClick={onChange}
        style={{ 
            width: '40px', 
            height: '22px', 
            borderRadius: '11px', 
            background: active ? '#3b82f6' : 'rgba(255, 255, 255, 0.1)', 
            position: 'relative', 
            cursor: 'pointer', 
            transition: 'background 0.2s',
            display: 'flex',
            alignItems: 'center',
            padding: '2px'
        }}
    >
        <div style={{ 
            width: '18px', 
            height: '18px', 
            borderRadius: '50%', 
            background: '#fff', 
            boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
            transition: 'transform 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
            transform: active ? 'translateX(18px)' : 'translateX(0)'
        }} />
    </div>
);

const NotificationRulesView = () => {
    const [rules, setRules] = useState([
        { id: 1, name: 'Critical Vulnerability Detected', desc: 'Alerts when a CVSS 9.0+ vulnerability is found.', email: true, slack: true, inApp: true },
        { id: 2, name: 'New Reachable Risk', desc: 'Alerts when runtime evidence confirms an exploit path.', email: true, slack: false, inApp: true },
        { id: 3, name: 'Compliance Violation (VEX)', desc: 'Alerts when a package fails compliance checks.', email: false, slack: true, inApp: true },
        { id: 4, name: 'Daily Security Digest', desc: 'Summary of the day\'s threats and mitigated risks.', email: true, slack: false, inApp: false },
    ]);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [newRuleName, setNewRuleName] = useState('');
    const [newRuleDesc, setNewRuleDesc] = useState('');

    const toggleRule = (id, channel) => {
        setRules(rules.map(r => r.id === id ? { ...r, [channel]: !r[channel] } : r));
    };

    const handleCreateRule = () => {
        if (!newRuleName.trim() || !newRuleDesc.trim()) return;
        
        const newRule = {
            id: Date.now(),
            name: newRuleName,
            desc: newRuleDesc,
            email: false,
            slack: false,
            inApp: true
        };
        
        setRules([newRule, ...rules]);
        setIsModalOpen(false);
        setNewRuleName('');
        setNewRuleDesc('');
    };

    return (
        <div style={{ padding: '24px', height: '100%', overflowY: 'auto', position: 'relative' }}>
            <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
                <button 
                    onClick={() => setIsModalOpen(true)}
                    style={{ background: '#3b82f6', border: 'none', color: '#fff', padding: '10px 16px', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    Add Custom Rule
                </button>
            </div>

            <div style={{ background: 'rgba(15, 15, 20, 0.4)', borderRadius: '16px', border: '1px solid rgba(255, 255, 255, 0.05)', overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                        <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)', background: 'rgba(255, 255, 255, 0.02)' }}>
                            <th style={{ padding: '16px 24px', color: '#94a3b8', fontSize: '12px', fontWeight: '500', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Event / Trigger</th>
                            <th style={{ padding: '16px 24px', color: '#94a3b8', fontSize: '12px', fontWeight: '500', textTransform: 'uppercase', letterSpacing: '0.5px', width: '120px', textAlign: 'center' }}>In-App</th>
                            <th style={{ padding: '16px 24px', color: '#94a3b8', fontSize: '12px', fontWeight: '500', textTransform: 'uppercase', letterSpacing: '0.5px', width: '120px', textAlign: 'center' }}>Email</th>
                            <th style={{ padding: '16px 24px', color: '#94a3b8', fontSize: '12px', fontWeight: '500', textTransform: 'uppercase', letterSpacing: '0.5px', width: '120px', textAlign: 'center' }}>Slack</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rules.map((rule) => (
                            <tr key={rule.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)' }}>
                                <td style={{ padding: '20px 24px' }}>
                                    <div style={{ color: '#e2e8f0', fontSize: '14px', fontWeight: '500', marginBottom: '4px' }}>{rule.name}</div>
                                    <div style={{ color: '#64748b', fontSize: '13px' }}>{rule.desc}</div>
                                </td>
                                <td style={{ padding: '20px 24px' }}>
                                    <div style={{ display: 'flex', justifyContent: 'center' }}>
                                        <Toggle active={rule.inApp} onChange={() => toggleRule(rule.id, 'inApp')} />
                                    </div>
                                </td>
                                <td style={{ padding: '20px 24px' }}>
                                    <div style={{ display: 'flex', justifyContent: 'center' }}>
                                        <Toggle active={rule.email} onChange={() => toggleRule(rule.id, 'email')} />
                                    </div>
                                </td>
                                <td style={{ padding: '20px 24px' }}>
                                    <div style={{ display: 'flex', justifyContent: 'center' }}>
                                        <Toggle active={rule.slack} onChange={() => toggleRule(rule.id, 'slack')} />
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            
            <div style={{ marginTop: '24px', background: 'rgba(59, 130, 246, 0.05)', border: '1px solid rgba(59, 130, 246, 0.2)', padding: '16px', borderRadius: '12px', display: 'flex', alignItems: 'flex-start', gap: '16px' }}>
                <div style={{ color: '#3b82f6', marginTop: '2px' }}>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                </div>
                <div>
                    <h4 style={{ color: '#bfdbfe', fontSize: '14px', fontWeight: '500', marginBottom: '4px' }}>Smart Digest Mode</h4>
                    <p style={{ color: '#93c5fd', fontSize: '13px', lineHeight: '1.5' }}>When an incident spawns multiple alerts within 5 minutes, Zenix will automatically group them into a single digest to prevent alert fatigue.</p>
                </div>
            </div>

            {/* Custom Rule Modal Overlay */}
            {isModalOpen && (
                <div style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    width: '100vw',
                    height: '100vh',
                    background: 'rgba(5, 5, 8, 0.8)',
                    backdropFilter: 'blur(4px)',
                    zIndex: 1000,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                }}>
                    <div style={{
                        background: '#0f0f14',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        borderRadius: '16px',
                        width: '400px',
                        padding: '24px',
                        boxShadow: '0 24px 48px rgba(0, 0, 0, 0.5)'
                    }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                            <h3 style={{ color: '#fff', fontSize: '18px', fontWeight: '600' }}>Create Custom Rule</h3>
                            <button 
                                onClick={() => setIsModalOpen(false)}
                                style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px' }}
                            >
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                            </button>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '24px' }}>
                            <div>
                                <label style={{ display: 'block', color: '#94a3b8', fontSize: '12px', marginBottom: '6px' }}>Rule Name</label>
                                <input 
                                    type="text" 
                                    placeholder="e.g. AWS S3 Bucket Exposed"
                                    value={newRuleName}
                                    onChange={(e) => setNewRuleName(e.target.value)}
                                    style={{ width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', color: '#fff', padding: '10px 12px', borderRadius: '8px', fontSize: '14px', outline: 'none' }}
                                />
                            </div>
                            <div>
                                <label style={{ display: 'block', color: '#94a3b8', fontSize: '12px', marginBottom: '6px' }}>Description</label>
                                <textarea 
                                    placeholder="Describe when this alert should trigger..."
                                    value={newRuleDesc}
                                    onChange={(e) => setNewRuleDesc(e.target.value)}
                                    rows={3}
                                    style={{ width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', color: '#fff', padding: '10px 12px', borderRadius: '8px', fontSize: '14px', outline: 'none', resize: 'vertical' }}
                                />
                            </div>
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                            <button 
                                onClick={() => setIsModalOpen(false)}
                                style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', color: '#e2e8f0', padding: '8px 16px', borderRadius: '8px', fontSize: '13px', cursor: 'pointer' }}
                            >
                                Cancel
                            </button>
                            <button 
                                onClick={handleCreateRule}
                                disabled={!newRuleName.trim() || !newRuleDesc.trim()}
                                style={{ 
                                    background: '#3b82f6', 
                                    border: 'none', 
                                    color: '#fff', 
                                    padding: '8px 16px', 
                                    borderRadius: '8px', 
                                    fontSize: '13px', 
                                    cursor: newRuleName.trim() && newRuleDesc.trim() ? 'pointer' : 'not-allowed',
                                    opacity: newRuleName.trim() && newRuleDesc.trim() ? 1 : 0.5
                                }}
                            >
                                Create Rule
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default NotificationRulesView;
