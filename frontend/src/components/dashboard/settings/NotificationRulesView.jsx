import React, { useState } from 'react';
import { Bell, Plus, Info, X } from 'lucide-react';

const Toggle = ({ active, onChange }) => (
    <div 
        onClick={onChange}
        style={{ 
            width: '40px', 
            height: '22px', 
            borderRadius: '11px', 
            background: active ? '#DAFC6F' : 'rgba(255, 255, 255, 0.08)', 
            position: 'relative', 
            cursor: 'pointer', 
            transition: 'background 0.15s ease',
            display: 'flex',
            alignItems: 'center',
            padding: '2px'
        }}
    >
        <div style={{ 
            width: '18px', 
            height: '18px', 
            borderRadius: '50%', 
            background: active ? '#050807' : '#A1A1AA', 
            boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
            transition: 'transform 0.15s cubic-bezier(0.4, 0, 0.2, 1)',
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', color: '#F5F5F5' }}>
            
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>Notification Rules</h3>
                    <p style={{ fontSize: '13px', color: '#A1A1AA', margin: '4px 0 0 0' }}>Configure notification alerts and messaging triggers.</p>
                </div>
                <button 
                    onClick={() => setIsModalOpen(true)}
                    style={{ background: '#DAFC6F', border: 'none', color: '#050807', padding: '8px 16px', borderRadius: '14px', fontSize: '12.5px', fontWeight: '600', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                    <Plus size={14} /> Add Rule
                </button>
            </div>

            {/* Rules Table Card */}
            <div style={{ background: '#1E1F23', borderRadius: '18px', border: '1px solid rgba(255, 255, 255, 0.08)', overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                        <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', background: '#25272B' }}>
                            <th style={{ padding: '16px 24px', color: '#A1A1AA', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Event / Trigger</th>
                            <th style={{ padding: '16px 24px', color: '#A1A1AA', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', width: '120px', textAlign: 'center' }}>In-App</th>
                            <th style={{ padding: '16px 24px', color: '#A1A1AA', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', width: '120px', textAlign: 'center' }}>Email</th>
                            <th style={{ padding: '16px 24px', color: '#A1A1AA', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', width: '120px', textAlign: 'center' }}>Slack</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rules.map((rule) => (
                            <tr key={rule.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                                <td style={{ padding: '20px 24px' }}>
                                    <div style={{ color: '#F5F5F5', fontSize: '13.5px', fontWeight: '600', marginBottom: '4px' }}>{rule.name}</div>
                                    <div style={{ color: '#A1A1AA', fontSize: '12.5px' }}>{rule.desc}</div>
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

            {/* Smart Digest Mode Banner */}
            <div style={{ background: 'rgba(59, 130, 246, 0.05)', border: '1px solid rgba(59, 130, 246, 0.12)', padding: '16px', borderRadius: '12px', display: 'flex', alignItems: 'flex-start', gap: '16px' }}>
                <div style={{ color: '#3B82F6', marginTop: '2px' }}>
                    <Info size={18} />
                </div>
                <div>
                    <h4 style={{ color: '#93C5FD', fontSize: '13.5px', fontWeight: '600', margin: '0 0 4px 0' }}>Smart Digest Mode Active</h4>
                    <p style={{ color: '#BFDBFE', fontSize: '12.5px', margin: 0, lineHeight: '1.5' }}>When an incident spawns multiple alerts within 5 minutes, Zenix will automatically group them into a single digest to prevent alert fatigue.</p>
                </div>
            </div>

            {/* Custom Rule Modal Overlay */}
            {isModalOpen && (
                <div style={{
                    position: 'fixed',
                    top: 0, left: 0, right: 0, bottom: 0,
                    background: 'rgba(0, 0, 0, 0.85)',
                    backdropFilter: 'blur(8px)',
                    zIndex: 99999,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '20px'
                }} onClick={() => setIsModalOpen(false)}>
                    <div style={{
                        background: '#1E1F23',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '18px',
                        width: '100%',
                        maxWidth: '420px',
                        padding: '24px',
                        boxShadow: '0 25px 50px rgba(0, 0, 0, 0.6)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '16px'
                    }} onClick={(e) => e.stopPropagation()}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <h3 style={{ color: '#F5F5F5', fontSize: '16px', fontWeight: '600', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <Bell size={16} color="#DAFC6F" /> Create Custom Rule
                            </h3>
                            <button 
                                onClick={() => setIsModalOpen(false)}
                                style={{ background: 'transparent', border: 'none', color: '#A1A1AA', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                            >
                                <X size={18} />
                            </button>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                            <div>
                                <label style={{ display: 'block', color: '#A1A1AA', fontSize: '12px', fontWeight: '500', marginBottom: '6px' }}>Rule Name</label>
                                <input 
                                    type="text" 
                                    placeholder="e.g. Critical Node Vulnerability"
                                    value={newRuleName}
                                    onChange={(e) => setNewRuleName(e.target.value)}
                                    style={{ width: '100%', background: '#050807', border: '1px solid rgba(255,255,255,0.08)', color: '#F5F5F5', padding: '10px 12px', borderRadius: '12px', fontSize: '13px', outline: 'none' }}
                                />
                            </div>
                            <div>
                                <label style={{ display: 'block', color: '#A1A1AA', fontSize: '12px', fontWeight: '500', marginBottom: '6px' }}>Description</label>
                                <textarea 
                                    placeholder="Alert triggers when CVSS CVSS score exceeds threshold..."
                                    value={newRuleDesc}
                                    onChange={(e) => setNewRuleDesc(e.target.value)}
                                    rows={3}
                                    style={{ width: '100%', background: '#050807', border: '1px solid rgba(255,255,255,0.08)', color: '#F5F5F5', padding: '10px 12px', borderRadius: '12px', fontSize: '13px', outline: 'none', resize: 'none' }}
                                />
                            </div>
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
                            <button 
                                onClick={() => setIsModalOpen(false)}
                                style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.08)', color: '#A1A1AA', padding: '8px 16px', borderRadius: '14px', fontSize: '12.5px', cursor: 'pointer', fontWeight: '500' }}
                            >
                                Cancel
                            </button>
                            <button 
                                onClick={handleCreateRule}
                                disabled={!newRuleName.trim() || !newRuleDesc.trim()}
                                style={{ 
                                    background: '#DAFC6F', 
                                    border: 'none', 
                                    color: '#050807', 
                                    padding: '8px 16px', 
                                    borderRadius: '14px', 
                                    fontSize: '12.5px', 
                                    fontWeight: '600',
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
