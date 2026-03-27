import React, { useState } from 'react';

const IntegrationCard = ({ name, type, status, icon, description, onToggle }) => {
    return (
        <div style={{ 
            background: 'rgba(15, 15, 20, 0.4)', 
            borderRadius: '16px', 
            border: status === 'connected' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(255, 255, 255, 0.05)', 
            padding: '24px',
            position: 'relative',
            overflow: 'hidden',
            transition: 'all 0.2s'
        }}>
            {status === 'connected' && (
                <div style={{ position: 'absolute', top: 0, left: 0, width: '4px', height: '100%', background: '#10b981' }} />
            )}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(255, 255, 255, 0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '24px' }}>
                    {icon}
                </div>
                {status === 'connected' ? (
                    <span style={{ padding: '4px 10px', borderRadius: '20px', background: 'rgba(16, 185, 129, 0.1)', color: '#34d399', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Connected</span>
                ) : (
                    <span style={{ padding: '4px 10px', borderRadius: '20px', background: 'rgba(255, 255, 255, 0.05)', color: '#94a3b8', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Disconnected</span>
                )}
            </div>
            
            <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#f8fafc', marginBottom: '4px' }}>{name}</h3>
            <p style={{ color: '#64748b', fontSize: '13px', marginBottom: '20px', lineHeight: '1.4', height: '36px' }}>{description}</p>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'auto' }}>
                <span style={{ color: '#475569', fontSize: '12px' }}>{type}</span>
                <button 
                    onClick={onToggle}
                    style={{ 
                        background: status === 'connected' ? 'rgba(248, 113, 113, 0.1)' : 'rgba(59, 130, 246, 0.1)', 
                        color: status === 'connected' ? '#f87171' : '#60a5fa', 
                        border: 'none', 
                        padding: '6px 16px', 
                        borderRadius: '6px', 
                        fontSize: '13px', 
                        fontWeight: '500', 
                        cursor: 'pointer',
                        transition: 'all 0.2s'
                    }}
                >
                    {status === 'connected' ? 'Disconnect' : 'Connect'}
                </button>
            </div>
        </div>
    );
};

const ApiIntegrationsView = () => {
    const [integrations, setIntegrations] = useState([
        { id: 1, name: 'Slack', type: 'Messaging', status: 'connected', description: 'Send automated security alerts to Slack channels.', icon: '💬' },
        { id: 2, name: 'Jira', type: 'Issue Tracking', status: 'connected', description: 'Automatically create tickets for reachable risks.', icon: '🎫' },
        { id: 3, name: 'GitHub', type: 'Version Control', status: 'connected', description: 'Sync repository data and automate PR reviews.', icon: '🐙' },
        { id: 4, name: 'Splunk', type: 'SIEM', status: 'disconnected', description: 'Export security logs for centralized monitoring.', icon: '📊' },
        { id: 5, name: 'PagerDuty', type: 'Incident Response', status: 'disconnected', description: 'Trigger on-call schedules for critical events.', icon: '🚨' },
        { id: 6, name: 'GitLab', type: 'Version Control', status: 'disconnected', description: 'Integrate pipeline security gates.', icon: '🦊' }
    ]);

    const toggleIntegration = (id) => {
        setIntegrations(integrations.map(int => 
            int.id === id 
                ? { ...int, status: int.status === 'connected' ? 'disconnected' : 'connected' }
                : int
        ));
    };

    return (
        <div style={{ padding: '24px', height: '100%', overflowY: 'auto' }}>
            <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
                <button style={{ background: '#3b82f6', border: 'none', color: '#fff', padding: '10px 16px', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer' }}>
                    Browse Directory
                </button>
            </div>

            <h2 style={{ fontSize: '16px', fontWeight: '500', color: '#e2e8f0', marginBottom: '16px' }}>Featured Integrations</h2>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '20px', marginBottom: '40px' }}>
                {integrations.map((int) => (
                    <IntegrationCard 
                        key={int.id} 
                        {...int} 
                        onToggle={() => toggleIntegration(int.id)} 
                    />
                ))}
            </div>

            <div style={{ background: 'rgba(15, 15, 20, 0.4)', borderRadius: '16px', border: '1px solid rgba(255, 255, 255, 0.05)', padding: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                    <div>
                        <h2 style={{ fontSize: '16px', fontWeight: '500', color: '#e2e8f0', marginBottom: '4px' }}>Personal Access Tokens</h2>
                        <p style={{ color: '#64748b', fontSize: '13px' }}>Tokens you have generated that can be used to access the Zenix API.</p>
                    </div>
                    <button style={{ background: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', padding: '8px 16px', borderRadius: '8px', fontSize: '13px', cursor: 'pointer' }}>
                        Generate New Token
                    </button>
                </div>

                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                        <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                            <th style={{ padding: '12px 16px', color: '#94a3b8', fontSize: '12px', fontWeight: '500' }}>Token Name</th>
                            <th style={{ padding: '12px 16px', color: '#94a3b8', fontSize: '12px', fontWeight: '500' }}>Last Used</th>
                            <th style={{ padding: '12px 16px', color: '#94a3b8', fontSize: '12px', fontWeight: '500' }}>Expires</th>
                            <th style={{ padding: '12px 16px', color: '#94a3b8', fontSize: '12px', fontWeight: '500', textAlign: 'right' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.02)' }}>
                            <td style={{ padding: '16px', color: '#e2e8f0', fontSize: '14px', fontWeight: '500' }}>CI/CD Pipeline Key</td>
                            <td style={{ padding: '16px', color: '#94a3b8', fontSize: '13px' }}>2 hours ago</td>
                            <td style={{ padding: '16px', color: '#94a3b8', fontSize: '13px' }}>Never</td>
                            <td style={{ padding: '16px', textAlign: 'right' }}>
                                <button style={{ background: 'transparent', border: 'none', color: '#f87171', fontSize: '13px', cursor: 'pointer' }}>Revoke</button>
                            </td>
                        </tr>
                        <tr>
                            <td style={{ padding: '16px', color: '#e2e8f0', fontSize: '14px', fontWeight: '500' }}>Local Dev Script</td>
                            <td style={{ padding: '16px', color: '#94a3b8', fontSize: '13px' }}>Yesterday</td>
                            <td style={{ padding: '16px', color: '#94a3b8', fontSize: '13px' }}>Oct 24, 2026</td>
                            <td style={{ padding: '16px', textAlign: 'right' }}>
                                <button style={{ background: 'transparent', border: 'none', color: '#f87171', fontSize: '13px', cursor: 'pointer' }}>Revoke</button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default ApiIntegrationsView;
