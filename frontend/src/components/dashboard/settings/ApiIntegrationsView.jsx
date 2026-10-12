import React, { useState } from 'react';

const IntegrationCard = ({ name, type, status, icon, description, onToggle }) => {
    const isConnected = status === 'connected';
    return (
        <div style={{ 
            background: '#1E1F23', 
            borderRadius: '18px', 
            border: isConnected ? '1px solid rgba(34, 197, 94, 0.25)' : '1px solid rgba(255, 255, 255, 0.08)', 
            padding: '24px',
            position: 'relative',
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
            transition: 'all 0.15s ease'
        }}>
            {isConnected && (
                <div style={{ position: 'absolute', top: 0, left: 0, width: '4px', height: '100%', background: '#22C55E' }} />
            )}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: '#25272B', border: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '22px' }}>
                    {icon}
                </div>
                {isConnected ? (
                    <span style={{ padding: '2px 8px', borderRadius: '6px', background: 'rgba(34, 197, 94, 0.08)', border: '1px solid rgba(34, 197, 94, 0.15)', color: '#22C55E', fontSize: '11px', fontWeight: '600' }}>Connected</span>
                ) : (
                    <span style={{ padding: '2px 8px', borderRadius: '6px', background: 'rgba(255, 255, 255, 0.04)', border: '1px solid rgba(255, 255, 255, 0.08)', color: '#A1A1AA', fontSize: '11px', fontWeight: '600' }}>Disconnected</span>
                )}
            </div>
            
            <div style={{ flex: 1 }}>
                <h4 style={{ fontSize: '15px', fontWeight: '600', color: '#F5F5F5', margin: '0 0 4px 0' }}>{name}</h4>
                <p style={{ color: '#A1A1AA', fontSize: '12.5px', margin: 0, lineHeight: '1.4' }}>{description}</p>
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px', borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: '12px' }}>
                <span style={{ color: '#71717A', fontSize: '11px', fontWeight: '500' }}>{type}</span>
                <button 
                    onClick={onToggle}
                    style={{ 
                        background: isConnected ? 'rgba(239, 68, 68, 0.1)' : '#DAFC6F', 
                        color: isConnected ? '#EF4444' : '#050807', 
                        border: isConnected ? '1px solid rgba(239, 68, 68, 0.25)' : 'none', 
                        padding: '6px 14px', 
                        borderRadius: '14px', 
                        fontSize: '12px', 
                        fontWeight: '600', 
                        cursor: 'pointer',
                        transition: 'all 0.15s ease'
                    }}
                >
                    {isConnected ? 'Disconnect' : 'Connect'}
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', color: '#F5F5F5' }}>
            
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>API & Integrations</h3>
                    <p style={{ fontSize: '13px', color: '#A1A1AA', margin: '4px 0 0 0' }}>Connect your workflow tools and manage access keys.</p>
                </div>
                <button style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.08)', color: '#F5F5F5', padding: '8px 16px', borderRadius: '14px', fontSize: '13px', cursor: 'pointer', transition: 'background-color 0.15s ease' }} onMouseOver={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.04)'} onMouseOut={e => e.currentTarget.style.backgroundColor = 'transparent'}>
                    Browse Directory
                </button>
            </div>

            {/* Featured Integrations Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '16px' }}>
                {integrations.map((int) => (
                    <IntegrationCard 
                        key={int.id} 
                        {...int} 
                        onToggle={() => toggleIntegration(int.id)} 
                    />
                ))}
            </div>

            {/* Personal Access Tokens Table */}
            <div style={{ background: '#1E1F23', borderRadius: '18px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                    <div>
                        <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>Personal Access Tokens</h4>
                        <p style={{ color: '#A1A1AA', fontSize: '12.5px', margin: '4px 0 0 0' }}>Tokens generated for external API client authentication.</p>
                    </div>
                    <button style={{ background: '#DAFC6F', border: 'none', color: '#050807', padding: '8px 16px', borderRadius: '14px', fontSize: '12.5px', fontWeight: '600', cursor: 'pointer' }}>
                        Generate Token
                    </button>
                </div>

                <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                                <th style={{ padding: '12px', color: '#A1A1AA', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase' }}>Token Name</th>
                                <th style={{ padding: '12px', color: '#A1A1AA', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase' }}>Last Used</th>
                                <th style={{ padding: '12px', color: '#A1A1AA', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase' }}>Expires</th>
                                <th style={{ padding: '12px', color: '#A1A1AA', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', textAlign: 'right' }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                                <td style={{ padding: '14px 12px', color: '#F5F5F5', fontSize: '13px', fontWeight: '600' }}>CI/CD Pipeline Key</td>
                                <td style={{ padding: '14px 12px', color: '#A1A1AA', fontSize: '12.5px' }}>2 hours ago</td>
                                <td style={{ padding: '14px 12px', color: '#A1A1AA', fontSize: '12.5px' }}>Never</td>
                                <td style={{ padding: '14px 12px', textAlign: 'right' }}>
                                    <button style={{ background: 'transparent', border: 'none', color: '#EF4444', fontSize: '12.5px', fontWeight: '600', cursor: 'pointer' }}>Revoke</button>
                                </td>
                            </tr>
                            <tr>
                                <td style={{ padding: '14px 12px', color: '#F5F5F5', fontSize: '13px', fontWeight: '600' }}>Local Dev Script</td>
                                <td style={{ padding: '14px 12px', color: '#A1A1AA', fontSize: '12.5px' }}>Yesterday</td>
                                <td style={{ padding: '14px 12px', color: '#A1A1AA', fontSize: '12.5px' }}>Oct 24, 2026</td>
                                <td style={{ padding: '14px 12px', textAlign: 'right' }}>
                                    <button style={{ background: 'transparent', border: 'none', color: '#EF4444', fontSize: '12.5px', fontWeight: '600', cursor: 'pointer' }}>Revoke</button>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
        </div>
    );
};

export default ApiIntegrationsView;
