import React, { useState } from 'react';

const Toggle = ({ active, onChange }) => (
    <div 
        onClick={onChange}
        style={{ 
            width: '40px', 
            height: '22px', 
            borderRadius: '11px', 
            background: active ? '#10b981' : 'rgba(255, 255, 255, 0.1)', 
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

const SecurityAccessView = () => {
    const [twoFactor, setTwoFactor] = useState(true);

    const sessions = [
        { id: 1, device: 'MacBook Pro · Chrome', location: 'San Francisco, CA (US)', ip: '192.168.1.42', current: true, time: 'Active now' },
        { id: 2, device: 'iPhone 14 Pro · Safari', location: 'San Jose, CA (US)', ip: '172.20.10.4', current: false, time: '2 hours ago' },
        { id: 3, device: 'Windows Desktop · Edge', location: 'Austin, TX (US)', ip: '10.0.0.155', current: false, time: 'Yesterday, 4:30 PM' }
    ];

    return (
        <div style={{ padding: '24px', height: '100%', overflowY: 'auto' }}>
            {/* Authentication Settings */}
            <div style={{ background: 'rgba(15, 15, 20, 0.4)', borderRadius: '16px', border: '1px solid rgba(255, 255, 255, 0.05)', padding: '24px', marginBottom: '24px' }}>
                <h2 style={{ fontSize: '18px', fontWeight: '500', color: '#e2e8f0', marginBottom: '20px' }}>Authentication</h2>
                
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '20px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                    <div>
                        <h3 style={{ fontSize: '15px', fontWeight: '500', color: '#f8fafc', marginBottom: '4px' }}>Two-Factor Authentication (2FA)</h3>
                        <p style={{ color: '#94a3b8', fontSize: '13px' }}>Add an extra layer of security to your account using an authenticator app.</p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        {twoFactor && <span style={{ padding: '4px 10px', borderRadius: '20px', background: 'rgba(16, 185, 129, 0.1)', color: '#34d399', fontSize: '11px', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Enabled</span>}
                        <Toggle active={twoFactor} onChange={() => setTwoFactor(!twoFactor)} />
                    </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '20px' }}>
                    <div>
                        <h3 style={{ fontSize: '15px', fontWeight: '500', color: '#f8fafc', marginBottom: '4px' }}>Password</h3>
                        <p style={{ color: '#94a3b8', fontSize: '13px' }}>Update your password. Last changed 3 months ago.</p>
                    </div>
                    <button style={{ background: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', padding: '8px 16px', borderRadius: '8px', fontSize: '13px', cursor: 'pointer' }}>
                        Update Password
                    </button>
                </div>
            </div>

            {/* Active Sessions */}
            <div style={{ background: 'rgba(15, 15, 20, 0.4)', borderRadius: '16px', border: '1px solid rgba(255, 255, 255, 0.05)', padding: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                    <div>
                        <h2 style={{ fontSize: '18px', fontWeight: '500', color: '#e2e8f0', marginBottom: '4px' }}>Active Sessions</h2>
                        <p style={{ color: '#94a3b8', fontSize: '13px' }}>Manage devices currently logged into your account.</p>
                    </div>
                    <button style={{ background: 'transparent', border: '1px solid rgba(248, 113, 113, 0.3)', color: '#f87171', padding: '8px 16px', borderRadius: '8px', fontSize: '13px', cursor: 'pointer', transition: 'all 0.2s' }} onMouseOver={e => e.currentTarget.style.background = 'rgba(248, 113, 113, 0.1)'} onMouseOut={e => e.currentTarget.style.background = 'transparent'}>
                        Sign Out All Other Devices
                    </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {sessions.map((session, index) => (
                        <div key={session.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.03)' }}>
                            <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
                                <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: session.current ? 'rgba(59, 130, 246, 0.1)' : 'rgba(255, 255, 255, 0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: session.current ? '#60a5fa' : '#94a3b8' }}>
                                    {session.device.includes('iPhone') ? (
                                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line></svg>
                                    ) : (
                                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                                    )}
                                </div>
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                                        <span style={{ color: '#e2e8f0', fontSize: '14px', fontWeight: '500' }}>{session.device}</span>
                                        {session.current && <span style={{ padding: '2px 8px', borderRadius: '12px', background: 'rgba(59, 130, 246, 0.2)', color: '#93c5fd', fontSize: '10px', fontWeight: '600', textTransform: 'uppercase' }}>Current Session</span>}
                                    </div>
                                    <div style={{ color: '#94a3b8', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                                        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg> {session.location}</span>
                                        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>• {session.ip}</span>
                                    </div>
                                    <div style={{ color: session.current ? '#10b981' : '#64748b', fontSize: '12px', marginTop: '6px' }}>{session.time}</div>
                                </div>
                            </div>
                            
                            {!session.current && (
                                <button style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '13px', cursor: 'pointer', padding: '8px' }} onMouseOver={e => e.currentTarget.style.color = '#f87171'} onMouseOut={e => e.currentTarget.style.color = '#94a3b8'}>
                                    Sign Out
                                </button>
                            )}
                        </div>
                    ))}
                </div>
            </div>
            
        </div>
    );
};

export default SecurityAccessView;
