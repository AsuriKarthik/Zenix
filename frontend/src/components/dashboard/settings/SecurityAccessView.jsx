import React, { useState } from 'react';

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

const SecurityAccessView = () => {
    const [twoFactor, setTwoFactor] = useState(true);

    const sessions = [
        { id: 1, device: 'MacBook Pro · Chrome', location: 'San Francisco, CA (US)', ip: '192.168.1.42', current: true, time: 'Active now' },
        { id: 2, device: 'iPhone 14 Pro · Safari', location: 'San Jose, CA (US)', ip: '172.20.10.4', current: false, time: '2 hours ago' },
        { id: 3, device: 'Windows Desktop · Edge', location: 'Austin, TX (US)', ip: '10.0.0.155', current: false, time: 'Yesterday, 4:30 PM' }
    ];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '800px', color: '#F5F5F5' }}>
            
            {/* Header */}
            <div>
                <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>Security Settings</h3>
                <p style={{ fontSize: '13px', color: '#A1A1AA', margin: '4px 0 0 0' }}>Configure multi-factor authentication controls and audit active sessions.</p>
            </div>

            {/* Authentication Settings */}
            <div style={{ background: '#1E1F23', borderRadius: '18px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '24px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#F5F5F5', margin: '0 0 20px 0' }}>Authentication</h4>
                
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '20px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <div>
                        <h5 style={{ fontSize: '14px', fontWeight: '600', color: '#F5F5F5', margin: '0 0 4px 0' }}>Two-Factor Authentication (2FA)</h5>
                        <p style={{ color: '#A1A1AA', fontSize: '12.5px', margin: 0 }}>Add an extra layer of security to your account using an authenticator app.</p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        {twoFactor && <span style={{ padding: '2px 8px', borderRadius: '6px', background: 'rgba(34, 197, 94, 0.08)', border: '1px solid rgba(34, 197, 94, 0.15)', color: '#22C55E', fontSize: '11px', fontWeight: '600' }}>Enabled</span>}
                        <Toggle active={twoFactor} onChange={() => setTwoFactor(!twoFactor)} />
                    </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '20px' }}>
                    <div>
                        <h5 style={{ fontSize: '14px', fontWeight: '600', color: '#F5F5F5', margin: '0 0 4px 0' }}>Password</h5>
                        <p style={{ color: '#A1A1AA', fontSize: '12.5px', margin: 0 }}>Update your password. Last changed 3 months ago.</p>
                    </div>
                    <button style={{ background: 'transparent', border: '1px solid rgba(255, 255, 255, 0.08)', color: '#F5F5F5', padding: '8px 16px', borderRadius: '14px', fontSize: '12.5px', cursor: 'pointer', transition: 'background-color 0.15s ease' }} onMouseOver={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.04)'} onMouseOut={e => e.currentTarget.style.backgroundColor = 'transparent'}>
                        Update Password
                    </button>
                </div>
            </div>

            {/* Active Sessions */}
            <div style={{ background: '#1E1F23', borderRadius: '18px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                    <div>
                        <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>Active Sessions</h4>
                        <p style={{ color: '#A1A1AA', fontSize: '12.5px', margin: '4px 0 0 0' }}>Manage devices currently logged into your account.</p>
                    </div>
                    <button style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', color: '#EF4444', padding: '8px 16px', borderRadius: '14px', fontSize: '12.5px', fontWeight: '600', cursor: 'pointer', transition: 'all 0.15s ease' }} onMouseOver={e => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)'} onMouseOut={e => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'}>
                        Sign Out All Other Devices
                    </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {sessions.map((session) => (
                        <div key={session.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px', background: '#25272B', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                            <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
                                <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: session.current ? 'rgba(218, 252, 111, 0.1)' : 'rgba(255, 255, 255, 0.04)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: session.current ? '#DAFC6F' : '#A1A1AA' }}>
                                    {session.device.includes('iPhone') ? (
                                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line></svg>
                                    ) : (
                                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                                    )}
                                </div>
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                                        <span style={{ color: '#F5F5F5', fontSize: '13.5px', fontWeight: '600' }}>{session.device}</span>
                                        {session.current && <span style={{ padding: '2px 8px', borderRadius: '12px', background: 'rgba(218, 252, 111, 0.1)', color: '#DAFC6F', fontSize: '10px', fontWeight: '600' }}>Current Session</span>}
                                    </div>
                                    <div style={{ color: '#A1A1AA', fontSize: '12.5px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                                        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg> {session.location}</span>
                                        <span>• {session.ip}</span>
                                    </div>
                                    <div style={{ color: session.current ? '#22C55E' : '#71717A', fontSize: '12px', marginTop: '6px' }}>{session.time}</div>
                                </div>
                            </div>
                            
                            {!session.current && (
                                <button style={{ background: 'transparent', border: 'none', color: '#A1A1AA', fontSize: '12.5px', cursor: 'pointer', padding: '8px', transition: 'color 0.15s ease' }} onMouseOver={e => e.currentTarget.style.color = '#EF4444'} onMouseOut={e => e.currentTarget.style.color = '#A1A1AA'}>
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
