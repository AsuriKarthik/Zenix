import React from 'react';
import { useNavigate, useLocation, Outlet } from 'react-router-dom';

const SettingsLayout = ({ onLogout }) => {
    const navigate = useNavigate();
    const location = useLocation();

    const navItems = [
        { id: 'view-profile-actions', label: 'Profile Actions', path: '/dashboard/settings/profile', icon: <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path> },
        { id: 'view-notification-rules', label: 'Notification Rules', path: '/dashboard/settings/notifications', icon: <><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></> },
        { id: 'view-api-integrations', label: 'API Integrations', path: '/dashboard/settings/api', icon: <><rect x="2" y="14" width="8" height="8" rx="2" ry="2"></rect><path d="M6 14v-4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v4"></path><path d="M14 10v-4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4"></path><path d="M6 14v-4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4"></path></> },
        { id: 'view-security-access', label: 'Security & Access', path: '/dashboard/settings/security', icon: <><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></> },
    ];


    return (
        <div style={{ display: 'flex', height: '100%', width: '100%', overflow: 'hidden' }}>
            {/* Sidebar Navigation */}
            <div style={{ 
                width: '260px', 
                minWidth: '260px',
                borderRight: '1px solid rgba(255, 255, 255, 0.08)', 
                background: '#101211', 
                display: 'flex', 
                flexDirection: 'column',
                justifyContent: 'space-between',
                padding: '24px 16px',
            }}>
                <div>
                    <h2 style={{ fontSize: '11px', fontWeight: '600', color: '#71717A', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '16px', paddingLeft: '12px' }}>Workspace Settings</h2>
                    
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {navItems.map((item) => {
                        const isActive = location.pathname === item.path;
                        return (
                            <button
                                key={item.id}
                                onClick={() => navigate(item.path)}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '12px',
                                    padding: '10px 12px',
                                    borderRadius: '12px',
                                    background: isActive ? 'rgba(218, 252, 111, 0.06)' : 'transparent',
                                    border: 'none',
                                    color: isActive ? '#DAFC6F' : '#A1A1AA',
                                    cursor: 'pointer',
                                    textAlign: 'left',
                                    transition: 'all 0.15s ease',
                                }}
                                onMouseOver={(e) => {
                                    if (!isActive) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)';
                                }}
                                onMouseOut={(e) => {
                                    if (!isActive) e.currentTarget.style.background = 'transparent';
                                }}
                            >
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: isActive ? '#DAFC6F' : '#71717A' }}>
                                    {item.icon}
                                    {item.id === 'view-profile-actions' && <circle cx="12" cy="7" r="4"></circle>}
                                </svg>
                                <span style={{ fontSize: '13px', fontWeight: isActive ? '600' : '500' }}>{item.label}</span>
                            </button>
                        );
                    })}
                </div>
                </div>

                <button
                    onClick={onLogout}
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        padding: '10px 12px',
                        borderRadius: '12px',
                        background: 'transparent',
                        border: 'none',
                        color: '#EF4444',
                        cursor: 'pointer',
                        textAlign: 'left',
                        transition: 'all 0.15s ease',
                        marginTop: 'auto'
                    }}
                    onMouseOver={(e) => {
                        e.currentTarget.style.background = 'rgba(239, 68, 68, 0.08)';
                    }}
                    onMouseOut={(e) => {
                        e.currentTarget.style.background = 'transparent';
                    }}
                >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                        <polyline points="16 17 21 12 16 7"></polyline>
                        <line x1="21" y1="12" x2="9" y2="12"></line>
                    </svg>
                    <span style={{ fontSize: '13px', fontWeight: '600' }}>Log Out</span>
                </button>
            </div>

            {/* Main Content Area */}
            <div style={{ flex: 1, overflowY: 'auto', background: '#050807', padding: '24px 32px' }}>
                <Outlet />
            </div>
        </div>
    );
};


export default SettingsLayout;
