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
                width: '280px', 
                minWidth: '280px',
                borderRight: '1px solid rgba(255, 255, 255, 0.05)', 
                background: 'rgba(10, 10, 15, 0.5)', 
                display: 'flex', 
                flexDirection: 'column',
                justifyContent: 'space-between',
                padding: '24px 16px',
            }}>
                <div>
                    <h2 style={{ fontSize: '13px', fontWeight: '600', color: '#64748b', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '16px', paddingLeft: '12px' }}>Settings</h2>
                    
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
                                    padding: '12px',
                                    borderRadius: '10px',
                                    background: isActive ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
                                    border: 'none',
                                    color: isActive ? '#fff' : '#94a3b8',
                                    cursor: 'pointer',
                                    textAlign: 'left',
                                    transition: 'all 0.2s',
                                }}
                                onMouseOver={(e) => {
                                    if (!isActive) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)';
                                }}
                                onMouseOut={(e) => {
                                    if (!isActive) e.currentTarget.style.background = 'transparent';
                                }}
                            >
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: isActive ? '#3b82f6' : '#64748b' }}>
                                    {item.icon}
                                    {item.id === 'view-profile-actions' && <circle cx="12" cy="7" r="4"></circle>}
                                </svg>
                                <span style={{ fontSize: '14px', fontWeight: isActive ? '500' : '400' }}>{item.label}</span>
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
                        padding: '12px',
                        borderRadius: '10px',
                        background: 'transparent',
                        border: 'none',
                        color: '#f87171',
                        cursor: 'pointer',
                        textAlign: 'left',
                        transition: 'all 0.2s',
                        marginTop: 'auto'
                    }}
                    onMouseOver={(e) => {
                        e.currentTarget.style.background = 'rgba(248, 113, 113, 0.1)';
                    }}
                    onMouseOut={(e) => {
                        e.currentTarget.style.background = 'transparent';
                    }}
                >
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                        <polyline points="16 17 21 12 16 7"></polyline>
                        <line x1="21" y1="12" x2="9" y2="12"></line>
                    </svg>
                    <span style={{ fontSize: '14px', fontWeight: '500' }}>Log Out</span>
                </button>
            </div>

            {/* Main Content Area */}
            <div style={{ flex: 1, overflowY: 'auto', background: 'rgba(5, 5, 8, 0.3)' }}>
                <Outlet />
            </div>
        </div>
    );
};


export default SettingsLayout;
