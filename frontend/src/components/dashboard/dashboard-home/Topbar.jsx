import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const Topbar = ({ onLogout }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const [isSettingsOpen, setIsSettingsOpen] = useState(false);
    
    // Map of full paths to IDs for active state logic
    const pathToId = {
        '/dashboard/overview': 'view-overview',
        '/dashboard/findings': 'view-findings',
        '/dashboard/reachability': 'view-reachability',
        '/dashboard/compliance': 'view-compliance',
        '/dashboard/threat-map': 'view-threat-map',
    };

    const activeView = pathToId[location.pathname] || 'view-overview';

    const [avatar, setAvatar] = useState(() => localStorage.getItem('zenix_user_avatar'));
    const [name, setName] = useState(() => localStorage.getItem('zenix_user_name') || 'Admin User');

    useEffect(() => {
        const handleProfileUpdate = () => {
            setAvatar(localStorage.getItem('zenix_user_avatar'));
            setName(localStorage.getItem('zenix_user_name') || 'Admin User');
        };

        window.addEventListener('zenix_profile_updated', handleProfileUpdate);
        return () => window.removeEventListener('zenix_profile_updated', handleProfileUpdate);
    }, []);

    const navItems = [
        { id: 'view-overview', label: 'Dashboard', icon: 'grid', path: '/dashboard/overview' },
        { id: 'view-findings', label: 'Reachable Risks', icon: 'crosshair', path: '/dashboard/findings' },
        { id: 'view-reachability', label: 'Runtime Evidence', icon: 'layers', path: '/dashboard/reachability' },
        { id: 'view-compliance', label: 'VEX', icon: 'shield', path: '/dashboard/compliance' },
        { id: 'view-threat-map', label: 'Threat Map', icon: 'folder', path: '/dashboard/threat-map' },
    ];

    return (
        <nav style={{ position: 'relative', width: '100%', height: '72px', background: '#0a0a10', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 32px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', zIndex: 100 }}>
            {/* Logo */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ fontSize: '18px', fontWeight: '400', letterSpacing: '2px', color: '#e7e5e4', fontFamily: 'sans-serif' }}>
                    Zenix
                </div>
            </div>

            {/* Navigation Links */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255, 255, 255, 0.03)', padding: '6px', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                {navItems.map((item) => {
                    const isActive = activeView === item.id;
                    return (
                        <div
                            key={item.id}
                            onClick={() => navigate(item.path)}
                            style={{
                                padding: '8px 16px',
                                borderRadius: '8px',
                                background: isActive ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                                color: isActive ? '#3b82f6' : '#94a3b8',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                fontSize: '13px',
                                fontWeight: isActive ? '600' : '500',
                                cursor: 'pointer',
                                transition: 'all 0.2s',
                            }}
                        >

                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                {item.icon === 'grid' && <><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></>}
                                {item.icon === 'crosshair' && <><circle cx="12" cy="12" r="10"></circle><line x1="22" y1="12" x2="18" y2="12"></line><line x1="6" y1="12" x2="2" y2="12"></line><line x1="12" y1="6" x2="12" y2="2"></line><line x1="12" y1="22" x2="12" y2="18"></line></>}
                                {item.icon === 'layers' && <><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></>}
                                {item.icon === 'shield' && <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></>}
                                {item.icon === 'folder' && <><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></>}
                            </svg>
                            {item.label}
                        </div>
                    );
                })}
            </div>

            {/* Right Side Icons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                {/* Settings Trigger */}
                <div style={{ position: 'relative' }}>
                    <div 
                        onClick={() => setIsSettingsOpen(!isSettingsOpen)}
                        style={{ 
                            display: 'flex', 
                            alignItems: 'center', 
                            justifyContent: 'center',
                            cursor: 'pointer', 
                            width: '40px',
                            height: '40px',
                            borderRadius: '50%', 
                            transition: 'all 0.2s ease', 
                            background: avatar 
                                ? `url(${avatar}) center/cover` 
                                : isSettingsOpen ? 'rgba(255, 255, 255, 0.1)' : 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)',
                            color: '#fff',
                            border: isSettingsOpen ? '2px solid rgba(255, 255, 255, 0.2)' : '2px solid transparent',
                            fontSize: '16px',
                            fontWeight: '600'
                        }}
                        onMouseOver={(e) => { 
                            if (!isSettingsOpen) {
                                e.currentTarget.style.border = '2px solid rgba(255, 255, 255, 0.2)'; 
                            }
                        }}
                        onMouseOut={(e) => { 
                            if (!isSettingsOpen) {
                                e.currentTarget.style.border = '2px solid transparent'; 
                            }
                        }}
                    >
                        {!avatar && name.charAt(0).toUpperCase()}
                    </div>

                    {/* Dropdown Settings Menu */}
                    {isSettingsOpen && (
                        <div style={{ 
                            position: 'absolute', 
                            top: 'calc(100% + 12px)', 
                            right: 0, 
                            width: '280px', 
                            background: 'rgba(15, 15, 20, 0.85)', 
                            backdropFilter: 'blur(24px)',
                            WebkitBackdropFilter: 'blur(24px)',
                            borderRadius: '16px', 
                            border: '1px solid rgba(255, 255, 255, 0.08)', 
                            boxShadow: '0 12px 48px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.02) inset',
                            display: 'flex', 
                            flexDirection: 'column', 
                            padding: '8px',
                            zIndex: 1000,
                            overflow: 'hidden',
                        }}>
                            <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', marginBottom: '8px' }}>
                                <div style={{ fontSize: '14px', color: '#fff', fontWeight: '600', letterSpacing: '0.3px' }}>Settings</div>
                                <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>Manage your workspace</div>
                            </div>
                            
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                {[
                                    { 
                                        id: 'view-profile-actions',
                                        label: 'Profile Actions', 
                                        desc: 'Manage account details',
                                        path: '/dashboard/settings/profile',
                                        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> 
                                    },
                                    { 
                                        id: 'view-notification-rules',
                                        label: 'Notification Rules', 
                                        desc: 'Customize alert triggers',
                                        path: '/dashboard/settings/notifications',
                                        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg> 
                                    },
                                    { 
                                        id: 'view-api-integrations',
                                        label: 'API Integrations', 
                                        desc: 'Connect external services',
                                        path: '/dashboard/settings/api',
                                        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="14" width="8" height="8" rx="2" ry="2"></rect><path d="M6 14v-4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v4"></path><path d="M14 10v-4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4"></path><path d="M6 14v-4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4"></path></svg> 
                                    },
                                    { 
                                        id: 'view-security-access',
                                        label: 'Security & Access', 
                                        desc: 'Manage roles and keys',
                                        path: '/dashboard/settings/security',
                                        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> 
                                    }
                                ].map((setting, i) => (
                                    <div key={i} style={{ 
                                        padding: '10px 16px', 
                                        borderRadius: '10px', 
                                        display: 'flex', 
                                        alignItems: 'center', 
                                        gap: '14px', 
                                        cursor: 'pointer', 
                                        transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)' 
                                    }}
                                    onClick={() => {
                                        navigate(setting.path);
                                        setIsSettingsOpen(false);
                                    }}
                                    onMouseOver={(e) => { 
                                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.06)'; 
                                        e.currentTarget.querySelector('.icon-wrap').style.color = '#3b82f6';
                                    }}
                                    onMouseOut={(e) => { 
                                        e.currentTarget.style.background = 'transparent'; 
                                        e.currentTarget.querySelector('.icon-wrap').style.color = '#94a3b8';
                                    }}
                                    >

                                        <div className="icon-wrap" style={{ color: '#94a3b8', transition: 'color 0.2s ease', display: 'flex', alignItems: 'center' }}>
                                            {setting.icon}
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                                            <span style={{ fontSize: '13px', fontWeight: '500', color: '#e2e8f0' }}>{setting.label}</span>
                                            <span style={{ fontSize: '11px', color: '#64748b', marginTop: '1px' }}>{setting.desc}</span>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <div style={{ marginTop: '8px', padding: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                <div onClick={onLogout} style={{ 
                                    padding: '10px 16px', 
                                    borderRadius: '10px', 
                                    display: 'flex', 
                                    alignItems: 'center', 
                                    gap: '14px', 
                                    cursor: 'pointer', 
                                    color: '#f87171', 
                                    transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)' 
                                }}
                                onMouseOver={(e) => {
                                    e.currentTarget.style.background = 'rgba(248, 113, 113, 0.1)';
                                    e.currentTarget.style.color = '#ef4444';
                                }}
                                onMouseOut={(e) => {
                                    e.currentTarget.style.background = 'transparent';
                                    e.currentTarget.style.color = '#f87171';
                                }}
                                >
                                    <div style={{ display: 'flex', alignItems: 'center' }}>
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                                    </div>
                                    <span style={{ fontSize: '13px', fontWeight: '500' }}>Log out</span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </nav>
    );
};

export default Topbar;
