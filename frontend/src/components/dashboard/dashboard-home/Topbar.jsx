import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';

const Topbar = ({ onLogout }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const [isSettingsOpen, setIsSettingsOpen] = useState(false);
    
    const [agentAuth, setAgentAuth] = useState(false);
    const [showAuthModal, setShowAuthModal] = useState(false);
    const [threatInjected, setThreatInjected] = useState(false);

    // Fetch initial access status from the backend
    useEffect(() => {
        fetch('http://localhost:5000/api/system-access/status')
            .then(res => res.json())
            .then(data => {
                setAgentAuth(data.authorized);
                setThreatInjected(data.simulated_threat_active || false);
            })
            .catch(err => console.warn("Agent status fetch failed, using offline simulation:", err));
            
        const handleStatusChanged = () => {
            fetch('http://localhost:5000/api/system-access/status')
                .then(res => res.json())
                .then(data => {
                    setAgentAuth(data.authorized);
                    setThreatInjected(data.simulated_threat_active || false);
                })
                .catch(err => console.warn(err));
        };
        
        window.addEventListener('zenix_agent_state_changed', handleStatusChanged);
        return () => window.removeEventListener('zenix_agent_state_changed', handleStatusChanged);
    }, []);

    const handleToggleAgent = () => {
        if (agentAuth) {
            // Disconnect agent (revoke system access)
            fetch('http://localhost:5000/api/system-access/revoke', { method: 'POST' })
                .then(res => res.json())
                .then(() => {
                    setAgentAuth(false);
                    setThreatInjected(false);
                    // Notify other components to refresh instantly
                    window.dispatchEvent(new Event('zenix_agent_state_changed'));
                })
                .catch(err => console.error("Error revoking access:", err));
        } else {
            // Open authentication prompt modal
            setShowAuthModal(true);
        }
    };

    const handleToggleThreat = () => {
        const nextState = !threatInjected;
        fetch('http://localhost:5000/api/system-access/threat-inject', { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ active: nextState })
        })
        .then(res => res.json())
        .then(data => {
            setThreatInjected(data.simulated_threat_active);
            window.dispatchEvent(new Event('zenix_agent_state_changed'));
        })
        .catch(err => console.error("Error toggling threat injection:", err));
    };

    const handleGrantAccess = () => {
        // Authenticate agent (grant read-only system access)
        fetch('http://localhost:5000/api/system-access/grant', { method: 'POST' })
            .then(res => res.json())
            .then(() => {
                setAgentAuth(true);
                setShowAuthModal(false);
                // Notify other components to refresh instantly
                window.dispatchEvent(new Event('zenix_agent_state_changed'));
            })
            .catch(err => console.error("Error granting access:", err));
    };

    
    // Map of full paths to IDs for active state logic
    const pathToId = {
        '/dashboard/overview': 'view-overview',
        '/dashboard/findings': 'view-findings',
        '/dashboard/reachability': 'view-reachability',
        '/dashboard/compliance': 'view-compliance',
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
        { id: 'view-findings', label: 'Investigation Workspace', icon: 'crosshair', path: '/dashboard/findings' },
        { id: 'view-reachability', label: 'Runtime Evidence', icon: 'layers', path: '/dashboard/reachability' },
        { id: 'view-compliance', label: 'VEX View', icon: 'shield', path: '/dashboard/compliance' },
    ];

    return (
        <nav style={{ position: 'relative', width: '100%', height: '64px', background: '#101211', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 24px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', zIndex: 10000 }}>
            {/* Logo */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ fontSize: '16px', fontWeight: '700', letterSpacing: '1px', color: '#F5F5F5', fontFamily: '"Inter", sans-serif' }}>
                    ZENIX
                </div>
            </div>

            {/* Navigation Links */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'rgba(255, 255, 255, 0.02)', padding: '4px', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                {navItems.map((item) => {
                    const isActive = activeView === item.id;
                    return (
                        <div
                            key={item.id}
                            onClick={() => navigate(item.path)}
                            style={{
                                position: 'relative',
                                padding: '6px 14px',
                                borderRadius: '8px',
                                color: isActive ? '#DAFC6F' : '#A1A1AA',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                fontSize: '13px',
                                fontWeight: '500',
                                cursor: 'pointer',
                                transition: 'color 0.15s ease',
                            }}
                            onMouseOver={(e) => {
                                if (!isActive) e.currentTarget.style.color = '#F5F5F5';
                            }}
                            onMouseOut={(e) => {
                                if (!isActive) e.currentTarget.style.color = '#A1A1AA';
                            }}
                        >
                            {isActive && (
                                <motion.div
                                    layoutId="activeTabPill"
                                    initial={false}
                                    transition={{ type: 'spring', stiffness: 450, damping: 32 }}
                                    style={{
                                        position: 'absolute',
                                        inset: 0,
                                        background: 'rgba(218, 252, 111, 0.12)',
                                        borderRadius: '8px',
                                        border: '1px solid rgba(218, 252, 111, 0.3)',
                                        boxShadow: '0 0 12px rgba(218, 252, 111, 0.15)',
                                        zIndex: 0,
                                    }}
                                />
                            )}
                            <span style={{ position: 'relative', zIndex: 1, display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    {item.icon === 'grid' && <><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></>}
                                    {item.icon === 'crosshair' && <><circle cx="12" cy="12" r="10"></circle><line x1="22" y1="12" x2="18" y2="12"></line><line x1="6" y1="12" x2="2" y2="12"></line><line x1="12" y1="6" x2="12" y2="2"></line><line x1="12" y1="22" x2="12" y2="18"></line></>}
                                    {item.icon === 'layers' && <><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></>}
                                    {item.icon === 'shield' && <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></>}
                                </svg>
                                {item.label}
                            </span>
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
                            background: '#1E1F23', 
                            borderRadius: '12px', 
                            border: '1px solid rgba(255, 255, 255, 0.08)', 
                            boxShadow: '0 12px 48px rgba(0, 0, 0, 0.4)',
                            display: 'flex', 
                            flexDirection: 'column', 
                            padding: '8px',
                            zIndex: 1000,
                            overflow: 'hidden',
                        }}>
                            <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', marginBottom: '8px' }}>
                                <div style={{ fontSize: '13px', color: '#F5F5F5', fontWeight: '600' }}>Settings</div>
                                <div style={{ fontSize: '11px', color: '#71717A', marginTop: '2px' }}>Manage your workspace</div>
                            </div>

                            {/* HOST AGENT CONNECTION SECTION */}
                            <div style={{ 
                                padding: '12px', 
                                background: '#25272B', 
                                borderRadius: '10px', 
                                border: '1px solid rgba(255, 255, 255, 0.08)', 
                                margin: '0 4px 8px 4px', 
                                display: 'flex', 
                                flexDirection: 'column', 
                                gap: '8px' 
                            }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                    <span style={{ fontSize: '11px', color: '#A1A1AA', fontWeight: '500', textTransform: 'uppercase' }}>Host Connection</span>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: agentAuth ? '#22C55E' : '#EF4444', display: 'inline-block' }}></span>
                                        <span style={{ fontSize: '11px', color: agentAuth ? '#22C55E' : '#EF4444', fontWeight: '600' }}>
                                            {agentAuth ? "Connected" : "Offline"}
                                        </span>
                                    </div>
                                </div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '4px' }}>
                                    <button 
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            handleToggleAgent();
                                        }}
                                        style={{ 
                                            background: agentAuth ? 'rgba(239, 68, 68, 0.1)' : '#DAFC6F', 
                                            border: agentAuth ? '1px solid rgba(239, 68, 68, 0.25)' : 'none', 
                                            color: agentAuth ? '#EF4444' : '#050807', 
                                            padding: '8px 12px', 
                                            borderRadius: '14px', 
                                            fontSize: '11px', 
                                            fontWeight: '600', 
                                            cursor: 'pointer',
                                            transition: 'all 0.2s',
                                            width: '100%',
                                            textAlign: 'center'
                                        }}
                                        onMouseOver={(e) => {
                                            if (agentAuth) {
                                                e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)';
                                            } else {
                                                e.currentTarget.style.background = '#E6FF85';
                                            }
                                        }}
                                        onMouseOut={(e) => {
                                            if (agentAuth) {
                                                e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)';
                                            } else {
                                                e.currentTarget.style.background = '#DAFC6F';
                                            }
                                        }}
                                    >
                                        {agentAuth ? "Disconnect Agent" : "Authenticate Host"}
                                    </button>

                                    {agentAuth && (
                                        <button 
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                handleToggleThreat();
                                            }}
                                            style={{ 
                                                background: threatInjected ? 'rgba(239, 68, 68, 0.1)' : 'rgba(255, 255, 255, 0.04)', 
                                                border: `1px solid ${threatInjected ? '#EF4444' : 'rgba(255, 255, 255, 0.08)'}`, 
                                                color: threatInjected ? '#EF4444' : '#A1A1AA', 
                                                padding: '8px 12px', 
                                                borderRadius: '14px', 
                                                fontSize: '11px', 
                                                fontWeight: '600', 
                                                cursor: 'pointer',
                                                transition: 'all 0.2s',
                                                width: '100%',
                                                textAlign: 'center'
                                            }}
                                            onMouseOver={(e) => {
                                                e.currentTarget.style.background = threatInjected ? 'rgba(239, 68, 68, 0.15)' : 'rgba(255, 255, 255, 0.08)';
                                            }}
                                            onMouseOut={(e) => {
                                                e.currentTarget.style.background = threatInjected ? 'rgba(239, 68, 68, 0.1)' : 'rgba(255, 255, 255, 0.04)';
                                            }}
                                        >
                                            {threatInjected ? "Remove Injector" : "Inject Test Threat"}
                                        </button>
                                    )}
                                </div>
                            </div>
                            
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                {[
                                    { 
                                        id: 'view-profile-actions',
                                        label: 'Profile Actions', 
                                        desc: 'Manage account details',
                                        path: '/dashboard/settings/profile',
                                        icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> 
                                    },
                                    { 
                                        id: 'view-notification-rules',
                                        label: 'Notification Rules', 
                                        desc: 'Customize alert triggers',
                                        path: '/dashboard/settings/notifications',
                                        icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg> 
                                    },
                                    { 
                                        id: 'view-api-integrations',
                                        label: 'API Integrations', 
                                        desc: 'Connect external services',
                                        path: '/dashboard/settings/api',
                                        icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="14" width="8" height="8" rx="2" ry="2"></rect><path d="M6 14v-4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v4"></path><path d="M14 10v-4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4"></path><path d="M6 14v-4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4"></path></svg> 
                                    },
                                    { 
                                        id: 'view-security-access',
                                        label: 'Security & Access', 
                                        desc: 'Manage roles and keys',
                                        path: '/dashboard/settings/security',
                                        icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> 
                                    }
                                ].map((setting, i) => (
                                    <div key={i} style={{ 
                                        padding: '8px 12px', 
                                        borderRadius: '8px', 
                                        display: 'flex', 
                                        alignItems: 'center', 
                                        gap: '12px', 
                                        cursor: 'pointer', 
                                        transition: 'all 0.15s ease' 
                                    }}
                                    onClick={() => {
                                        navigate(setting.path);
                                        setIsSettingsOpen(false);
                                    }}
                                    onMouseOver={(e) => { 
                                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)'; 
                                        e.currentTarget.querySelector('.icon-wrap').style.color = '#F5F5F5';
                                    }}
                                    onMouseOut={(e) => { 
                                        e.currentTarget.style.background = 'transparent'; 
                                        e.currentTarget.querySelector('.icon-wrap').style.color = '#A1A1AA';
                                    }}
                                    >
                                        <div className="icon-wrap" style={{ color: '#A1A1AA', transition: 'color 0.15s ease', display: 'flex', alignItems: 'center' }}>
                                            {setting.icon}
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                                            <span style={{ fontSize: '13px', fontWeight: '500', color: '#F5F5F5' }}>{setting.label}</span>
                                            <span style={{ fontSize: '11px', color: '#71717A', marginTop: '1px' }}>{setting.desc}</span>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <div style={{ marginTop: '8px', padding: '6px 4px 4px 4px', borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}>
                                <div onClick={onLogout} style={{ 
                                    padding: '8px 12px', 
                                    borderRadius: '8px', 
                                    display: 'flex', 
                                    alignItems: 'center', 
                                    gap: '12px', 
                                    cursor: 'pointer', 
                                    color: '#EF4444', 
                                    transition: 'all 0.15s ease' 
                                }}
                                onMouseOver={(e) => {
                                    e.currentTarget.style.background = 'rgba(239, 68, 68, 0.08)';
                                }}
                                onMouseOut={(e) => {
                                    e.currentTarget.style.background = 'transparent';
                                }}
                                >
                                    <div style={{ display: 'flex', alignItems: 'center' }}>
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                                    </div>
                                    <span style={{ fontSize: '13px', fontWeight: '500' }}>Log out</span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {showAuthModal && (
                <div style={{
                    position: 'fixed',
                    top: 0, left: 0, right: 0, bottom: 0,
                    background: 'rgba(0, 0, 0, 0.85)',
                    backdropFilter: 'blur(8px)',
                    WebkitBackdropFilter: 'blur(8px)',
                    zIndex: 99999,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '20px'
                }} onClick={() => setShowAuthModal(false)}>
                    <div style={{
                        background: '#1E1F23',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '18px',
                        padding: '32px',
                        width: '100%',
                        maxWidth: '460px',
                        boxShadow: '0 25px 50px rgba(0, 0, 0, 0.6)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '16px'
                    }} onClick={(e) => e.stopPropagation()}>
                        <h3 style={{ fontSize: '18px', fontWeight: '600', margin: 0, color: '#F5F5F5', display: 'flex', alignItems: 'center', gap: '8px', letterSpacing: '-0.3px' }}>
                            🔑 Host Agent Authentication
                        </h3>
                        <p style={{ fontSize: '13.5px', color: '#A1A1AA', margin: 0, lineHeight: '1.5' }}>
                            Zenix is requesting <strong>read-only permissions</strong> to collect active process lists (`psutil`), DLL mappings, and directory sizes from your local host machine. 
                        </p>
                        <div style={{ background: 'rgba(59, 130, 246, 0.05)', border: '1px solid rgba(59, 130, 246, 0.12)', padding: '12px', borderRadius: '8px', fontSize: '12px', color: '#3B82F6', lineHeight: '1.4' }}>
                            🔒 <strong>Strictly Read-Only:</strong> This connection will not execute code, write files, or modify any settings on your Windows computer.
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
                            <button 
                                onClick={() => setShowAuthModal(false)}
                                style={{ background: 'transparent', border: '1px solid rgba(255, 255, 255, 0.08)', color: '#A1A1AA', padding: '8px 16px', borderRadius: '14px', fontSize: '13.5px', cursor: 'pointer', fontWeight: '500' }}
                            >
                                Keep Simulator
                            </button>
                            <button 
                                onClick={handleGrantAccess}
                                style={{ background: '#DAFC6F', border: 'none', color: '#050807', padding: '8px 16px', borderRadius: '14px', fontSize: '13.5px', cursor: 'pointer', fontWeight: '600' }}
                            >
                                Grant Access
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </nav>

    );
};

export default Topbar;
