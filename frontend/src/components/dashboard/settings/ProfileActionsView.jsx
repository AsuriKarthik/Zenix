import React, { useState, useEffect } from 'react';

const ProfileActionsView = () => {
    // Read initial state from localStorage or use defaults
    const getInitialState = (key, defaultValue) => {
        const saved = localStorage.getItem(key);
        return saved !== null ? saved : defaultValue;
    };

    const [name, setName] = useState(() => getInitialState('zenix_user_name', 'Admin User'));
    const [email, setEmail] = useState(() => getInitialState('zenix_user_email', 'admin@zenix.io'));
    const [avatar, setAvatar] = useState(() => getInitialState('zenix_user_avatar', null));
    const [isSaving, setIsSaving] = useState(false);
    const [saveSuccess, setSaveSuccess] = useState(false);
    const [isAvatarMenuOpen, setIsAvatarMenuOpen] = useState(false);

    const fileInputRef = React.useRef(null);

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file && file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onloadend = () => {
                setAvatar(reader.result);
            };
            reader.readAsDataURL(file);
        }
    };

    const handleRemoveAvatar = () => {
        setAvatar(null);
        if (fileInputRef.current) {
            fileInputRef.current.value = '';
        }
    };

    const handleSave = () => {
        setIsSaving(true);
        // Simulate an API call
        setTimeout(() => {
            localStorage.setItem('zenix_user_name', name);
            localStorage.setItem('zenix_user_email', email);
            if (avatar) {
                localStorage.setItem('zenix_user_avatar', avatar);
            } else {
                localStorage.removeItem('zenix_user_avatar');
            }
            setIsSaving(false);
            setSaveSuccess(true);
            
            // Dispatch event to update other components (like Topbar)
            window.dispatchEvent(new CustomEvent('zenix_profile_updated'));
            
            // Hide success message after 3 seconds
            setTimeout(() => setSaveSuccess(false), 3000);
        }, 600);
    };

    return (
        <div style={{ padding: '12px 16px', height: '100%', overflowY: 'auto' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxWidth: '800px' }}>
                {/* Personal Information */}
                <div style={{ background: 'rgba(15, 15, 20, 0.4)', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.05)', padding: '12px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px', position: 'relative' }}>
                        <div 
                            onClick={() => setIsAvatarMenuOpen(!isAvatarMenuOpen)}
                            style={{ 
                                width: '48px', 
                                height: '48px', 
                                borderRadius: '50%', 
                                background: avatar ? `url(${avatar}) center/cover` : 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)', 
                                display: 'flex', 
                                alignItems: 'center', 
                                justifyContent: 'center', 
                                fontSize: '20px', 
                                fontWeight: '600', 
                                color: '#fff',
                                overflow: 'hidden',
                                cursor: 'pointer',
                                border: '2px solid rgba(255, 255, 255, 0.1)',
                                transition: 'all 0.2s',
                            }}
                            onMouseOver={(e) => e.currentTarget.style.border = '2px solid rgba(255, 255, 255, 0.3)'}
                            onMouseOut={(e) => e.currentTarget.style.border = '2px solid rgba(255, 255, 255, 0.1)'}
                        >
                            {!avatar && name.charAt(0).toUpperCase()}
                        </div>
                        
                        {isAvatarMenuOpen && (
                            <div style={{ 
                                position: 'absolute', 
                                left: '60px', 
                                top: '50%', 
                                transform: 'translateY(-50%)',
                                background: 'rgba(20, 20, 25, 0.95)', 
                                padding: '8px', 
                                borderRadius: '8px', 
                                border: '1px solid rgba(255, 255, 255, 0.1)',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
                                zIndex: 10
                            }}>
                                <input 
                                    type="file" 
                                    accept="image/*" 
                                    ref={fileInputRef}
                                    style={{ display: 'none' }} 
                                    onChange={(e) => {
                                        handleFileChange(e);
                                        setIsAvatarMenuOpen(false);
                                    }}
                                />
                                <button 
                                    onClick={() => fileInputRef.current?.click()}
                                    style={{ background: 'rgba(59, 130, 246, 0.1)', border: 'none', color: '#60a5fa', padding: '6px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: '500', cursor: 'pointer', transition: 'all 0.2s' }}
                                    onMouseOver={(e) => e.currentTarget.style.background = 'rgba(59, 130, 246, 0.2)'}
                                    onMouseOut={(e) => e.currentTarget.style.background = 'rgba(59, 130, 246, 0.1)'}
                                >
                                    Change
                                </button>
                                {avatar && (
                                    <button 
                                        onClick={() => {
                                            handleRemoveAvatar();
                                            setIsAvatarMenuOpen(false);
                                        }}
                                        style={{ background: 'rgba(248, 113, 113, 0.1)', border: 'none', color: '#f87171', padding: '6px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: '500', cursor: 'pointer', transition: 'all 0.2s' }}
                                        onMouseOver={(e) => e.currentTarget.style.background = 'rgba(248, 113, 113, 0.2)'}
                                        onMouseOut={(e) => e.currentTarget.style.background = 'rgba(248, 113, 113, 0.1)'}
                                    >
                                        Remove
                                    </button>
                                )}
                            </div>
                        )}
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <div>
                            <label style={{ display: 'block', color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}>Full Name</label>
                            <input 
                                type="text" 
                                value={name} 
                                onChange={(e) => setName(e.target.value)}
                                style={{ width: '100%', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', padding: '8px 12px', borderRadius: '8px', fontSize: '13px', outline: 'none' }} 
                            />
                        </div>
                        <div>
                            <label style={{ display: 'block', color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}>Email Address</label>
                            <input 
                                type="email" 
                                value={email} 
                                onChange={(e) => setEmail(e.target.value)}
                                style={{ width: '100%', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', padding: '8px 12px', borderRadius: '8px', fontSize: '13px', outline: 'none' }} 
                            />
                        </div>
                        <div>
                            <label style={{ display: 'block', color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}>Role</label>
                            <div style={{ width: '100%', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.05)', color: '#94a3b8', padding: '8px 12px', borderRadius: '8px', fontSize: '13px', cursor: 'not-allowed' }}>
                                Security Administrator
                            </div>
                        </div>
                    </div>

                    <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid rgba(255, 255, 255, 0.05)', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '16px' }}>
                        {saveSuccess && (
                            <span style={{ color: '#34d399', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                                Changes saved successfully
                            </span>
                        )}
                        <button 
                            onClick={handleSave}
                            disabled={isSaving}
                            style={{ 
                                background: '#3b82f6', 
                                border: 'none', 
                                color: '#fff', 
                                padding: '8px 16px', 
                                borderRadius: '8px', 
                                fontSize: '13px', 
                                fontWeight: '500', 
                                cursor: isSaving ? 'wait' : 'pointer', 
                                transition: 'all 0.2s', 
                                boxShadow: '0 4px 12px rgba(59, 130, 246, 0.3)',
                                opacity: isSaving ? 0.7 : 1
                            }}
                        >
                            {isSaving ? 'Saving...' : 'Save Changes'}
                        </button>
                    </div>
                </div>

                {/* Account Preferences */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ background: 'rgba(15, 15, 20, 0.4)', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.05)', padding: '12px 16px' }}>
                        <h3 style={{ fontSize: '14px', fontWeight: '500', color: '#fff', marginBottom: '10px' }}>Localization</h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <div>
                                <label style={{ display: 'block', color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}>Timezone</label>
                                <select style={{ width: '100%', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', padding: '8px 12px', borderRadius: '8px', fontSize: '13px', outline: 'none', appearance: 'none' }}>
                                    <option>UTC (Coordinated Universal Time)</option>
                                    <option>EST (Eastern Standard Time)</option>
                                    <option>PST (Pacific Standard Time)</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <div style={{ background: 'rgba(15, 15, 20, 0.4)', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.05)', padding: '12px 16px' }}>
                        <h3 style={{ fontSize: '14px', fontWeight: '500', color: '#fff', marginBottom: '10px' }}>Danger Zone</h3>
                        <div style={{ border: '1px solid rgba(248, 113, 113, 0.2)', borderRadius: '8px', padding: '10px 14px', background: 'rgba(248, 113, 113, 0.05)' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <div>
                                    <div style={{ color: '#fff', fontSize: '14px', fontWeight: '500' }}>Delete Account</div>
                                    <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px' }}>Permanently remove your personal data.</div>
                                </div>
                                <button style={{ background: '#ef4444', border: 'none', color: '#fff', padding: '8px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: '500', cursor: 'pointer' }}>
                                    Delete
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ProfileActionsView;
