import React, { useState } from 'react';

const ProfileActionsView = () => {
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
            window.dispatchEvent(new CustomEvent('zenix_profile_updated'));
            setTimeout(() => setSaveSuccess(false), 3000);
        }, 600);
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '800px', color: '#F5F5F5' }}>
            
            {/* Header */}
            <div>
                <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#F5F5F5', margin: 0 }}>Profile Settings</h3>
                <p style={{ fontSize: '13px', color: '#A1A1AA', margin: '4px 0 0 0' }}>Update your user credentials and avatar identity.</p>
            </div>

            {/* Personal Information */}
            <div style={{ background: '#1E1F23', borderRadius: '18px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '20px', position: 'relative' }}>
                    <div 
                        onClick={() => setIsAvatarMenuOpen(!isAvatarMenuOpen)}
                        style={{ 
                            width: '56px', 
                            height: '56px', 
                            borderRadius: '50%', 
                            background: avatar ? `url(${avatar}) center/cover` : 'linear-gradient(135deg, #DAFC6F 0%, #3B82F6 100%)', 
                            display: 'flex', 
                            alignItems: 'center', 
                            justifyContent: 'center', 
                            fontSize: '22px', 
                            fontWeight: '600', 
                            color: '#050807',
                            overflow: 'hidden',
                            cursor: 'pointer',
                            border: '1.5px solid rgba(255, 255, 255, 0.08)',
                            transition: 'all 0.15s ease',
                        }}
                        onMouseOver={(e) => e.currentTarget.style.borderColor = '#DAFC6F'}
                        onMouseOut={(e) => e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)'}
                    >
                        {!avatar && name.charAt(0).toUpperCase()}
                    </div>
                    
                    {isAvatarMenuOpen && (
                        <div style={{ 
                            position: 'absolute', 
                            left: '72px', 
                            top: '50%', 
                            transform: 'translateY(-50%)',
                            background: '#25272B', 
                            padding: '8px', 
                            borderRadius: '12px', 
                            border: '1px solid rgba(255, 255, 255, 0.08)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                            boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
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
                                style={{ background: '#DAFC6F', border: 'none', color: '#050807', padding: '6px 12px', borderRadius: '14px', fontSize: '11px', fontWeight: '600', cursor: 'pointer', transition: 'all 0.15s ease' }}
                            >
                                Change
                            </button>
                            {avatar && (
                                <button 
                                    onClick={() => {
                                        handleRemoveAvatar();
                                        setIsAvatarMenuOpen(false);
                                    }}
                                    style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', color: '#EF4444', padding: '6px 12px', borderRadius: '14px', fontSize: '11px', fontWeight: '600', cursor: 'pointer', transition: 'all 0.15s ease' }}
                                >
                                    Remove
                                </button>
                            )}
                        </div>
                    )}
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div>
                        <label style={{ display: 'block', color: '#A1A1AA', fontSize: '12px', fontWeight: '500', marginBottom: '6px' }}>Full Name</label>
                        <input 
                            type="text" 
                            value={name} 
                            onChange={(e) => setName(e.target.value)}
                            style={{ width: '100%', background: '#050807', border: '1px solid rgba(255, 255, 255, 0.08)', color: '#F5F5F5', padding: '10px 14px', borderRadius: '12px', fontSize: '13px', outline: 'none' }} 
                        />
                    </div>
                    <div>
                        <label style={{ display: 'block', color: '#A1A1AA', fontSize: '12px', fontWeight: '500', marginBottom: '6px' }}>Email Address</label>
                        <input 
                            type="email" 
                            value={email} 
                            onChange={(e) => setEmail(e.target.value)}
                            style={{ width: '100%', background: '#050807', border: '1px solid rgba(255, 255, 255, 0.08)', color: '#F5F5F5', padding: '10px 14px', borderRadius: '12px', fontSize: '13px', outline: 'none' }} 
                        />
                    </div>
                    <div>
                        <label style={{ display: 'block', color: '#A1A1AA', fontSize: '12px', fontWeight: '500', marginBottom: '6px' }}>Role</label>
                        <div style={{ width: '100%', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.04)', color: '#71717A', padding: '10px 14px', borderRadius: '12px', fontSize: '13px', cursor: 'not-allowed' }}>
                            Security Administrator
                        </div>
                    </div>
                </div>

                <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '16px' }}>
                    {saveSuccess && (
                        <span style={{ color: '#22C55E', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            Changes saved successfully
                        </span>
                    )}
                    <button 
                        onClick={handleSave}
                        disabled={isSaving}
                        style={{ 
                            background: '#DAFC6F', 
                            border: 'none', 
                            color: '#050807', 
                            padding: '10px 20px', 
                            borderRadius: '14px', 
                            fontSize: '13px', 
                            fontWeight: '600', 
                            cursor: isSaving ? 'wait' : 'pointer', 
                            transition: 'all 0.15s ease', 
                            opacity: isSaving ? 0.7 : 1
                        }}
                        onMouseOver={(e) => {
                            if (!isSaving) e.currentTarget.style.background = '#E6FF85';
                        }}
                        onMouseOut={(e) => {
                            if (!isSaving) e.currentTarget.style.background = '#DAFC6F';
                        }}
                    >
                        {isSaving ? 'Saving...' : 'Save Changes'}
                    </button>
                </div>
            </div>

            {/* Localization Preferences */}
            <div style={{ background: '#1E1F23', borderRadius: '18px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '24px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#F5F5F5', margin: '0 0 16px 0' }}>Localization</h4>
                <div>
                    <label style={{ display: 'block', color: '#A1A1AA', fontSize: '12px', fontWeight: '500', marginBottom: '6px' }}>Timezone</label>
                    <select style={{ width: '100%', background: '#050807', border: '1px solid rgba(255, 255, 255, 0.08)', color: '#F5F5F5', padding: '10px 14px', borderRadius: '12px', fontSize: '13px', outline: 'none' }}>
                        <option>UTC (Coordinated Universal Time)</option>
                        <option>EST (Eastern Standard Time)</option>
                        <option>PST (Pacific Standard Time)</option>
                    </select>
                </div>
            </div>

            {/* Danger Zone */}
            <div style={{ background: '#1E1F23', borderRadius: '18px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '24px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#F5F5F5', margin: '0 0 16px 0' }}>Danger Zone</h4>
                <div style={{ border: '1px solid rgba(239, 68, 68, 0.15)', borderRadius: '12px', padding: '16px', background: 'rgba(239, 68, 68, 0.02)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                            <div style={{ color: '#F5F5F5', fontSize: '13.5px', fontWeight: '600' }}>Delete Account</div>
                            <div style={{ color: '#A1A1AA', fontSize: '12px', marginTop: '4px' }}>Permanently remove your workspace credentials and local data.</div>
                        </div>
                        <button style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', color: '#EF4444', padding: '8px 16px', borderRadius: '14px', fontSize: '12.5px', fontWeight: '600', cursor: 'pointer' }}>
                            Delete Account
                        </button>
                    </div>
                </div>
            </div>

        </div>
    );
};

export default ProfileActionsView;
