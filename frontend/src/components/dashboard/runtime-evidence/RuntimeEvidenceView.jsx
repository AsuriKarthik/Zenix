import React from 'react';
import { Home, ChevronRight } from 'lucide-react';

const RuntimeEvidenceView = () => {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '16px', overflowY: 'auto', paddingRight: '8px' }}>
            <div className="view-header" style={{ marginBottom: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a8a29e', fontSize: '12px', marginBottom: '8px' }}>
                    <Home size={14} /> <ChevronRight size={14} /> Runtime Evidence
                </div>
                <h2 style={{ fontSize: '24px', fontWeight: '500', color: '#e7e5e4', margin: 0 }}>Live Logs</h2>
            </div>
            <div className="glass-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', borderRadius: '16px', padding: '36px', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.05)' }}>
                <h3 style={{ color: '#e7e5e4', fontSize: '24px', fontWeight: '500', marginBottom: '8px' }}>Live Logs Data</h3>
                <p style={{ color: '#a8a29e', fontSize: '15px' }}>Live Logs visualization placeholder.</p>
            </div>
        </div>
    );
};

export default RuntimeEvidenceView;
