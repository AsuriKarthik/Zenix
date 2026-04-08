import React, { useState, useEffect } from 'react';

const StatsRow = () => {
    const [currentTime, setCurrentTime] = useState(new Date());

    useEffect(() => {
        const timer = setInterval(() => setCurrentTime(new Date()), 1000);
        return () => clearInterval(timer);
    }, []);

    const timeString = currentTime.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
    const dateString = currentTime.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' }).toUpperCase();

    return (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '16px', marginBottom: '8px' }}>

            {/* CARD 1 */}
            <div className="glass-panel" style={{ borderRadius: '16px', padding: '32px', display: 'flex', flexDirection: 'column', gap: '16px', minHeight: '160px', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ color: '#e7e5e4', fontSize: '15px', fontWeight: '500' }}>CVEs via Call Graph</span>
                    <div style={{ background: '#292524', color: '#a8a29e', fontSize: '11px', padding: '4px 8px', borderRadius: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <span style={{ fontSize: '10px' }}>↗</span> 12%
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                    <div>
                        <div style={{ fontSize: '36px', color: '#ffffff', fontWeight: '400', lineHeight: '1.2' }}>235</div>
                        <div style={{ fontSize: '12px', color: '#78716c' }}>211 last week</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'flex-end', gap: '3px', height: '32px' }}>
                        {[40, 60, 30, 80, 50, 90, 40, 60, 70, 85].map((h, i) => (
                            <div key={i} style={{ width: '4px', background: '#37b250', height: `${h}%`, borderRadius: '2px' }}></div>
                        ))}
                    </div>
                </div>
            </div>

            {/* CARD 2 */}
            <div className="glass-panel" style={{ borderRadius: '16px', padding: '32px', display: 'flex', flexDirection: 'column', gap: '16px', minHeight: '160px', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ color: '#e7e5e4', fontSize: '15px', fontWeight: '500' }}>Active library functions</span>
                    <div style={{ background: '#292524', color: '#a8a29e', fontSize: '11px', padding: '4px 8px', borderRadius: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <span style={{ fontSize: '10px' }}>↘</span> 8%
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                    <div>
                        <div style={{ fontSize: '36px', color: '#ffffff', fontWeight: '400', lineHeight: '1.2' }}>1,240</div>
                        <div style={{ fontSize: '12px', color: '#78716c' }}>11 last week</div>
                    </div>
                    <div style={{ position: 'relative', width: '40px', height: '40px', marginBottom: '4px' }}>
                        <svg viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                            <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#292524" strokeWidth="4" />
                            <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831" fill="none" stroke="#fa4516" strokeWidth="4" strokeDasharray="40, 100" />
                        </svg>
                        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', fontSize: '10px', color: '#e7e5e4', fontWeight: '500' }}>40%</div>
                    </div>
                </div>
            </div>

            {/* CARD 3 */}
            <div className="glass-panel" style={{ borderRadius: '16px', padding: '32px', display: 'flex', flexDirection: 'column', gap: '16px', minHeight: '160px', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ color: '#e7e5e4', fontSize: '15px', fontWeight: '500' }}>Artifacts &apos;Not Affected&apos;</span>
                    <div style={{ background: '#292524', color: '#a8a29e', fontSize: '11px', padding: '4px 8px', borderRadius: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <span style={{ fontSize: '10px' }}>↗</span> 6%
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                    <div>
                        <div style={{ fontSize: '36px', color: '#ffffff', fontWeight: '400', lineHeight: '1.2' }}>98%</div>
                        <div style={{ fontSize: '12px', color: '#78716c' }}>47% last week</div>
                    </div>
                    <div style={{ position: 'relative', width: '60px', height: '30px', overflow: 'hidden', marginBottom: '2px' }}>
                        <svg viewBox="0 0 100 50" style={{ width: '100%', height: '200%' }}>
                            <path d="M10 90 A 40 40 0 1 1 90 90" fill="none" stroke="#292524" strokeWidth="12" strokeLinecap="round" />
                            <path d="M10 90 A 40 40 0 0 1 50 10" fill="none" stroke="#37b250" strokeWidth="12" strokeLinecap="round" />
                        </svg>
                    </div>
                </div>
            </div>

            {/* CARD 4 */}
            <div className="glass-panel" style={{ borderRadius: '16px', padding: '32px', display: 'flex', flexDirection: 'column', gap: '16px', minHeight: '160px', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ color: '#e7e5e4', fontSize: '15px', fontWeight: '500' }}>Patches applied w/o breaks</span>
                    <div style={{ background: '#292524', color: '#a8a29e', fontSize: '11px', padding: '4px 8px', borderRadius: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <span style={{ fontSize: '10px' }}>↘</span> 11%
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                    <div>
                        <div style={{ fontSize: '36px', color: '#ffffff', fontWeight: '400', lineHeight: '1.2' }}>84%</div>
                        <div style={{ fontSize: '12px', color: '#78716c' }}>2d: 8h last week</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'flex-end', gap: '3px', height: '32px' }}>
                        {[30, 50, 20, 70, 40, 80, 30, 90, 60, 40].map((h, i) => (
                            <div key={i} style={{ width: '4px', background: '#fa4516', height: `${h}%`, borderRadius: '2px' }}></div>
                        ))}
                    </div>
                </div>
            </div>

            {/* CARD 5: TIME */}
            <div className="glass-panel" style={{ borderRadius: '16px', padding: '32px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '160px', gap: '12px' }}>
                <div style={{ fontSize: '36px', fontWeight: '700', color: '#ffffff', lineHeight: '1', letterSpacing: '1px' }}>{timeString}</div>
                <div style={{ fontSize: '14px', color: '#a8a29e', fontWeight: '500', letterSpacing: '2px' }}>{dateString}</div>
            </div>

        </div>
    );
};

export default StatsRow;
