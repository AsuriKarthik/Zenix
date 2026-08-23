import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

const StatsRow = () => {
    const [currentTime, setCurrentTime] = useState(new Date());
    const [stats, setStats] = useState({
        process_count: 0,
        dll_count: 0,
        noise_reduction: 95.0,
        vex_count: 3
    });

    const fetchStats = () => {
        fetch('http://localhost:5000/api/system-stats')
            .then(res => res.json())
            .then(data => setStats(data))
            .catch(err => console.warn("Failed to fetch system stats from backend:", err));
    };

    useEffect(() => {
        const timer = setInterval(() => setCurrentTime(new Date()), 1000);
        
        fetchStats();
        // Poll every 4 seconds to sync with system-level changes
        const statsTimer = setInterval(fetchStats, 4000);

        window.addEventListener('zenix_agent_state_changed', fetchStats);

        return () => {
            clearInterval(timer);
            clearInterval(statsTimer);
            window.removeEventListener('zenix_agent_state_changed', fetchStats);
        };
    }, []);

    const timeString = currentTime.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
    const dateString = currentTime.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' }).toUpperCase();

    const cardStyle = {
        background: 'linear-gradient(135deg, rgba(30, 31, 35, 0.65) 0%, rgba(18, 19, 23, 0.45) 100%)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: 'inset 0 1px 0 0 rgba(255, 255, 255, 0.08), 0 8px 32px rgba(0, 0, 0, 0.36)',
        borderRadius: '18px',
        padding: '20px 24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        minHeight: '142px',
        justifyContent: 'space-between',
        cursor: 'pointer',
        transition: 'all 0.25s ease'
    };

    const timeCardStyle = {
        ...cardStyle,
        background: 'linear-gradient(135deg, rgba(37, 39, 43, 0.75) 0%, rgba(20, 22, 26, 0.55) 100%)',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '6px',
        cursor: 'default'
    };

    // Color definitions
    const greenMatch = '#22C55E';
    const blueMatch = '#3B82F6';
    const amberMatch = '#F59E0B';
    const redMatch = '#EF4444';

    const cardVariants = {
        hidden: { opacity: 0, y: 24, scale: 0.92, filter: 'blur(10px)' },
        visible: (i) => ({
            opacity: 1,
            y: 0,
            scale: 1,
            filter: 'blur(0px)',
            transition: {
                duration: 0.55,
                delay: i * 0.08,
                ease: [0.16, 1, 0.3, 1]
            }
        })
    };

    return (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '16px', marginBottom: '8px' }}>

            {/* OBJECTIVE 1: Alert Noise Filter */}
            <motion.div 
                custom={0}
                initial="hidden"
                animate="visible"
                variants={cardVariants}
                whileHover={{ y: -2, transition: { duration: 0.2 } }}
                style={cardStyle}
            >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ color: '#e7e5e4', fontSize: '13px', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Objective 1: Noise Filter</span>
                    <div style={{ background: 'rgba(55, 178, 80, 0.1)', color: greenMatch, fontSize: '10px', padding: '3px 8px', borderRadius: '12px', fontWeight: 'bold' }}>
                        ACTIVE
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                    <div>
                        <div style={{ fontSize: '38px', color: greenMatch, fontWeight: '700', lineHeight: '1.1' }}>{stats.noise_reduction}%</div>
                        <div style={{ fontSize: '11px', color: '#78716c', marginTop: '2px', fontWeight: '500' }}>False Positive Suppression</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'flex-end', gap: '3px', height: '28px' }}>
                        {[30, 45, 20, 60, 40, 80, 30, 95, 75, 95].map((h, i) => (
                            <div key={i} style={{ width: '3px', background: greenMatch, height: `${h}%`, borderRadius: '1px' }}></div>
                        ))}
                    </div>
                </div>
            </motion.div>

            {/* OBJECTIVE 2: Dynamic Context (ETW) */}
            <motion.div 
                custom={1}
                initial="hidden"
                animate="visible"
                variants={cardVariants}
                whileHover={{ y: -2, transition: { duration: 0.2 } }}
                style={cardStyle}
            >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ color: '#e7e5e4', fontSize: '13px', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Objective 2: Context</span>
                    <div style={{
                        background: stats.etw_running ? 'rgba(59, 130, 246, 0.1)' : 'rgba(120, 113, 108, 0.1)',
                        color: stats.etw_running ? blueMatch : '#78716c',
                        fontSize: '10px', padding: '3px 8px', borderRadius: '12px', fontWeight: 'bold'
                    }}>
                        {stats.etw_running ? 'ETW ACTIVE' : 'ETW DISABLED'}
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                    <div>
                        <div style={{ fontSize: '36px', color: '#ffffff', fontWeight: '700', lineHeight: '1.1', letterSpacing: '0.5px' }}>
                            {stats.etw_running ? (stats.process_count || 0) : "0"} <span style={{ fontSize: '14px', color: stats.etw_running ? blueMatch : '#78716c' }}>PIDs</span>
                        </div>
                        <div style={{ fontSize: '11px', color: '#78716c', marginTop: '4px', fontWeight: '500' }}>
                            {stats.etw_running ? (stats.event_count_total ? `${stats.event_count_total.toLocaleString()} ETW Events` : `${stats.dll_count || 0} Image Maps`) : "No runtime telemetry collected"}
                        </div>
                    </div>
                    <div style={{ position: 'relative', width: '36px', height: '36px', marginBottom: '2px' }}>
                        <svg viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                            <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="3.5" />
                            <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831" fill="none" stroke={stats.etw_running ? blueMatch : '#78716c'} strokeWidth="3.5" strokeDasharray={stats.etw_running ? "75, 100" : "0, 100"} />
                        </svg>
                        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', fontSize: '9px', color: stats.etw_running ? '#e7e5e4' : '#78716c', fontWeight: 'bold' }}>
                            {stats.etw_running ? 'LIVE' : 'OFF'}
                        </div>
                    </div>
                </div>
            </motion.div>

            {/* OBJECTIVE 3: Shadow Dependency (AI) */}
            <motion.div 
                custom={2}
                initial="hidden"
                animate="visible"
                variants={cardVariants}
                whileHover={{ y: -2, transition: { duration: 0.2 } }}
                style={cardStyle}
            >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ color: '#e7e5e4', fontSize: '13px', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Objective 3: Discovery</span>
                    <div style={{ background: 'rgba(245, 158, 11, 0.1)', color: amberMatch, fontSize: '10px', padding: '3px 8px', borderRadius: '12px', fontWeight: 'bold' }}>
                        AI TRIAGE
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                    <div>
                        <div style={{ fontSize: '38px', color: amberMatch, fontWeight: '700', lineHeight: '1.1' }}>
                            {stats.dependency_count ? stats.dependency_count.toLocaleString() : "AI"}
                        </div>
                        <div style={{ fontSize: '11px', color: '#78716c', marginTop: '2.5px', fontWeight: '500' }}>Workspace Files Scanned</div>
                    </div>
                    <div style={{ position: 'relative', width: '50px', height: '25px', overflow: 'hidden', marginBottom: '4px' }}>
                        <svg viewBox="0 0 100 50" style={{ width: '100%', height: '200%' }}>
                            <path d="M10 90 A 40 40 0 1 1 90 90" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="12" strokeLinecap="round" />
                            <path d="M10 90 A 40 40 0 0 1 70 20" fill="none" stroke={amberMatch} strokeWidth="12" strokeLinecap="round" />
                        </svg>
                    </div>
                </div>
            </motion.div>

            {/* OBJECTIVE 4: Automated Compliance (VEX) */}
            <motion.div 
                custom={3}
                initial="hidden"
                animate="visible"
                variants={cardVariants}
                whileHover={{ y: -2, transition: { duration: 0.2 } }}
                style={cardStyle}
            >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ color: '#e7e5e4', fontSize: '13px', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '0.8px' }}>Objective 4: Compliance</span>
                    <div style={{ background: 'rgba(250, 69, 22, 0.1)', color: redMatch, fontSize: '10px', padding: '3px 8px', borderRadius: '12px', fontWeight: 'bold' }}>
                        VEX
                    </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                    <div>
                        <div style={{ fontSize: '38px', color: '#ffffff', fontWeight: '700', lineHeight: '1.1' }}>{stats.vex_count}</div>
                        <div style={{ fontSize: '11px', color: '#78716c', marginTop: '2px', fontWeight: '500' }}>Signed VEX Proofs</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'flex-end', gap: '3px', height: '28px' }}>
                        {[20, 40, 60, 30, 50, 70, 40, 80, 60, 90].map((h, i) => (
                            <div key={i} style={{ width: '3px', background: redMatch, height: `${h}%`, borderRadius: '1px' }}></div>
                        ))}
                    </div>
                </div>
            </motion.div>

            {/* CARD 5: TIME */}
            <motion.div 
                custom={4}
                initial="hidden"
                animate="visible"
                variants={cardVariants}
                whileHover={{ scale: 1.01, transition: { duration: 0.2 } }}
                style={timeCardStyle}
            >
                <div style={{ fontSize: '34px', fontWeight: '700', color: '#ffffff', lineHeight: '1', letterSpacing: '1px' }}>{timeString}</div>
                <div style={{ fontSize: '12.5px', color: '#a8a29e', fontWeight: '600', letterSpacing: '2px' }}>{dateString}</div>
            </motion.div>


        </div>
    );
};

export default StatsRow;

