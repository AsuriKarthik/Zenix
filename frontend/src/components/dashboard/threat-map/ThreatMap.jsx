import React, { useState, useRef, useEffect } from 'react';
import { MapContainer, TileLayer, Marker, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Search, Loader2, ArrowLeft, ShieldAlert } from 'lucide-react';

// Smooth transition to searched coordinates
const MapController = ({ location }) => {
    const map = useMap();
    useEffect(() => {
        if (location) map.flyTo(location, 14, { duration: 8, easeLinearity: 0.1 });
    }, [location, map]);
    return null;
};

const createPulsingIcon = (color) => new L.DivIcon({
    className: 'custom-pulsing-icon',
    html: `<div style="width:16px; height:16px; background:${color}; border-radius:50%; box-shadow: 0 0 15px ${color}; animation: pulse 2s infinite;"></div>`,
    iconSize: [16, 16],
    iconAnchor: [8, 8]
});

const AnimatedThreatMap = () => {
    const [searchQuery, setSearchQuery] = useState('');
    const [searchedIp, setSearchedIp] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const handleSearch = async (e) => {
        e.preventDefault();
        const ip = searchQuery.trim();
        if (!ip) return;

        setLoading(true);
        setError(null);

        try {
            // Simulated network delay
            await new Promise(resolve => setTimeout(resolve, 800));

            // Generate mock data based on the IP address string to make it deterministic
            const hash = Array.from(ip).reduce((acc, char) => acc + char.charCodeAt(0), 0);
            const isCritical = hash % 3 === 0;
            const isWarning = hash % 3 === 1;
            const status = isCritical ? 'CRITICAL' : isWarning ? 'WARNING' : 'SAFE';
            
            const data = {
                ip: ip,
                latitude: (hash % 180) - 90 + (hash % 10) / 10,
                longitude: (hash % 360) - 180 + (hash % 10) / 10,
                city: isCritical ? 'Moscow' : isWarning ? 'Beijing' : 'Ashburn',
                country_name: isCritical ? 'Russia' : isWarning ? 'China' : 'United States',
                status: status,
                threat_score: isCritical ? 85 + (hash % 15) : isWarning ? 50 + (hash % 30) : hash % 30,
                data_sources: {
                    shodan: isCritical ? 'success' : 'access_denied',
                    alienvault: 'success',
                    virustotal: 'success'
                },
                vt_positives: isCritical ? 10 + (hash % 50) : isWarning ? 2 + (hash % 5) : 0,
                vt_total: 94,
                reachability: {
                    is_reachable: isCritical,
                    status: isCritical ? 'reachable' : 'offline'
                },
                ports: isCritical ? [80, 443, 3389, 22].slice(0, 1 + (hash % 4)) : [],
                mitre_techniques: isCritical ? [
                    { id: 'T1548', name: 'Abuse Elevation Control Mechanism' },
                    { id: 'T1059', name: 'Command and Scripting Interpreter' }
                ] : [],
                threat_activity: Array.from({ length: 7 }, () => Math.floor(Math.random() * 100)),
                latest_event: isCritical ? {
                    type: 'Exploit Attempt',
                    description: 'Detected anomalous inbound traffic matching known CVE signatures.',
                    tags: ['Exploit', 'Network']
                } : null
            };
            
            // UI Color Logic
            const uiData = {
                ...data,
                lat: data.latitude,
                lng: data.longitude,
                color: data.status === 'CRITICAL' ? '#ef4444' : data.status === 'WARNING' ? '#eab308' : '#22c55e'
            };
            
            setSearchedIp(uiData);
        } catch (err) {
            setError(err.message);
            setSearchedIp(null);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ height: '100vh', width: '100vw', background: '#020617', position: 'relative', overflow: 'hidden' }}>
            <MapContainer center={[20, 0]} zoom={2.5} zoomControl={false} style={{ height: '100%', width: '100%' }}>
                <TileLayer url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" />
                {searchedIp && (
                    <>
                        <MapController location={[searchedIp.lat, searchedIp.lng]} />
                        <Marker position={[searchedIp.lat, searchedIp.lng]} icon={createPulsingIcon(searchedIp.color)} />
                    </>
                )}
            </MapContainer>

            {/* Loading Overlay */}
            {loading && (
                <div style={{ 
                    position: 'absolute', 
                    inset: 0, 
                    background: 'rgba(2, 6, 23, 0.3)', 
                    display: 'flex', 
                    flexDirection: 'column', 
                    alignItems: 'center', 
                    justifyContent: 'center', 
                    zIndex: 2000,
                    backdropFilter: 'blur(4px)'
                }}>
                    <Loader2 className="spin-animation" color="#8b5cf6" size={60} />
                    <h2 style={{ 
                        color: '#fff', 
                        marginTop: '20px', 
                        letterSpacing: '4px', 
                        fontSize: '16px', 
                        fontWeight: 'bold',
                        textShadow: '0 2px 10px rgba(0,0,0,0.5)'
                    }}>TRIANGULATING THE ADDRESS...</h2>
                </div>
            )}

            {/* Search Bar */}
            <div style={{ position: 'absolute', top: 20, left: 20, zIndex: 1000 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                     <button onClick={() => window.location.reload()} style={{ background: '#1F2128', border: '1px solid #272832', borderRadius: '8px', padding: '10px', cursor: 'pointer', color: '#fff' }}>
                        <ArrowLeft size={18} />
                    </button>
                    <form onSubmit={handleSearch} style={{ display: 'flex', background: '#1F2128', border: '1px solid #272832', borderRadius: '8px', overflow: 'hidden' }}>
                        <input 
                            type="text" placeholder="Scan IP Address..." value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            style={{ background: 'transparent', border: 'none', color: '#fff', padding: '10px 15px', outline: 'none', width: '250px' }}
                        />
                        <button type="submit" style={{ background: '#8b5cf6', border: 'none', padding: '10px 15px', cursor: 'pointer' }}>
                            <Search color="#fff" size={20} />
                        </button>
                    </form>
                </div>
                {error && <div style={{ color: '#ef4444', fontSize: '12px', marginTop: '8px', background: '#ef444420', padding: '4px 8px', borderRadius: '4px' }}>{error}</div>}
            </div>

            {/* Enhanced Info Panel */}
            {searchedIp && (
                <div style={{ position: 'absolute', top: 20, right: 20, bottom: 20, width: '380px', background: 'rgba(19, 20, 27, 0.95)', border: '1px solid #272832', borderRadius: '16px', padding: '24px', color: '#fff', zIndex: 1000, overflowY: 'auto', backdropFilter: 'blur(10px)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                            <h2 style={{ margin: 0, fontSize: '28px', fontWeight: 'bold' }}>{searchedIp.ip}</h2>
                            <p style={{ color: '#94a3b8', margin: '4px 0', fontSize: '14px' }}>📍 {searchedIp.city}, {searchedIp.country_name}</p>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                            <span style={{ 
                                color: searchedIp.data_sources?.shodan === 'access_denied' ? '#fb923c' : searchedIp.color, 
                                fontSize: '11px', 
                                fontWeight: 'bold', 
                                border: `1px solid ${searchedIp.data_sources?.shodan === 'access_denied' ? '#fb923c' : searchedIp.color}60`, 
                                padding: '4px 10px', 
                                borderRadius: '6px', 
                                background: `${searchedIp.data_sources?.shodan === 'access_denied' ? '#fb923c' : searchedIp.color}15` 
                            }}>
                                {searchedIp.data_sources?.shodan === 'access_denied' ? 'LIMITED DATA' : searchedIp.status}
                            </span>
                        </div>
                    </div>

                    {/* Engine Status Icons */}
                    <div style={{ marginTop: '16px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                        {Object.entries(searchedIp.data_sources || {}).map(([engine, status]) => (
                            <div key={engine} style={{ 
                                fontSize: '9px', 
                                letterSpacing: '0.05em',
                                background: status === 'success' ? '#065f4630' : status === 'access_denied' ? '#7c2d1230' : '#1e293b',
                                color: status === 'success' ? '#10b981' : status === 'access_denied' ? '#fb923c' : '#94a3b8',
                                border: `1px solid ${status === 'success' ? '#10b98140' : status === 'access_denied' ? '#fb923c40' : '#334155'}`,
                                padding: '2px 8px',
                                borderRadius: '4px',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '4px',
                                textTransform: 'uppercase'
                            }}>
                                <div style={{ 
                                    width: '4px', 
                                    height: '4px', 
                                    borderRadius: '50%', 
                                    background: status === 'success' ? '#10b981' : status === 'access_denied' ? '#fb923c' : '#64748b' 
                                }} />
                                {engine}
                            </div>
                        ))}
                    </div>

                    {/* Risk Score */}
                    <div style={{ marginTop: '20px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                            <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 'bold' }}>ZENIX RISK SCORE</span>
                            <span style={{ color: searchedIp.color, fontWeight: 'bold', fontSize: '18px' }}>{searchedIp.threat_score}/100</span>
                        </div>
                        <div style={{ height: '8px', background: '#1c1d24', borderRadius: '4px', overflow: 'hidden' }}>
                            <div style={{ width: `${searchedIp.threat_score}%`, height: '100%', background: `linear-gradient(90deg, #3b82f6, ${searchedIp.color})`, transition: 'width 1.5s ease-out' }} />
                        </div>
                    </div>

                    {/* Latest Event */}
                    {searchedIp.latest_event && (
                        <div style={{ marginTop: '24px', background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.1)', borderRadius: '12px', padding: '16px' }}>
                             <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#ef4444' }} />
                                <span style={{ fontSize: '10px', color: '#ef4444', fontWeight: 'bold', letterSpacing: '1px' }}>LATEST DETECTED EVENT</span>
                            </div>
                            <strong style={{ display: 'block', fontSize: '14px', marginBottom: '4px' }}>{searchedIp.latest_event.type}</strong>
                            <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8', lineHeight: '1.5' }}>{searchedIp.latest_event.description}</p>
                            <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
                                {searchedIp.latest_event.tags.map(tag => (
                                    <span key={tag} style={{ fontSize: '10px', background: '#ef444420', color: '#ef4444', padding: '2px 8px', borderRadius: '4px', fontWeight: 'bold' }}>{tag}</span>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* MITRE Techniques */}
                    {searchedIp.mitre_techniques && searchedIp.mitre_techniques.length > 0 && (
                        <div style={{ marginTop: '24px' }}>
                            <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 'bold', display: 'block', marginBottom: '12px' }}>MITRE ATT&CK® TECHNIQUES</span>
                            {searchedIp.mitre_techniques.map(tech => (
                                <div key={tech.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid #272832' }}>
                                    <span style={{ fontSize: '13px' }}>{tech.name}</span>
                                    <span style={{ fontSize: '11px', color: '#64748b' }}>{tech.id}</span>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Threat Activity Chart */}
                    <div style={{ marginTop: '24px' }}>
                        <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 'bold', display: 'block', marginBottom: '16px' }}>THREAT ACTIVITY (LAST 7 DAYS)</span>
                        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', height: '60px' }}>
                            {searchedIp.threat_activity.map((val, i) => (
                                <div key={i} style={{ flex: 1, height: `${(val / 100) * 100}%`, minHeight: '4px', background: i === 6 ? '#ef4444' : '#334155', borderRadius: '2px', transition: 'height 1s ease-out' }} />
                            ))}
                        </div>
                    </div>

                    {/* Service Stats */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '24px' }}>
                        <div style={{ background: '#1c1d24', padding: '16px', borderRadius: '12px', border: '1px solid #272832' }}>
                            <div style={{ fontSize: '10px', color: '#3b82f6', fontWeight: 'bold', marginBottom: '8px' }}>VIRUSTOTAL</div>
                            <div style={{ fontSize: '20px', fontWeight: 'bold' }}>{searchedIp.vt_positives}<span style={{ color: '#475569', fontSize: '14px' }}>/{searchedIp.vt_total}</span></div>
                            <div style={{ fontSize: '10px', color: '#64748b', marginTop: '4px' }}>Malicious Flagged</div>
                        </div>
                        <div style={{ background: '#1c1d24', padding: '16px', borderRadius: '12px', border: '1px solid #272832' }}>
                            <div style={{ fontSize: '10px', color: '#10b981', fontWeight: 'bold', marginBottom: '8px' }}>REACHABILITY</div>
                            <div style={{ fontSize: '20px', fontWeight: 'bold', color: searchedIp.reachability?.is_reachable ? '#10b981' : '#64748b' }}>{searchedIp.reachability?.status?.toUpperCase() || 'OFFLINE'}</div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '8px' }}>
                                {searchedIp.ports.length > 0 ? searchedIp.ports.map(p => (
                                    <span key={p} style={{ fontSize: '9px', background: '#334155', color: '#fff', padding: '2px 6px', borderRadius: '3px' }}>{p}</span>
                                )) : <span style={{ fontSize: '9px', color: '#64748b' }}>No active ports</span>}
                            </div>
                            <div style={{ fontSize: '9px', color: '#475569', marginTop: '8px', fontStyle: 'italic' }}>
                                {searchedIp.data_sources?.shodan === 'success' ? 'Source: Shodan Global' : 'Source: Local Port Scan'}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <style>{`
                @keyframes pulse {
                    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(255, 255, 255, 0.7); }
                    70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(255, 255, 255, 0); }
                    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(255, 255, 255, 0); }
                }
                @keyframes spin {
                    from { transform: rotate(0deg); }
                    to { transform: rotate(360deg); }
                }
                .spin-animation {
                    animation: spin 1.5s linear infinite;
                }
                ::-webkit-scrollbar { width: 4px; }
                ::-webkit-scrollbar-track { background: transparent; }
                ::-webkit-scrollbar-thumb { background: #272832; borderRadius: 2px; }
            `}</style>
        </div>
    );
};

export default AnimatedThreatMap;