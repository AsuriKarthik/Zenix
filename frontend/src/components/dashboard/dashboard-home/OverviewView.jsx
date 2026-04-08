import React from 'react';
import StatsRow from './StatsRow';

const OverviewView = () => {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '16px', overflowY: 'auto', paddingRight: '8px' }}>
            <StatsRow />
            <div style={{ display: 'flex', gap: '16px', flex: 1, minHeight: '600px' }}>
                <div className="glass-panel" style={{ flex: '2', display: 'flex', flexDirection: 'column', borderRadius: '16px', padding: '36px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '32px' }}>
                        <div style={{ width: '8px', height: '8px', background: '#ef4444', borderRadius: '50%', boxShadow: '0 0 8px #ef4444' }}></div>
                        <h3 style={{ fontSize: '16px', color: '#e7e5e4', fontWeight: '500', margin: 0 }}>Blast Radius Summary</h3>
                    </div>
                    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid rgba(255, 255, 255, 0.05)', borderRadius: '8px', padding: '32px' }}>
                        <p style={{ fontSize: '16px', color: '#a8a29e', margin: 0, lineHeight: '1.8' }}>
                            System analysis reveals <span style={{ color: '#e7e5e4', fontWeight: '600' }}>235 CVEs reachable via Call Graph</span> spanning <span style={{ color: '#e7e5e4', fontWeight: '600' }}>1,240 active library functions</span>. 
                            Currently, <span style={{ color: '#ef4444', fontWeight: '600' }}>1 critical vulnerability</span> has been validated (Log4Shell), with <span style={{ color: '#3b82f6', fontWeight: '600' }}>1 high risk under active repair</span>. 
                            <span style={{ color: '#22c55e', fontWeight: '600' }}>1 risk</span> has been successfully resolved and marked as VEX Signed.
                            <br/><br/>
                            The highest concentration of exploitable risk originates from the <span style={{ color: '#e7e5e4', fontWeight: '500' }}>CVE-2021-44228 (Log4Shell)</span> and <span style={{ color: '#e7e5e4', fontWeight: '500' }}>CVE-2023-44487 (HTTP/2 Rapid Reset)</span> pathways. With our attestation data indicating <span style={{ color: '#e7e5e4', fontWeight: '500' }}>98% of artifacts are "Not Affected"</span>, immediate attention is recommended on the 3 confirmed exploit paths to prevent horizontal escalation.
                        </p>
                    </div>
                </div>
                <div className="glass-panel" style={{ flex: '1', display: 'flex', flexDirection: 'column', borderRadius: '16px', padding: '32px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                        <h3 style={{ fontSize: '14px', color: '#e7e5e4', fontWeight: '500', margin: 0 }}>Context Activity</h3>
                        <div style={{ fontSize: '12px', color: '#78716c', display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                            Sort by <span style={{ marginLeft: '4px', fontSize: '10px' }}>▼</span>
                        </div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', overflowY: 'auto' }}>
                        {[
                            { icon: 'shield', title: 'VEX Attestation Signed for log4j-core', sub: 'Automated compliance check • 8 mins ago' },
                            { icon: 'alert', title: 'SLA breach on Incident #4453', sub: 'Response time exceeded by • 2 hours' },
                            { icon: 'bug', title: 'Critical vulnerability detected: CVE-2025-1234 in nginx server', sub: 'Found in nginx server • (CVE-2025-1234)' },
                            { icon: 'scan', title: 'Compliance scan started', sub: 'Manual trigger • by John.D' },
                            { icon: 'report', title: 'Report scheduled: "Monthly Summary"', sub: 'Set to run on May 2, • 10:00 UTC' },
                            { icon: 'export', title: 'Export completed: Findings (CSV)', sub: '45 records downloaded' },
                            { icon: 'check', title: 'Remediation task marked complete', sub: 'Resolved by admin • (Task #942)' },
                        ].map((item, idx) => (
                            <div key={idx} style={{ background: 'rgba(0, 0, 0, 0.2)', padding: '12px 16px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer', transition: 'background 0.2s', border: '1px solid rgba(255, 255, 255, 0.02)' }}
                                onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)'}
                                onMouseOut={(e) => e.currentTarget.style.background = 'rgba(0, 0, 0, 0.2)'}
                            >
                                <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                    <div style={{ width: '12px', height: '12px', border: '1px solid #a8a29e', borderRadius: item.icon === 'shield' || item.icon === 'bug' ? '2px' : '50%' }}></div>
                                </div>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontSize: '13px', color: '#e7e5e4', fontWeight: '500', marginBottom: '2px' }}>{item.title}</div>
                                    <div style={{ fontSize: '11px', color: '#78716c' }}>{item.sub}</div>
                                </div>
                                <div style={{ fontSize: '14px', color: '#78716c' }}>↗</div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default OverviewView;
