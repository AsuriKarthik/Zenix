import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import Topbar from './Topbar';
import OverviewView from './OverviewView';
import InvestigationWorkspace from '../reachable-risks/InvestigationWorkspace';
import RuntimeEvidenceView from '../runtime-evidence/RuntimeEvidenceView';
import VexView from '../vex/VexView';
import SettingsLayout from '../settings/SettingsLayout';
import ProfileActionsView from '../settings/ProfileActionsView';
import NotificationRulesView from '../settings/NotificationRulesView';
import ApiIntegrationsView from '../settings/ApiIntegrationsView';
import SecurityAccessView from '../settings/SecurityAccessView';

const Dashboard = ({ onLogout }) => {
    const navigate = useNavigate();
    const location = useLocation();

    const defaultColumns = {
        'open': {
            title: 'Identified',
            count: 2,
            iconColor: '#e7e5e4',
            iconType: 'circle',
            items: [
                { id: 'CVE-2023-44487', subtitle: 'HTTP/2 Rapid Reset', date: '2025-05-17', init: 'MV', initBg: '#22c55e', hasImg: false, dot: '#eab308' },
                { id: 'CVE-2023-38545', subtitle: 'curl SOCKS5 overflow', date: '2025-05-09', init: 'KK', initBg: '#eab308', hasImg: false, dot: '#eab308' }
            ]
        },
        'triaged': {
            title: 'Validated',
            count: 1,
            iconColor: '#a8a29e',
            iconType: 'target',
            items: [
                { id: 'CVE-2021-44228', subtitle: 'Log4Shell • log4j-core', date: '2025-11-20', init: 'NM', initBg: '#eab308', hasImg: true, dot: '#ef4444', badge: 'CRIT', badgeColor: '#ef4444' }
            ]
        },
        'inprogress': {
            title: 'Repairing',
            count: 1,
            iconColor: '#eab308',
            iconType: 'play',
            items: [
                { id: 'CVE-2023-4863', subtitle: 'libwebp heap buffer', date: '2025-05-21', init: 'DK', initBg: '#ef4444', hasImg: false, dot: '#fa4516', badge: 'HIGH', badgeColor: '#fa4516' }
            ]
        },
        'resolved': {
            title: 'Resolved',
            count: 1,
            iconColor: '#22c55e',
            iconType: 'check',
            items: [
                { id: 'CVE-2023-38408', subtitle: 'OpenSSH struct vuln', date: '2025-05-16', init: 'AR', initBg: '#3b82f6', hasImg: false, dot: '#22c55e', badge: 'VEX Signed', badgeColor: '#3b82f6' }
            ]
        }
    };

    const [findings, setFindings] = useState(defaultColumns);

    useEffect(() => {
        // Fetch findings from Python backend API
        fetch('http://localhost:5000/api/findings')
            .then(res => res.json())
            .then(data => setFindings(data))
            .catch(err => console.error("Error fetching findings:", err));
    }, []);

    const updateFindings = (newFindings) => {
        setFindings(newFindings);
        fetch('http://localhost:5000/api/findings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(newFindings)
        }).catch(err => console.error("Error updating findings:", err));
    };

    return (
        <Routes>
            {/* Standard Dashboard Layout */}
            <Route path="*" element={
                <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', background: '#050807', overflow: 'hidden', fontFamily: '"Inter", sans-serif' }}>
                    <Topbar onLogout={onLogout} />
                    <main style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '24px 32px', overflow: 'hidden', background: '#050807' }}>
                        <div style={{ flex: 1, position: 'relative', overflowY: 'hidden', display: 'flex', flexDirection: 'column' }}>
                            <AnimatePresence mode="wait">
                                <motion.div
                                    key={location.pathname}
                                    initial={{ opacity: 0, scale: 0.97, y: 14, filter: 'blur(8px)' }}
                                    animate={{ opacity: 1, scale: 1, y: 0, filter: 'blur(0px)' }}
                                    exit={{ opacity: 0, scale: 0.98, y: -10, filter: 'blur(4px)' }}
                                    transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                                    style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100%' }}
                                >
                                    <Routes location={location}>
                                        <Route path="overview" element={<OverviewView findings={findings} setFindings={updateFindings} />} />
                                        <Route path="findings" element={
                                            <InvestigationWorkspace 
                                                columns={findings}
                                                setColumns={updateFindings}
                                            />
                                        } />
                                        <Route path="reachability" element={<RuntimeEvidenceView />} />
                                        <Route path="compliance" element={<VexView />} />
                                        
                                        {/* Settings Sub-routes */}
                                        <Route path="settings" element={<SettingsLayout onLogout={onLogout} />}>
                                            <Route index element={<Navigate to="profile" replace />} />
                                            <Route path="profile" element={<ProfileActionsView />} />
                                            <Route path="notifications" element={<NotificationRulesView />} />
                                            <Route path="api" element={<ApiIntegrationsView />} />
                                            <Route path="security" element={<SecurityAccessView />} />
                                        </Route>

                                        <Route path="*" element={<Navigate to="overview" replace />} />
                                    </Routes>
                                </motion.div>
                            </AnimatePresence>
                        </div>
                    </main>
                </div>
            } />
        </Routes>
    );
};

export default Dashboard;
