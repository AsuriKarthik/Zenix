import React from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import Topbar from './Topbar';
import OverviewView from './OverviewView';
import KanbanBoard from '../reachable-risks/KanbanBoard';
import ReachabilityView from '../reachable-risks/ReachabilityView';
import RuntimeEvidenceView from '../runtime-evidence/RuntimeEvidenceView';
import VexView from '../vex/VexView';
import ThreatMap from '../threat-map/ThreatMap';
import SettingsLayout from '../settings/SettingsLayout';
import ProfileActionsView from '../settings/ProfileActionsView';
import NotificationRulesView from '../settings/NotificationRulesView';
import ApiIntegrationsView from '../settings/ApiIntegrationsView';
import SecurityAccessView from '../settings/SecurityAccessView';

const Dashboard = ({ onLogout }) => {
    const navigate = useNavigate();

    return (
        <Routes>
            {/* Threat Map is a special full-screen view */}
            <Route 
                path="threat-map" 
                element={<ThreatMap isFullScreen={true} onCloseFullScreen={() => navigate('/dashboard/overview')} />} 
            />
            
            {/* Standard Dashboard Layout */}
            <Route path="*" element={
                <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', background: '#050508', overflow: 'hidden', fontFamily: '"Inter", sans-serif' }}>
                    <Topbar onLogout={onLogout} />
                    <main style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '24px 32px', overflow: 'hidden', background: 'radial-gradient(circle at 50% -20%, rgba(30, 58, 138, 0.1), transparent 60%)' }}>
                        <div style={{ flex: 1, position: 'relative', overflowY: 'hidden', display: 'flex', flexDirection: 'column' }}>
                            <Routes>
                                <Route path="overview" element={<OverviewView />} />
                                <Route path="findings" element={
                                    <KanbanBoard 
                                        onCheckEvidence={(card) => navigate(`/dashboard/reachability?id=${card.id}`)}
                                    />
                                } />
                                <Route path="reachability" element={<ReachabilityView />} />
                                <Route path="runtime-evidence" element={<RuntimeEvidenceView />} />
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
                        </div>
                    </main>
                </div>
            } />
        </Routes>
    );
};


export default Dashboard;
