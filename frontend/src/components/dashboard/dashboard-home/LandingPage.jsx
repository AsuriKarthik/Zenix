import React, { useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { ArrowRight, Check, Shield, Database, Lock, Cpu, Clock, Filter, FileText, Activity, Globe, Server, Layers } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

const LandingPage = ({ onLogin }) => {
    const heroRef = useRef(null);

    useEffect(() => {
        const ctx = gsap.context(() => {

            // Hero Animation
            const heroTl = gsap.timeline({ defaults: { ease: "power3.out" } });

            // Initial State matching CSS visibility
            gsap.set(".hero-visual-card", { autoAlpha: 0, scale: 0.9 });
            gsap.set(".connection-line", { strokeDasharray: 500, strokeDashoffset: 500 }); // Reset lines
            gsap.set(".check-icon", { scale: 0, opacity: 0 }); // Reset checks

            // 1. AI Card
            heroTl.to(".card-ai", { autoAlpha: 1, scale: 1, duration: 0.6 })
                .to(".card-ai .check-icon", { scale: 1, opacity: 1, duration: 0.3, ease: "back.out(1.7)" });

            // 2. Lines to Threat & VEX (Split)
            heroTl.to(".line-ai-threat", { strokeDashoffset: 0, duration: 0.6 }, "-=0.1")
                .to(".line-ai-vex", { strokeDashoffset: 0, duration: 0.6 }, "<");

            // 3. Threat & VEX Cards (Appear together)
            heroTl.to([".card-threat", ".card-vex"], { autoAlpha: 1, scale: 1, duration: 0.5 }, "-=0.3")
                .to([".card-threat .check-icon", ".card-vex .check-icon"], { scale: 1, opacity: 1, duration: 0.3, ease: "back.out(1.7)" });

            // 4. Line to Risk (From VEX)
            heroTl.to(".line-vex-risk", { strokeDashoffset: 0, duration: 0.5 }, "-=0.1");

            // 5. Risk Card
            heroTl.to(".card-risk", { autoAlpha: 1, scale: 1, duration: 0.5 }, "-=0.3")
                .to(".card-risk .check-icon", { scale: 1, opacity: 1, duration: 0.3, ease: "back.out(1.7)" });

            // Hero Content (Text)
            heroTl.from(".hero-content", { y: 30, opacity: 0, duration: 1 }, "-=2");

            // Stats Counter
            const counters = document.querySelectorAll('.count-up span');
            counters.forEach(counter => {
                const target = parseInt(counter.dataset.target);
                gsap.to(counter, {
                    innerHTML: target,
                    duration: 2,
                    snap: { innerHTML: 1 },
                    ease: "power2.out"
                });
            });

            // Feature Sections
            gsap.utils.toArray('.feature-section').forEach(section => {
                gsap.from(section, {
                    scrollTrigger: {
                        trigger: section,
                        start: "top 80%",
                    },
                    y: 40,
                    opacity: 0,
                    duration: 0.8
                });
            });

        }, heroRef);

        return () => ctx.revert();
    }, []);

    return (
        <div id="landing-view" ref={heroRef} style={{ background: '#050505', minHeight: '100vh', color: 'white', fontFamily: 'Inter, sans-serif' }}>
            <header className="navbar" style={{ padding: '20px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', position: 'fixed', width: '100%', top: 0, background: 'rgba(5,5,5,0.8)', backdropFilter: 'blur(10px)', zIndex: 100 }}>
                <div className="container" style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 20px' }}>
                    <div className="logo" style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>Zenix</div>
                    <nav className="nav-links" style={{ display: 'flex', gap: '40px', fontSize: '0.9rem', fontWeight: '500' }}>
                        <a href="#home" style={{ color: '#fff' }}>Home</a>
                        <a href="#platform" style={{ color: '#9ca3af', transition: 'color 0.2s' }}>Platform</a>
                        <a href="#value" style={{ color: '#9ca3af', transition: 'color 0.2s' }}>Value</a>
                        <a href="#compliance" style={{ color: '#9ca3af', transition: 'color 0.2s' }}>Compliance</a>
                    </nav>
                    <button className="btn" onClick={() => onLogin(false)} style={{ background: 'white', color: 'black', fontWeight: 'bold' }}>
                        Dashboard <ArrowRight size={16} />
                    </button>
                </div>
            </header>

            <main style={{ paddingTop: '80px' }}>
                {/* Hero Section */}
                <section className="hero-section" id="home" style={{ padding: '120px 0 80px', position: 'relative', overflow: 'hidden' }}>
                    <div className="container" style={{ maxWidth: '1200px', margin: '0 auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '60px', padding: '0 20px', alignItems: 'center' }}>
                        <div className="hero-content">
                            <h1 style={{ fontSize: '4rem', lineHeight: '1.1', marginBottom: '24px', fontWeight: '700' }}>
                                A Universe of <br />
                                <span style={{ color: '#a855f7' }}>Cognitive Triage.</span>
                            </h1>
                            <p style={{ fontSize: '1.2rem', color: '#9ca3af', marginBottom: '40px', lineHeight: '1.6', maxWidth: '500px' }}>
                                CyberTrons transforms overwhelming vulnerability reports into a prioritized,
                                context-aware security roadmap. Using exploit probability, AI reasoning,
                                and automated compliance proof.
                            </p>
                            <div className="hero-cta" style={{ display: 'flex', gap: '16px', marginBottom: '60px' }}>
                                <button className="btn btn-white" onClick={() => onLogin(false)} style={{ background: 'white', color: 'black', padding: '14px 28px', borderRadius: '8px', fontWeight: '600' }}>
                                    Request Demo <ArrowRight size={16} />
                                </button>
                                <button className="btn btn-outline" style={{ border: '1px solid #333', padding: '14px 28px', background: 'transparent', color: 'white', borderRadius: '8px' }}>
                                    Upload SBOM / Scan
                                </button>
                            </div>

                            <div className="hero-stats" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px' }}>
                                <div className="stat-item count-up">
                                    <h3 style={{ fontSize: '2rem', fontWeight: 'bold' }}><span data-target="5000">0</span></h3>
                                    <p style={{ fontSize: '0.75rem', color: '#6b7280', textTransform: 'uppercase', letterSpacing: '1px' }}>SIGNALS INGESTED</p>
                                </div>
                                <div className="stat-item count-up">
                                    <h3 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#3b82f6' }}><span data-target="4950">0</span></h3>
                                    <p style={{ fontSize: '0.75rem', color: '#6b7280', textTransform: 'uppercase', letterSpacing: '1px' }}>AUTO-RESOLVED</p>
                                </div>
                                <div className="stat-item count-up">
                                    <h3 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#ef4444' }}><span data-target="50">0</span></h3>
                                    <p style={{ fontSize: '0.75rem', color: '#6b7280', textTransform: 'uppercase', letterSpacing: '1px' }}>ACTIONABLE THREATS</p>
                                </div>
                                <div className="stat-item count-up">
                                    <h3 style={{ fontSize: '2rem', fontWeight: 'bold' }}><span data-target="142">0</span></h3>
                                    <p style={{ fontSize: '0.75rem', color: '#6b7280', textTransform: 'uppercase', letterSpacing: '1px' }}>HOURS SAVED</p>
                                </div>
                            </div>
                        </div>

                        <div className="hero-visuals" style={{ position: 'relative', height: '500px', width: '100%' }}>
                            {/* Connecting Lines SVG (Tree Structure) */}
                            <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', zIndex: 0, pointerEvents: 'none', overflow: 'visible' }} viewBox="0 0 100 100" preserveAspectRatio="none">
                                <defs>
                                    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                                        <polygon points="0 0, 10 3.5, 0 7" fill="#3b82f6" opacity="0.6" />
                                    </marker>
                                </defs>
                                {/* AI -> Split -> CVE & VEX */}
                                {/* AI Bottom Center (50, 25) -> Split (50, 32) -> Left (20, 32) -> Down (20, 40) */}
                                <path className="connection-line line-ai-threat" d="M 50 25 V 32 H 20 V 40" fill="none" stroke="#3b82f6" strokeWidth="2" vectorEffect="non-scaling-stroke" strokeDasharray="500" strokeDashoffset="500" opacity="0.6" strokeLinecap="round" strokeLinejoin="round" />
                                {/* AI Bottom Center (50, 25) -> Split (50, 32) -> Right (80, 32) -> Down (80, 40) */}
                                <path className="connection-line line-ai-vex" d="M 50 25 V 32 H 80 V 40" fill="none" stroke="#3b82f6" strokeWidth="2" vectorEffect="non-scaling-stroke" strokeDasharray="500" strokeDashoffset="500" opacity="0.6" strokeLinecap="round" strokeLinejoin="round" />

                                {/* VEX Bottom Center (80, 66) -> Risk Top Center (80, 76) */}
                                <path className="connection-line line-vex-risk" d="M 80 66 V 76" fill="none" stroke="#3b82f6" strokeWidth="2" vectorEffect="non-scaling-stroke" strokeDasharray="500" strokeDashoffset="500" opacity="0.6" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>

                            {/* Main Card (AI Engine) - Top Center */}
                            <div className="hero-visual-card card-ai" style={{ position: 'absolute', top: '0%', left: '50%', transform: 'translateX(-50%)', width: '320px', background: '#1c1c1e', padding: '24px', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.1)', boxShadow: '0 20px 50px rgba(0,0,0,0.5)', zIndex: 3 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                                    <img src="https://ui-avatars.com/api/?name=AI&background=3b82f6&color=fff" style={{ width: '40px', height: '40px', borderRadius: '12px' }} alt="AI" />
                                    <div>
                                        <div style={{ fontWeight: '600' }}>AI Engine</div>
                                        <div style={{ fontSize: '0.8rem', color: '#9ca3af' }}>resolved 4,950 alerts automatically</div>
                                    </div>
                                    <div className="check-icon" style={{ marginLeft: 'auto', background: 'rgba(16,185,129,0.2)', padding: '4px', borderRadius: '50%' }}><Check size={14} color="#10b981" /></div>
                                </div>
                                <div style={{ height: '4px', background: '#333', borderRadius: '2px', marginBottom: '8px', width: '100%' }}><div style={{ width: '80%', height: '100%', background: '#3b82f6', borderRadius: '2px' }}></div></div>
                            </div>

                            {/* Threat Cards Stack - Left Extreme */}
                            <div className="hero-visual-card card-threat" style={{ position: 'absolute', top: '40%', left: '0', width: '280px', background: '#121214', padding: '16px', borderRadius: '14px', border: '1px solid rgba(255,255,255,0.05)', boxShadow: '0 10px 30px rgba(0,0,0,0.4)', zIndex: 2 }}>
                                <div className="check-icon" style={{ position: 'absolute', top: '-10px', right: '-10px', background: '#10b981', padding: '6px', borderRadius: '50%', boxShadow: '0 4px 12px rgba(16,185,129,0.3)', zIndex: 10 }}>
                                    <Check size={16} color="white" />
                                </div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', padding: '8px', background: 'rgba(255,255,255,0.03)', borderRadius: '6px' }}>
                                        <span style={{ color: '#e5e7eb' }}>CVE-2137</span>
                                        <span className="badge" style={{ background: 'rgba(16,185,129,0.1)', color: '#10b981', padding: '2px 6px', borderRadius: '4px', fontSize: '0.7rem' }}>Action ↗</span>
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', padding: '8px', opacity: 0.5 }}>
                                        <span>CVE-2136</span>
                                        <span style={{ color: '#10b981' }}>Safe</span>
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', padding: '8px', opacity: 0.5 }}>
                                        <span>CVE-2135</span>
                                        <span style={{ color: '#10b981' }}>Safe</span>
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', padding: '8px', opacity: 0.5 }}>
                                        <span>CVE-2134</span>
                                        <span style={{ color: '#10b981' }}>Safe</span>
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', padding: '8px', opacity: 0.5 }}>
                                        <span>CVE-2133</span>
                                        <span style={{ color: '#10b981' }}>Safe</span>
                                    </div>
                                </div>
                            </div>

                            {/* VEX Card - Right Extreme */}
                            <div className="hero-visual-card card-vex" style={{ position: 'absolute', top: '40%', right: '0', width: '240px', background: '#18181b', padding: '20px', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.08)', boxShadow: '0 20px 40px rgba(0,0,0,0.6)', zIndex: 4 }}>
                                <div style={{ textAlign: 'center', marginBottom: '12px' }}>
                                    <div style={{ width: '40px', height: '40px', background: 'rgba(255,255,255,0.05)', borderRadius: '50%', margin: '0 auto 10px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                        <FileText size={20} color="#fff" />
                                    </div>
                                    <div style={{ fontSize: '0.9rem', fontWeight: '600' }}>VEX Document</div>
                                    <div style={{ fontSize: '0.75rem', color: '#666' }}>generated successfully</div>
                                </div>
                                <div className="check-icon" style={{ display: 'flex', justifyContent: 'center' }}>
                                    <div style={{ background: '#10b981', width: '20px', height: '20px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                        <Check size={12} color="white" />
                                    </div>
                                </div>
                            </div>

                            {/* Remaining Risk - Below VEX (Aligned Right) */}
                            <div className="hero-visual-card card-risk" style={{ position: 'absolute', top: '76%', right: '0', width: '260px', background: '#121214', padding: '20px', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.05)', boxShadow: '0 10px 30px rgba(0,0,0,0.3)', zIndex: 1 }}>
                                <div className="check-icon" style={{ position: 'absolute', top: '-10px', right: '-10px', background: '#10b981', padding: '6px', borderRadius: '50%', boxShadow: '0 4px 12px rgba(16,185,129,0.3)', zIndex: 10 }}>
                                    <Check size={16} color="white" />
                                </div>
                                <div style={{ textAlign: 'center' }}>
                                    <div style={{ fontSize: '0.8rem', color: '#9ca3af', marginBottom: '4px' }}>Remaining Risk</div>
                                    <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#10b981' }}>50 Issues</div>
                                    <div style={{ marginTop: '10px', height: '6px', background: '#333', borderRadius: '3px', position: 'relative' }}>
                                        <div style={{ width: '99%', height: '100%', background: '#10b981', borderRadius: '3px' }}></div>
                                    </div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#666', marginTop: '6px' }}>
                                        <span>CONFIDENCE</span>
                                        <span>99%</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Platform Section */}
                <section className="feature-section" id="platform" style={{ padding: '100px 0', background: '#0a0a0a' }}>
                    <div className="container" style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 20px' }}>
                        <div style={{ textAlign: 'center', marginBottom: '80px' }}>
                            <h4 style={{ color: '#3b82f6', fontSize: '0.9rem', marginBottom: '16px', fontWeight: '600', letterSpacing: '1px' }}>PLATFORM</h4>
                            <h2 style={{ fontSize: '3rem', fontWeight: 'bold' }}>Unified Security Context</h2>
                            <p style={{ color: '#9ca3af', maxWidth: '600px', margin: '20px auto' }}>Stop chasing false positives. Zenix unifies data from every layer of your stack to determine what remains exploitable.</p>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '30px' }}>
                            <div style={{ padding: '30px', background: '#111', borderRadius: '16px', border: '1px solid #222' }}>
                                <Globe size={32} color="#3b82f6" style={{ marginBottom: '20px' }} />
                                <h3 style={{ fontSize: '1.2rem', marginBottom: '10px' }}>Global Asset Map</h3>
                                <p style={{ color: '#888', fontSize: '0.9rem', lineHeight: '1.6' }}>Visualize your entire infrastructure across clouds, regions, and on-premise data centers in real-time.</p>
                            </div>
                            <div style={{ padding: '30px', background: '#111', borderRadius: '16px', border: '1px solid #222' }}>
                                <Server size={32} color="#a855f7" style={{ marginBottom: '20px' }} />
                                <h3 style={{ fontSize: '1.2rem', marginBottom: '10px' }}>Runtime Analysis</h3>
                                <p style={{ color: '#888', fontSize: '0.9rem', lineHeight: '1.6' }}>Detect which libraries are actually loaded and executed in memory, suppressing dormant vulnerabilities.</p>
                            </div>
                            <div style={{ padding: '30px', background: '#111', borderRadius: '16px', border: '1px solid #222' }}>
                                <Layers size={32} color="#ef4444" style={{ marginBottom: '20px' }} />
                                <h3 style={{ fontSize: '1.2rem', marginBottom: '10px' }}>Reachability Graph</h3>
                                <p style={{ color: '#888', fontSize: '0.9rem', lineHeight: '1.6' }}>Trace execution paths from user input to vulnerable function to confirm exploitability.</p>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Value Section */}
                <section className="feature-section" id="value" style={{ padding: '100px 0', background: '#050505' }}>
                    <div className="container" style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 20px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '80px', alignItems: 'center' }}>
                        <div>
                            <h4 style={{ color: '#ef4444', fontSize: '0.9rem', marginBottom: '16px', fontWeight: '600', letterSpacing: '1px' }}>VALUE</h4>
                            <h2 style={{ fontSize: '3rem', fontWeight: 'bold', marginBottom: '24px' }}>Focus on the 5% that matters.</h2>
                            <p style={{ color: '#9ca3af', fontSize: '1.1rem', lineHeight: '1.6', marginBottom: '30px' }}>
                                95% of vulnerabilities in your backlog are not exploitable in your specific environment. CyberTrons proves it, so you can ignore them safely.
                            </p>
                            <ul style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                                <li style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <div style={{ background: 'rgba(59,130,246,0.1)', padding: '4px', borderRadius: '50%' }}><Check size={16} color="#3b82f6" /></div>
                                    <span>Reduce MTTR by 80%</span>
                                </li>
                                <li style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <div style={{ background: 'rgba(59,130,246,0.1)', padding: '4px', borderRadius: '50%' }}><Check size={16} color="#3b82f6" /></div>
                                    <span>Stop breaking builds for non-issues</span>
                                </li>
                                <li style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <div style={{ background: 'rgba(59,130,246,0.1)', padding: '4px', borderRadius: '50%' }}><Check size={16} color="#3b82f6" /></div>
                                    <span>Automated audit trail for every decision</span>
                                </li>
                            </ul>
                        </div>
                        <div style={{ background: '#111', padding: '40px', borderRadius: '24px', border: '1px solid #222', position: 'relative' }}>
                            {/* Abstract Graph Visualization */}
                            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '300px' }}>
                                <div style={{ textAlign: 'center' }}>
                                    <div style={{ fontSize: '4rem', fontWeight: 'bold', color: 'white' }}>95%</div>
                                    <div style={{ color: '#666' }}>NOISE ELIMINATED</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Compliance Section */}
                <section className="feature-section" id="compliance" style={{ padding: '100px 0', background: '#0a0a0a' }}>
                    <div className="container" style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 20px', textAlign: 'center' }}>
                        <h4 style={{ color: '#10b981', fontSize: '0.9rem', marginBottom: '16px', fontWeight: '600', letterSpacing: '1px' }}>COMPLIANCE</h4>
                        <h2 style={{ fontSize: '3rem', fontWeight: 'bold', marginBottom: '60px' }}>Automated Verification</h2>

                        <div style={{ display: 'flex', justifyContent: 'center', gap: '40px', flexWrap: 'wrap' }}>
                            <div style={{ background: '#18181b', padding: '20px 40px', borderRadius: '12px', border: '1px solid #333' }}>
                                <h3 style={{ margin: 0 }}>SOC 2</h3>
                            </div>
                            <div style={{ background: '#18181b', padding: '20px 40px', borderRadius: '12px', border: '1px solid #333' }}>
                                <h3 style={{ margin: 0 }}>ISO 27001</h3>
                            </div>
                            <div style={{ background: '#18181b', padding: '20px 40px', borderRadius: '12px', border: '1px solid #333' }}>
                                <h3 style={{ margin: 0 }}>GDPR</h3>
                            </div>
                            <div style={{ background: '#18181b', padding: '20px 40px', borderRadius: '12px', border: '1px solid #333' }}>
                                <h3 style={{ margin: 0 }}>HIPAA</h3>
                            </div>
                        </div>
                    </div>
                </section>
            </main>

            <footer style={{ padding: '60px 0', borderTop: '1px solid #222', background: '#050505', textAlign: 'center', color: '#666' }}>
                <div className="container" style={{ maxWidth: '1200px', margin: '0 auto' }}>
                    <p>&copy; 2026 Zenix Security. All rights reserved.</p>
                </div>
            </footer>
        </div>
    );
};

export default LandingPage;
