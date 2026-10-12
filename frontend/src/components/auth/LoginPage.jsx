/**
 * LoginPage
 *
 * Full-screen login experience:
 *  - Pure black background
 *  - Animated geometric elements (Framer Motion SVG paths, Reference 3 style)
 *  - Login panel with real backend authentication
 *  - Rate limit / lockout error display
 *  - No background images, no scenes
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertCircle, Lock, Mail } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { register } from '../../api/auth';

/* ── Zenix mark SVG paths ──────────────────────────────────────── */
// Inverted-triangle + crossing lines — abstract form of the logo visible in reference images
const MARK_PATHS = {
  outer: 'M 50 8 L 92 78 L 8 78 Z',         // outer triangle (inverted)
  inner: 'M 50 22 L 80 70 L 20 70 Z',        // inner triangle
  topLine:  'M 50 0 L 50 8',                  // vertical top tick
  leftLine: 'M 20 70 L 4 88',                 // lower-left arm
  rightLine:'M 80 70 L 96 88',               // lower-right arm
  crossL: 'M 26 60 L 50 22',
  crossR: 'M 74 60 L 50 22',
};

/* ── Ambient floating elements ─────────────────────────────────── */
function AmbientCanvas() {
  return (
    <svg
      className="login-canvas"
      viewBox="0 0 1440 900"
      xmlns="http://www.w3.org/2000/svg"
      preserveAspectRatio="xMidYMid slice"
    >
      {/* Far left triangle cluster */}
      <motion.path
        d="M 160 600 L 230 720 L 90 720 Z"
        stroke="rgba(255,255,255,0.07)"
        strokeWidth="1"
        fill="none"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 2.2, delay: 0.3, ease: 'easeInOut' }}
      />
      <motion.path
        d="M 160 635 L 210 715 L 110 715 Z"
        stroke="rgba(255,255,255,0.04)"
        strokeWidth="1"
        fill="none"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 2.5, delay: 0.8, ease: 'easeInOut' }}
      />

      {/* Top right three-arm element */}
      <motion.g
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.0, duration: 1.5 }}
      >
        <motion.line
          x1="1180" y1="180" x2="1180" y2="110"
          stroke="rgba(255,255,255,0.08)" strokeWidth="1"
          initial={{ pathLength: 0 }} animate={{ pathLength: 1 }}
          transition={{ duration: 1.2, delay: 1.2 }}
        />
        <motion.line
          x1="1180" y1="180" x2="1120" y2="220"
          stroke="rgba(255,255,255,0.08)" strokeWidth="1"
          initial={{ pathLength: 0 }} animate={{ pathLength: 1 }}
          transition={{ duration: 1.2, delay: 1.4 }}
        />
        <motion.line
          x1="1180" y1="180" x2="1240" y2="220"
          stroke="rgba(255,255,255,0.08)" strokeWidth="1"
          initial={{ pathLength: 0 }} animate={{ pathLength: 1 }}
          transition={{ duration: 1.2, delay: 1.6 }}
        />
      </motion.g>

      {/* Bottom left diamond */}
      <motion.path
        d="M 240 750 L 268 778 L 240 806 L 212 778 Z"
        stroke="rgba(255,255,255,0.06)"
        strokeWidth="1"
        fill="none"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 2.0, delay: 1.8, ease: 'easeInOut' }}
      />

      {/* Center-left precision circle (reference 3 style) */}
      <motion.circle
        cx="280" cy="400" r="60"
        stroke="rgba(255,255,255,0.04)"
        strokeWidth="1"
        fill="none"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 2.5, delay: 0.6 }}
      />
      <motion.circle
        cx="280" cy="400" r="48"
        stroke="rgba(255,255,255,0.03)"
        strokeWidth="1"
        fill="none"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 2.0, delay: 1.0 }}
      />
      {/* Tick marks around circle */}
      {[0, 45, 90, 135, 180, 225, 270, 315].map((angle, i) => {
        const r = 55;
        const r2 = 62;
        const rad = (angle * Math.PI) / 180;
        return (
          <motion.line
            key={angle}
            x1={280 + r * Math.cos(rad)} y1={400 + r * Math.sin(rad)}
            x2={280 + r2 * Math.cos(rad)} y2={400 + r2 * Math.sin(rad)}
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="1"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.2 + i * 0.04 }}
          />
        );
      })}

      {/* Right side bracket */}
      <motion.path
        d="M 1260 380 L 1300 380 L 1300 420"
        stroke="rgba(255,255,255,0.05)"
        strokeWidth="1"
        fill="none"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 0.7 }}
        transition={{ duration: 1.5, delay: 2.0 }}
      />
      <motion.path
        d="M 1260 520 L 1300 520 L 1300 480"
        stroke="rgba(255,255,255,0.05)"
        strokeWidth="1"
        fill="none"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 0.7 }}
        transition={{ duration: 1.5, delay: 2.2 }}
      />

      {/* Horizontal hairlines */}
      <motion.line
        x1="0" y1="220" x2="320" y2="220"
        stroke="rgba(255,255,255,0.025)" strokeWidth="1"
        initial={{ scaleX: 0 }} animate={{ scaleX: 1 }}
        style={{ transformOrigin: 'left center' }}
        transition={{ duration: 2.0, delay: 0.5 }}
      />
      <motion.line
        x1="1100" y1="660" x2="1440" y2="660"
        stroke="rgba(255,255,255,0.025)" strokeWidth="1"
        initial={{ scaleX: 0 }} animate={{ scaleX: 1 }}
        style={{ transformOrigin: 'right center' }}
        transition={{ duration: 2.0, delay: 0.7 }}
      />
    </svg>
  );
}

/* ── Zenix Logo Mark ───────────────────────────────────────────── */
function ZenixMark({ size = 48 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
      <motion.path
        d={MARK_PATHS.outer}
        stroke="rgba(124,38,236,0.6)"
        strokeWidth="2"
        fill="none"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.2, ease: 'easeInOut' }}
      />
      <motion.path
        d={MARK_PATHS.inner}
        stroke="rgba(32,225,163,0.8)"
        strokeWidth="1.5"
        fill="none"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.0, delay: 0.4, ease: 'easeInOut' }}
      />
      <motion.line
        x1="50" y1="0" x2="50" y2="10"
        stroke="rgba(255,255,255,0.3)" strokeWidth="1.5"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }}
        transition={{ delay: 0.9 }}
      />
      <motion.line
        x1="20" y1="70" x2="5" y2="90"
        stroke="rgba(255,255,255,0.3)" strokeWidth="1.5"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }}
        transition={{ delay: 1.0 }}
      />
      <motion.line
        x1="80" y1="70" x2="95" y2="90"
        stroke="rgba(255,255,255,0.3)" strokeWidth="1.5"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }}
        transition={{ delay: 1.1 }}
      />
    </svg>
  );
}

/* ── Sign Up Form ──────────────────────────────────────────────── */
function SignUpForm({ onSuccess }) {
  const [email, setEmail]         = useState('');
  const [password, setPassword]   = useState('');
  const [confirm, setConfirm]     = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]         = useState(null);
  const [success, setSuccess]     = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }

    setSubmitting(true);
    try {
      await register(email.trim().toLowerCase(), password, 'analyst');
      setSuccess(true);
      // Auto-proceed to login after brief pause
      setTimeout(() => onSuccess(email.trim().toLowerCase(), password), 800);
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed. Try again.');
    } finally {
      setSubmitting(false);
    }
  };

  if (success) {
    return (
      <motion.div
        className="alert alert-success"
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        style={{ marginTop: 8, flexDirection: 'column', alignItems: 'center', textAlign: 'center', padding: 24 }}
      >
        <AlertCircle size={20} style={{ color: 'var(--color-verified)', marginBottom: 8 }} />
        <div style={{ fontWeight: 600, marginBottom: 4 }}>Account created!</div>
        <div style={{ fontSize: 12 }}>Signing you in…</div>
      </motion.div>
    );
  }

  return (
    <form className="login-form" onSubmit={handleSubmit}>
      <div className="input-group">
        <label className="input-label" htmlFor="signup-email">Email</label>
        <div style={{ position: 'relative' }}>
          <Mail size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            id="signup-email"
            className="input"
            type="email"
            placeholder="analyst@organization.com"
            value={email}
            onChange={e => setEmail(e.target.value)}
            required
            autoComplete="email"
            disabled={submitting}
            style={{ paddingLeft: 36 }}
          />
        </div>
      </div>

      <div className="input-group">
        <label className="input-label" htmlFor="signup-password">Password</label>
        <div style={{ position: 'relative' }}>
          <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            id="signup-password"
            className="input"
            type="password"
            placeholder="Min. 8 characters"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
            autoComplete="new-password"
            disabled={submitting}
            style={{ paddingLeft: 36 }}
          />
        </div>
      </div>

      <div className="input-group">
        <label className="input-label" htmlFor="signup-confirm">Confirm Password</label>
        <div style={{ position: 'relative' }}>
          <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: confirm && confirm !== password ? 'var(--color-critical)' : 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            id="signup-confirm"
            className="input"
            type="password"
            placeholder="Repeat password"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
            required
            autoComplete="new-password"
            disabled={submitting}
            style={{
              paddingLeft: 36,
              borderColor: confirm && confirm !== password ? 'var(--color-critical)' : undefined,
            }}
          />
        </div>
      </div>

      <AnimatePresence mode="wait">
        {error && (
          <motion.div
            className="alert alert-error"
            initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <AlertCircle size={14} style={{ flexShrink: 0 }} />
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      <div className="alert alert-info" style={{ fontSize: 11 }}>
        <AlertCircle size={12} style={{ flexShrink: 0, opacity: 0.6 }} />
        New accounts are created with the <strong>analyst</strong> role. Contact an admin to elevate permissions.
      </div>

      <button
        id="signup-submit-btn"
        type="submit"
        className="btn btn-primary btn-lg"
        disabled={submitting}
      >
        {submitting
          ? <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: 1 }}>CREATING ACCOUNT…</span>
          : 'Create Account'
        }
      </button>
    </form>
  );
}

/* ── Main LoginPage Component ──────────────────────────────────── */
export default function LoginPage() {
  const navigate = useNavigate();
  const { login, isAuthenticated } = useAuth();

  // 'signin' | 'signup'
  const [mode, setMode] = useState('signin');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [lockoutSeconds, setLockoutSeconds] = useState(0);

  // If already authenticated, redirect to app
  useEffect(() => {
    if (isAuthenticated) navigate('/app/dashboard', { replace: true });
  }, [isAuthenticated, navigate]);

  // Lockout countdown timer
  useEffect(() => {
    if (lockoutSeconds <= 0) return;
    const t = setInterval(() => {
      setLockoutSeconds((s) => {
        if (s <= 1) { clearInterval(t); return 0; }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [lockoutSeconds]);

  // Clear errors when switching mode
  const switchMode = (m) => {
    setMode(m);
    setError(null);
    setLockoutSeconds(0);
  };

  const handleSignIn = async (e) => {
    e.preventDefault();
    if (lockoutSeconds > 0) return;
    setError(null);
    setIsSubmitting(true);

    try {
      await login(email.trim().toLowerCase(), password);
      navigate('/app/dashboard', { replace: true });
    } catch (err) {
      const data = err.response?.data;
      if (err.response?.status === 429) {
        const match = data?.error?.match(/(\d+) seconds/);
        if (match) setLockoutSeconds(parseInt(match[1], 10));
        setError(data?.error || 'Too many attempts. Please wait.');
      } else {
        setError(data?.error || 'Authentication failed. Check your credentials.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  // Called by SignUpForm on successful registration — auto login
  const handleSignUpSuccess = async (registeredEmail, registeredPassword) => {
    try {
      await login(registeredEmail, registeredPassword);
      navigate('/app/dashboard', { replace: true });
    } catch {
      switchMode('signin');
      setEmail(registeredEmail);
    }
  };

  return (
    <div className="login-page">
      {/* Ambient geometric background */}
      <AmbientCanvas />

      {/* Login Panel */}
      <motion.div
        className="login-panel"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.5, ease: [0.16, 1, 0.3, 1] }}
      >
        {/* Header */}
        <div className="login-panel-header">
          <div className="login-logo-mark">
            <ZenixMark size={44} />
          </div>
          <div className="login-panel-title">Zenix</div>
          <div className="login-panel-sub">Vulnerability Intelligence Platform</div>
        </div>

        {/* Mode Toggle Tabs */}
        <div style={{
          display: 'flex',
          marginBottom: 'var(--space-6)',
          background: 'rgba(0,0,0,0.3)',
          borderRadius: 'var(--radius-md)',
          padding: 3,
          gap: 3,
        }}>
          {[
            { key: 'signin', label: 'Sign In' },
            { key: 'signup', label: 'Sign Up' },
          ].map(({ key, label }) => (
            <button
              key={key}
              id={`auth-tab-${key}`}
              type="button"
              onClick={() => switchMode(key)}
              style={{
                flex: 1,
                padding: '8px 12px',
                borderRadius: 'calc(var(--radius-md) - 2px)',
                fontFamily: 'var(--font-body)',
                fontSize: 13,
                fontWeight: 500,
                cursor: 'pointer',
                border: 'none',
                transition: 'all 200ms ease',
                background: mode === key
                  ? 'rgba(124, 38, 236, 0.18)'
                  : 'transparent',
                color: mode === key
                  ? 'var(--text-primary)'
                  : 'var(--text-muted)',
                boxShadow: mode === key
                  ? 'inset 0 0 0 1px rgba(124,38,236,0.35)'
                  : 'none',
              }}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Animated form area */}
        <AnimatePresence mode="wait">
          {mode === 'signin' ? (
            <motion.div
              key="signin"
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 12 }}
              transition={{ duration: 0.2 }}
            >
              <form className="login-form" onSubmit={handleSignIn}>
                <div className="input-group">
                  <label className="input-label" htmlFor="login-email">Email</label>
                  <div style={{ position: 'relative' }}>
                    <Mail size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
                    <input
                      id="login-email"
                      className="input"
                      type="email"
                      placeholder="analyst@organization.com"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      required
                      autoComplete="email"
                      disabled={isSubmitting || lockoutSeconds > 0}
                      style={{ paddingLeft: 36 }}
                    />
                  </div>
                </div>

                <div className="input-group">
                  <label className="input-label" htmlFor="login-password">Password</label>
                  <div style={{ position: 'relative' }}>
                    <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
                    <input
                      id="login-password"
                      className="input"
                      type="password"
                      placeholder="••••••••"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                      disabled={isSubmitting || lockoutSeconds > 0}
                      style={{ paddingLeft: 36 }}
                    />
                  </div>
                </div>

                <AnimatePresence mode="wait">
                  {error && (
                    <motion.div
                      className="alert alert-error"
                      initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      <AlertCircle size={14} style={{ flexShrink: 0 }} />
                      <div>
                        <div>{error}</div>
                        {lockoutSeconds > 0 && (
                          <div style={{ marginTop: 4, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                            Retry in {lockoutSeconds}s
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                <button
                  id="login-submit-btn"
                  type="submit"
                  className="btn btn-primary btn-lg"
                  style={{ marginTop: 4 }}
                  disabled={isSubmitting || lockoutSeconds > 0}
                >
                  {isSubmitting ? (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: 1 }}>AUTHENTICATING…</span>
                  ) : lockoutSeconds > 0 ? (
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: 1 }}>LOCKED · {lockoutSeconds}s</span>
                  ) : (
                    'Authenticate & Sign In'
                  )}
                </button>

                {/* Switch hint */}
                <div style={{ textAlign: 'center', marginTop: 'var(--space-3)' }}>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>No account?{' '}</span>
                  <button
                    type="button"
                    onClick={() => switchMode('signup')}
                    style={{
                      background: 'none', border: 'none', cursor: 'pointer',
                      fontSize: 12, color: 'var(--color-verified)',
                      textDecoration: 'underline', textUnderlineOffset: 3,
                    }}
                  >
                    Create one
                  </button>
                </div>
              </form>
            </motion.div>
          ) : (
            <motion.div
              key="signup"
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -12 }}
              transition={{ duration: 0.2 }}
            >
              <SignUpForm onSuccess={handleSignUpSuccess} />

              {/* Switch hint */}
              <div style={{ textAlign: 'center', marginTop: 'var(--space-4)' }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Already have an account?{' '}</span>
                <button
                  type="button"
                  onClick={() => switchMode('signin')}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    fontSize: 12, color: 'var(--color-verified)',
                    textDecoration: 'underline', textUnderlineOffset: 3,
                  }}
                >
                  Sign in
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Footer */}
        <div className="login-footer" style={{ marginTop: 'var(--space-5)' }}>
          <div className="login-footer-text">
            Zenix Security Platform · Session Protected
          </div>
        </div>
      </motion.div>
    </div>
  );
}

