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

import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertCircle, Lock, Mail } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import useAuthStore from '../../store/authStore';
import { login as apiLogin, register, setupEtwPassword, verifyEmail, getSecurityQuestion, resetPasswordWithSecurityAnswer } from '../../api/auth';
import LoadingScreen from '../layout/LoadingScreen';

/* ── Forgot Password / Security Question Recovery Modal ────────── */
function ForgotPasswordModal({ onClose, onSuccess }) {
  const [step, setStep] = useState(1); // 1: Email, 2: Security Question & Reset
  const [resetEmail, setResetEmail] = useState('');
  const [securityQuestion, setSecurityQuestion] = useState('');
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const handleFetchQuestion = async (e) => {
    e.preventDefault();
    if (!resetEmail) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getSecurityQuestion(resetEmail.trim().toLowerCase());
      setSecurityQuestion(data.security_question || 'What is your primary security role?');
      setStep(2);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to locate user account with that email.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await resetPasswordWithSecurityAnswer(resetEmail.trim().toLowerCase(), securityAnswer, newPassword);
      setSuccessMsg(data.message || 'Password reset successfully!');
      setTimeout(() => {
        onSuccess(resetEmail, newPassword);
        onClose();
      }, 1500);
    } catch (err) {
      setError(err.response?.data?.error || 'Incorrect security answer or failed to reset password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop" style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0, 0, 0, 0.85)', backdropFilter: 'blur(8px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
    }}>
      <div className="card" style={{ width: '100%', maxWidth: 460, background: '#1E1F23', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: 16, padding: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: '#F5F5F5' }}>Account Recovery</div>
          <button type="button" onClick={onClose} style={{ background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer', fontSize: 18 }}>✕</button>
        </div>

        {step === 1 ? (
          <form onSubmit={handleFetchQuestion}>
            <div style={{ fontSize: 12, color: '#94A3B8', marginBottom: 16 }}>
              Enter your account email address to retrieve your security verification question.
            </div>
            <div className="input-group mb-4">
              <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>Account Email</label>
              <input
                className="input"
                type="email"
                placeholder="analyst@organization.com"
                value={resetEmail}
                onChange={e => setResetEmail(e.target.value)}
                required
              />
            </div>
            {error && <div className="alert alert-error mb-4" style={{ fontSize: 12 }}>{error}</div>}
            <div style={{ display: 'flex', gap: 12 }}>
              <button type="button" className="btn btn-ghost" onClick={onClose} style={{ flex: 1 }}>Cancel</button>
              <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={loading}>
                {loading ? 'Searching…' : 'Next'}
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleResetPassword}>
            {successMsg ? (
              <div className="alert alert-success mb-4" style={{ fontSize: 13, background: 'rgba(34, 197, 94, 0.15)', color: '#4ADE80', border: '1px solid rgba(34, 197, 94, 0.3)', padding: 12, borderRadius: 8 }}>
                {successMsg}
              </div>
            ) : (
              <>
                <div style={{ padding: 12, background: 'rgba(218, 252, 111, 0.05)', border: '1px solid rgba(218, 252, 111, 0.2)', borderRadius: 8, marginBottom: 16 }}>
                  <div style={{ fontSize: 10, color: '#DAFC6F', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>Security Question</div>
                  <div style={{ fontSize: 13, color: '#F5F5F5', marginTop: 4, fontWeight: 500 }}>{securityQuestion}</div>
                </div>

                <div className="input-group mb-4">
                  <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>Security Answer</label>
                  <input
                    className="input"
                    type="text"
                    placeholder="Enter your security answer (e.g. analyst)"
                    value={securityAnswer}
                    onChange={e => setSecurityAnswer(e.target.value)}
                    required
                  />
                </div>

                <div className="input-group mb-4">
                  <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>New Password</label>
                  <input
                    className="input"
                    type="password"
                    placeholder="Enter new password (min 8 chars)"
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="input-group mb-4">
                  <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>Confirm New Password</label>
                  <input
                    className="input"
                    type="password"
                    placeholder="Repeat new password"
                    value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                    required
                  />
                </div>

                {error && <div className="alert alert-error mb-4" style={{ fontSize: 12 }}>{error}</div>}

                <div style={{ display: 'flex', gap: 12 }}>
                  <button type="button" className="btn btn-ghost" onClick={() => setStep(1)} style={{ flex: 1 }}>Back</button>
                  <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={loading}>
                    {loading ? 'Resetting Password…' : 'Reset Password'}
                  </button>
                </div>
              </>
            )}
          </form>
        )}
      </div>
    </div>
  );
}

/* ── First-Time / Environment ETW Collector Setup & Permission Modal ──── */
function EtwSetupModal({ onComplete }) {
  const [passphrase, setPassphrase] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [permissionGranted, setPermissionGranted] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!permissionGranted) {
      setError('You must grant ETW telemetry collection permission to proceed.');
      return;
    }
    if (passphrase !== confirmPass) {
      setError('Passwords do not match.');
      return;
    }
    if (passphrase.length < 6) {
      setError('ETW Collector Passphrase must be at least 6 characters.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await setupEtwPassword(passphrase);
      localStorage.setItem('zenix_etw_permission_granted', 'true');
      onComplete();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to authorize ETW Collector Passphrase.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0, 0, 0, 0.88)', backdropFilter: 'blur(10px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
    }}>
      <div className="card" style={{ width: '100%', maxWidth: 480, background: '#18191C', border: '1px solid rgba(34, 197, 94, 0.3)', borderRadius: 16, padding: 28, boxShadow: '0 20px 50px rgba(0,0,0,0.8)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 16 }}>
          <div style={{ width: 44, height: 44, borderRadius: 12, background: 'rgba(34, 197, 94, 0.12)', border: '1px solid rgba(34, 197, 94, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#4ADE80' }}>
            <Lock size={22} />
          </div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#F5F5F5', fontFamily: 'var(--font-heading)' }}>ETW Telemetry Access Permission</div>
            <div style={{ fontSize: 11, color: '#4ADE80', fontFamily: 'var(--font-mono)' }}>MANDATORY SYSTEM AUTHORIZATION</div>
          </div>
        </div>
        <div style={{
          padding: 14,
          background: 'rgba(34, 197, 94, 0.08)',
          border: '1px solid rgba(34, 197, 94, 0.25)',
          borderRadius: 10,
          fontSize: 12,
          color: '#E2E8F0',
          lineHeight: 1.6,
          marginBottom: 18
        }}>
          <strong style={{ color: '#4ADE80' }}>CRITICAL SECURITY REQUIREMENT:</strong> Zenix collects real-time kernel process telemetry via Event Tracing for Windows (ETW). Please grant access permission and configure your ETW Passphrase to enable live runtime monitoring in this environment.
        </div>
        <form onSubmit={handleSubmit}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16, padding: '10px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)' }}>
            <input
              type="checkbox"
              id="grant-etw-permission-check"
              checked={permissionGranted}
              onChange={e => setPermissionGranted(e.target.checked)}
              style={{ width: 16, height: 16, accentColor: '#22c55e', cursor: 'pointer' }}
            />
            <label htmlFor="grant-etw-permission-check" style={{ fontSize: 12, color: '#F5F5F5', cursor: 'pointer', fontWeight: 500 }}>
              I grant Zenix permission to collect ETW runtime telemetry on this system.
            </label>
          </div>

          <div className="input-group mb-4">
            <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>ETW Collector Passphrase</label>
            <input
              className="input input-mono"
              type="password"
              placeholder="Enter ETW Collector Passphrase (min 6 chars)"
              value={passphrase}
              onChange={e => setPassphrase(e.target.value)}
              required
            />
          </div>
          <div className="input-group mb-4">
            <label className="input-label" style={{ color: '#F5F5F5', fontSize: 12 }}>Confirm ETW Collector Passphrase</label>
            <input
              className="input input-mono"
              type="password"
              placeholder="Repeat ETW Collector Passphrase"
              value={confirmPass}
              onChange={e => setConfirmPass(e.target.value)}
              required
            />
          </div>
          {error && <div className="alert alert-error mb-4" style={{ fontSize: 12 }}>{error}</div>}
          <button type="submit" className="btn btn-primary btn-lg" style={{ width: '100%', background: '#22c55e', color: '#000', fontWeight: 700 }} disabled={submitting}>
            {submitting ? 'Saving Security Credential…' : 'Grant Permission & Authorize ETW Access'}
          </button>
        </form>
      </div>
    </div>
  );
}

/* ── Main LoginPage Component ──────────────────────────────────── */
export default function LoginPage() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();
  const setUser = useAuthStore((state) => state.setUser);

  // 'signin' | 'signup'
  const [mode, setMode] = useState('signin');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [lockoutSeconds, setLockoutSeconds] = useState(0);
  const [authStatus, setAuthStatus] = useState('idle');
  const [isLoadingAnim, setIsLoadingAnim] = useState(false);
  const [showFirstTimeEtwModal, setShowFirstTimeEtwModal] = useState(false);
  const [showForgotPasswordModal, setShowForgotPasswordModal] = useState(false);
  const validatedUserRef = useRef(null);

  // If already authenticated on initial mount, redirect to app
  useEffect(() => {
    if (isAuthenticated && !isLoadingAnim && !validatedUserRef.current) {
      navigate('/app/dashboard', { replace: true });
    }
  }, [isAuthenticated, isLoadingAnim, navigate]);

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
    if (lockoutSeconds > 0 || isSubmitting) return;
    setError(null);
    setIsSubmitting(true);
    setAuthStatus('submitting');

    try {
      const data = await apiLogin(email.trim().toLowerCase(), password);
      if (!data?.user) {
        throw new Error('Invalid database credentials.');
      }

      validatedUserRef.current = data.user;

      const hasPermission = localStorage.getItem('zenix_etw_permission_granted') === 'true';
      if (!data.user.has_etw_passkey || !hasPermission) {
        setShowFirstTimeEtwModal(true);
        setIsSubmitting(false);
        setAuthStatus('idle');
        return;
      }

      localStorage.setItem('zenix_session_authenticated', 'true');
      setAuthStatus('success');
      setIsLoadingAnim(true);
    } catch (err) {
      setAuthStatus('error');
      setIsSubmitting(false);
      const data = err.response?.data;
      if (err.response?.status === 429) {
        const match = data?.error?.match(/(\d+) seconds/);
        if (match) setLockoutSeconds(parseInt(match[1], 10));
        setError(data?.error || 'Too many attempts. Please wait.');
      } else {
        setError(data?.error || 'Invalid email or password.');
      }
    }
  };

  // Called by SignUpForm on successful registration — auto login
  const handleSignUpSuccess = async (registeredEmail, registeredPassword) => {
    try {
      const data = await apiLogin(registeredEmail, registeredPassword);
      if (data?.user) {
        validatedUserRef.current = data.user;
        const hasPermission = localStorage.getItem('zenix_etw_permission_granted') === 'true';
        if (!data.user.has_etw_passkey || !hasPermission) {
          setShowFirstTimeEtwModal(true);
        } else {
          localStorage.setItem('zenix_session_authenticated', 'true');
          setIsLoadingAnim(true);
        }
      }
    } catch {
      switchMode('signin');
      setEmail(registeredEmail);
    }
  };

  const handleFirstTimeEtwComplete = () => {
    setShowFirstTimeEtwModal(false);
    localStorage.setItem('zenix_etw_permission_granted', 'true');
    localStorage.setItem('zenix_session_authenticated', 'true');
    if (validatedUserRef.current) {
      validatedUserRef.current.has_etw_passkey = true;
    }
    setAuthStatus('success');
    setIsLoadingAnim(true);
  };

  const handleBootComplete = React.useCallback(() => {
    localStorage.setItem('zenix_session_authenticated', 'true');
    if (validatedUserRef.current) {
      setUser(validatedUserRef.current);
    }
    navigate('/app/dashboard', { replace: true });
  }, [setUser, navigate]);

  if (isLoadingAnim) {
    return (
      <LoadingScreen
        isReady={true}
        onComplete={handleBootComplete}
      />
    );
  }
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

/* ── Core Auth Ring Animation ──────────────────────────────────── */
function AuthRingAnimation({ status }) {
  const isIdle = status === 'idle' || status === 'error';
  const isSubmitting = status === 'submitting';
  const isSuccess = status === 'success';

  return (
    <div className="auth-ring-container">
      <motion.svg
        width="650"
        height="650"
        viewBox="-325 -325 650 650"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        animate={{
          rotate: isSubmitting ? 720 : (isSuccess ? 0 : 360)
        }}
        transition={{
          duration: isSubmitting ? 2 : (isSuccess ? 0.5 : 20),
          ease: isSubmitting ? "easeInOut" : "linear",
          repeat: isIdle ? Infinity : 0
        }}
      >
        {/* Full background orbit circle */}
        <circle cx="0" cy="0" r="220" stroke="rgba(229, 72, 77, 0.15)" strokeWidth="2" />

        {/* Single Sleek Glowing Red Arc */}
        <motion.circle 
          cx="0" cy="0" r="220" 
          stroke="#E5484D" 
          strokeWidth="3.5"
          strokeDasharray="1382" /* 2 * PI * 220 = 1382 */
          strokeLinecap="round"
          style={{ filter: 'drop-shadow(0 0 10px rgba(229, 72, 77, 0.85))' }}
          initial={{ strokeDashoffset: 1100 }}
          animate={{
            strokeDashoffset: isSubmitting ? 345 : (isSuccess ? 0 : 1100),
            scale: isSuccess ? 1.05 : 1,
            opacity: isSuccess ? 0 : 1
          }}
          transition={{ duration: 1.5, ease: "easeInOut" }}
        />

        {/* Inner dashed guide circle */}
        <circle cx="0" cy="0" r="190" stroke="rgba(229, 72, 77, 0.1)" strokeWidth="1" strokeDasharray="8 8" />
        
        {/* Inner error pulse */}
        {status === 'error' && (
          <motion.circle
            cx="0" cy="0" r="240"
            stroke="#E5484D"
            strokeWidth="2"
            initial={{ scale: 0.9, opacity: 0.5 }}
            animate={{ scale: 1.2, opacity: 0 }}
            transition={{ duration: 0.8 }}
          />
        )}
      </motion.svg>
    </div>
  );
}

/* ── Zenix Logo Mark ───────────────────────────────────────────── */
function ZenixMark({ size = 48 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
      <motion.path
        d={MARK_PATHS.outer}
        stroke="rgba(229,72,77,0.92)"
        strokeWidth="2"
        fill="none"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.2, ease: 'easeInOut' }}
      />
      <motion.path
        d={MARK_PATHS.inner}
        stroke="rgba(255,129,133,0.98)"
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
  const [etwPasskey, setEtwPasskey] = useState('');
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
      await register(email.trim().toLowerCase(), password, 'analyst', etwPasskey);
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

      <div className="input-group">
        <label className="input-label" htmlFor="signup-etw">ETW Telemetry Password (Optional)</label>
        <div style={{ position: 'relative' }}>
          <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            id="signup-etw"
            className="input input-mono"
            type="password"
            placeholder="Custom ETW password"
            value={etwPasskey}
            onChange={e => setEtwPasskey(e.target.value)}
            disabled={submitting}
            style={{ paddingLeft: 36 }}
          />
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
          Encrypted in database for session ETW telemetry authorization.
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

  return (
    <div className="login-page">
      {showFirstTimeEtwModal && (
        <EtwSetupModal onComplete={handleFirstTimeEtwComplete} />
      )}

      {showForgotPasswordModal && (
        <ForgotPasswordModal
          onClose={() => setShowForgotPasswordModal(false)}
          onSuccess={(resetEmail, newPwd) => {
            setEmail(resetEmail);
            setPassword(newPwd);
            setMode('signin');
          }}
        />
      )}

      {/* Background Central Ring Animation */}
      <AuthRingAnimation status={authStatus} />

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
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label className="input-label" htmlFor="login-password">Password</label>
                    <button
                      type="button"
                      onClick={() => setShowForgotPasswordModal(true)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        fontSize: 11,
                        cursor: 'pointer',
                        padding: 0,
                        transition: 'color 0.2s',
                      }}
                      onMouseEnter={(e) => e.target.style.color = '#DAFC6F'}
                      onMouseLeave={(e) => e.target.style.color = 'var(--text-muted)'}
                    >
                      Forgot password?
                    </button>
                  </div>
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
