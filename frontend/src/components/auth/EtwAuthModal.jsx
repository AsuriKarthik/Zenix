/**
 * EtwAuthModal — Session ETW Authorization & Credential Prompt
 *
 * Rendered when the site opens to prompt the user to enter/set their ETW credentials
 * and launch live continuous kernel telemetry for the session.
 */

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Lock, AlertTriangle, CheckCircle, Eye, EyeOff, X } from 'lucide-react';
import { enableEtw } from '../../api/telemetry';

export default function EtwAuthModal({ isOpen, onClose, onSuccess }) {
  const [passphrase, setPassphrase] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!passphrase) return;

    setSubmitting(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await enableEtw(passphrase);
      setSuccessMsg('ETW Session authorized! Launching kernel telemetry...');
      if (res.session_token) {
        localStorage.setItem('zenix_etw_session', res.session_token);
      }
      setTimeout(() => {
        onSuccess?.(res);
        onClose?.();
      }, 700);
    } catch (err) {
      const data = err.response?.data;
      setError(data?.error || 'Authentication failed. Check your secondary ETW passphrase.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AnimatePresence>
      <div className="modal-backdrop" style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(0, 0, 0, 0.85)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
      }}>
        <motion.div
          className="card"
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          style={{
            width: '100%',
            maxWidth: 480,
            background: 'var(--bg-surface-1)',
            border: '1px solid var(--border-medium)',
            borderRadius: 'var(--radius-lg)',
            boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(229, 72, 77, 0.15)',
            position: 'relative',
          }}
        >
          {/* Close button */}
          <button
            type="button"
            onClick={onClose}
            style={{
              position: 'absolute',
              top: 16,
              right: 16,
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
            }}
          >
            <X size={16} />
          </button>

          {/* Modal Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
            <div style={{
              width: 40,
              height: 40,
              borderRadius: 'var(--radius-md)',
              background: 'rgba(229, 72, 77, 0.12)',
              border: '1px solid rgba(229, 72, 77, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Shield size={20} style={{ color: 'var(--color-critical)' }} />
            </div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#FFFFFF' }}>
                ETW Event Telemetry Authentication
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 1 }}>
                REQUIRED FOR CONTINUOUS RUNTIME EVIDENCE
              </div>
            </div>
          </div>

          <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 'var(--space-4)' }}>
            Enter your secondary administrative ETW credentials to enable continuous kernel-level image-load telemetry for this active browser session.
          </p>

          <form onSubmit={handleSubmit}>
            <div className="input-group mb-4">
              <label className="input-label" htmlFor="modal-etw-passphrase">
                ETW Admin Password
              </label>
              <div style={{ position: 'relative' }}>
                <Lock size={14} style={{
                  position: 'absolute', left: 12, top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-muted)',
                  pointerEvents: 'none',
                }} />
                <input
                  id="modal-etw-passphrase"
                  className="input input-mono"
                  type={showPass ? 'text' : 'password'}
                  placeholder="Enter ETW password"
                  value={passphrase}
                  onChange={e => setPassphrase(e.target.value)}
                  required
                  autoFocus
                  disabled={submitting}
                  style={{ paddingLeft: 36, paddingRight: 40 }}
                />
                <button
                  type="button"
                  onClick={() => setShowPass(v => !v)}
                  style={{
                    position: 'absolute', right: 12, top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none', border: 'none',
                    color: 'var(--text-muted)', cursor: 'pointer',
                  }}
                >
                  {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="alert alert-error mb-4" style={{ fontSize: 12 }}>
                <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                {error}
              </div>
            )}

            {successMsg && (
              <div className="alert alert-success mb-4" style={{ fontSize: 12 }}>
                <CheckCircle size={14} style={{ flexShrink: 0 }} />
                {successMsg}
              </div>
            )}

            <div style={{ display: 'flex', gap: 'var(--space-3)', marginTop: 'var(--space-5)' }}>
              <button
                type="submit"
                className="btn btn-primary"
                style={{ flex: 1 }}
                disabled={submitting || !passphrase}
              >
                {submitting ? 'Authorizing…' : 'Authenticate ETW Session'}
              </button>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={onClose}
                disabled={submitting}
              >
                Defer (Read-Only)
              </button>
            </div>
          </form>

          <div style={{
            marginTop: 'var(--space-4)',
            paddingTop: 'var(--space-3)',
            borderTop: '1px solid var(--border-subtle)',
            fontSize: 10,
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
          }}>
            LIFECYCLE POLICY: Session expires automatically when browser/tab closes.
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
