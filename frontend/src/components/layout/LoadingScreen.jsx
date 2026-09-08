/**
 * LoadingScreen — Boot Loader Animation
 */

import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

/**
 * AppBootLoader Animation
 * Uses the exact Load.mp4 video file for 100% visual, speed, and motion fidelity.
 */
export function AppBootLoader({ isReady = true, onComplete, minDuration = 2400 }) {
  const hasCalledRef = React.useRef(false);
  const [minTimeElapsed, setMinTimeElapsed] = useState(false);

  // Guarantee the loading animation plays for at least `minDuration`
  useEffect(() => {
    const timer = setTimeout(() => {
      setMinTimeElapsed(true);
    }, minDuration);
    return () => clearTimeout(timer);
  }, [minDuration]);

  // Once the minimum animation duration has elapsed AND the session is ready:
  useEffect(() => {
    if (minTimeElapsed && isReady && !hasCalledRef.current) {
      hasCalledRef.current = true;
      onComplete?.();
    }
  }, [minTimeElapsed, isReady, onComplete]);

  // Fallback safety timer: if session check or loading hangs, transition after safety timeout
  useEffect(() => {
    const timer = setTimeout(() => {
      if (!hasCalledRef.current) {
        hasCalledRef.current = true;
        onComplete?.();
      }
    }, Math.max(minDuration + 1600, 4000));
    return () => clearTimeout(timer);
  }, [minDuration, onComplete]);

  return (
    <div style={{ position: 'relative', width: 520, height: 520, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <video
        src="/load.mp4"
        autoPlay
        loop
        muted
        playsInline
        onError={() => {
          if (!hasCalledRef.current) {
            hasCalledRef.current = true;
            onComplete?.();
          }
        }}
        style={{
          width: 500,
          height: 500,
          objectFit: 'contain',
          display: 'block',
          mixBlendMode: 'screen',
        }}
      />
    </div>
  );
}

const DEFAULT_STEPS = [];

export default function LoadingScreen({
  onComplete,
  isReady = true,
  variant = 'startup',
  steps = DEFAULT_STEPS,
  title = 'INITIALIZING SECURITY SYSTEM',
  subtitle = 'PREPARING SECURE WORKSPACE',
  versionLabel = 'Zenix Core v2.0 · Secure Session',
  stepDurationMs = 350,
  minDuration = 2400,
}) {
  const isProject = variant === 'project';
  const [currentStep, setCurrentStep] = useState(0);
  const [doneSteps, setDoneSteps] = useState([]);

  useEffect(() => {
    if (!isProject) return; 
    
    if (currentStep >= steps.length) {
      const t = setTimeout(() => onComplete?.(), 300);
      return () => clearTimeout(t);
    }

    const t = setTimeout(() => {
      setDoneSteps((prev) => [...prev, steps[currentStep].id]);
      setCurrentStep((s) => s + 1);
    }, stepDurationMs);

    return () => clearTimeout(t);
  }, [currentStep, onComplete, steps, stepDurationMs, isProject]);

  const progress = steps.length ? Math.min((doneSteps.length / steps.length) * 100, 100) : 100;

  return (
    <motion.div
      className={`loading-screen ${variant}`}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.25 }}
    >
      {isProject ? (
        <div style={{ width: 40, height: 40, borderRadius: '50%', border: '2px solid rgba(255,255,255,0.1)', borderTopColor: '#fff', animation: 'spin 1s linear infinite', marginBottom: 32 }} />
      ) : (
        <AppBootLoader isReady={isReady} onComplete={onComplete} minDuration={minDuration} />
      )}

      <div className="loading-copy" style={{ textAlign: 'center', marginTop: 4 }}>
        {!isProject ? (
          <>
            <h2 className="loading-title" style={{ fontFamily: 'var(--font-mono)', fontSize: 13, letterSpacing: 2, color: '#F1F5F9', fontWeight: 600 }}>
              {title}
            </h2>
            {subtitle && (
              <p className="loading-subtitle" style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: 1.5, color: '#38BDF8', marginTop: 6, opacity: 0.85 }}>
                {subtitle}
              </p>
            )}
          </>
        ) : (
          <>
            <h2 className="loading-title">{title}</h2>
            {subtitle && <p className="loading-subtitle">{subtitle}</p>}
          </>
        )}
      </div>

      {isProject && (
        <div className="loading-steps">
          {steps.map((step, idx) => {
            const isDone = doneSteps.includes(step.id);
            const isActive = idx === currentStep;
            const stepClass = isDone ? 'done' : isActive ? 'active' : '';
            return (
              <motion.div
                key={step.id}
                className={`loading-step ${stepClass}`}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: isDone || isActive ? 1 : 0.3, x: 0 }}
                transition={{ duration: 0.25, delay: idx * 0.05 }}
              >
                <div className="loading-step-dot" />
                <span>{step.label}</span>
                {isDone && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-verified)' }}
                  >
                    OK
                  </motion.span>
                )}
              </motion.div>
            );
          })}
        </div>
      )}

      {isProject && (
        <>
          <div className="loading-bar-container">
            <motion.div className="loading-bar-fill" style={{ width: `${progress}%` }} />
          </div>
          <div className="loading-version">{versionLabel}</div>
        </>
      )}
    </motion.div>
  );
}
