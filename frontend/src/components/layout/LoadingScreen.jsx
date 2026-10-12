/**
 * LoadingScreen
 *
 * System initialization sequence shown before the app shell mounts.
 * Each step corresponds to a real backend subsystem.
 * Fast, minimal, technical.
 */

import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const STEPS = [
  { id: 'core',     label: 'Initializing Zenix Core' },
  { id: 'modules',  label: 'Loading Security Modules' },
  { id: 'engine',   label: 'Connecting Analysis Engine' },
  { id: 'evidence', label: 'Validating Runtime Evidence' },
  { id: 'ready',    label: 'Opening Workspace' },
];

const STEP_DURATION_MS = 350;

// Zenix mark SVG (same as login, minimal version)
function LoadingMark() {
  return (
    <motion.svg
      width="52" height="52" viewBox="0 0 100 100" fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <motion.path
        d="M 50 8 L 92 78 L 8 78 Z"
        stroke="rgba(124,38,236,0.5)"
        strokeWidth="2"
        fill="none"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 0.8, ease: 'easeInOut' }}
      />
      <motion.path
        d="M 50 22 L 80 70 L 20 70 Z"
        stroke="rgba(32,225,163,0.7)"
        strokeWidth="1.5"
        fill="none"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 0.7, delay: 0.3, ease: 'easeInOut' }}
      />
      <motion.line x1="50" y1="0" x2="50" y2="10"
        stroke="rgba(255,255,255,0.2)" strokeWidth="1.5"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }}
        transition={{ delay: 0.8 }}
      />
    </motion.svg>
  );
}

/**
 * @param {{ onComplete: function }} props
 */
export default function LoadingScreen({ onComplete }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [doneSteps, setDoneSteps] = useState([]);

  useEffect(() => {
    if (currentStep >= STEPS.length) {
      // All steps done — call onComplete after a brief pause
      const t = setTimeout(onComplete, 300);
      return () => clearTimeout(t);
    }

    const t = setTimeout(() => {
      setDoneSteps((prev) => [...prev, STEPS[currentStep].id]);
      setCurrentStep((s) => s + 1);
    }, STEP_DURATION_MS);

    return () => clearTimeout(t);
  }, [currentStep, onComplete]);

  const progress = Math.min((doneSteps.length / STEPS.length) * 100, 100);

  return (
    <motion.div
      className="loading-screen"
      exit={{ opacity: 0 }}
      transition={{ duration: 0.4 }}
    >
      {/* Logo mark */}
      <div className="loading-mark">
        <LoadingMark />
      </div>

      {/* Step list */}
      <div className="loading-steps">
        {STEPS.map((step, idx) => {
          const isDone   = doneSteps.includes(step.id);
          const isActive = idx === currentStep;
          const stepClass = isDone ? 'done' : isActive ? 'active' : '';

          return (
            <motion.div
              key={step.id}
              className={`loading-step ${stepClass}`}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: isDone || isActive ? 1 : 0.3, x: 0 }}
              transition={{ duration: 0.25, delay: idx * 0.04 }}
            >
              <div className="loading-step-dot" />
              <span>{step.label}</span>
              {isDone && (
                <motion.span
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  style={{
                    marginLeft: 'auto',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    color: 'var(--color-verified)',
                  }}
                >
                  OK
                </motion.span>
              )}
            </motion.div>
          );
        })}
      </div>

      {/* Progress bar */}
      <div className="loading-bar-container">
        <motion.div
          className="loading-bar-fill"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Version label */}
      <div className="loading-version">Zenix Core v2.0 · Secure Session</div>
    </motion.div>
  );
}
