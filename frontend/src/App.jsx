import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import LandingPage from './components/dashboard/LandingPage';
import Dashboard from './components/dashboard/Dashboard';
import { X, Shield } from 'lucide-react';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showLoginModal, setShowLoginModal] = useState(false);

  useEffect(() => {
    // Check persistence
    const auth = localStorage.getItem('zenix_auth');
    if (auth === 'true') {
      setIsLoggedIn(true);
    }
  }, []);

  const handleLogin = (e) => {
    e.preventDefault();
    const email = e.target[0].value;
    const password = e.target[1].value;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      alert("Please enter a valid email address.");
      return;
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(password)) {
      alert("Password must be at least 8 characters, include one uppercase letter and one number.");
      return;
    }

    localStorage.setItem('zenix_auth', 'true');
    setIsLoggedIn(true);
    setShowLoginModal(false);
  };

  const handleLogout = () => {
    localStorage.removeItem('zenix_auth');
    setIsLoggedIn(false);
  };

  const openLogin = () => setShowLoginModal(true);
  const closeLogin = () => setShowLoginModal(false);

  return (
    <div className="app-container">
      <Routes>
        <Route 
          path="/" 
          element={isLoggedIn ? <Navigate to="/dashboard/overview" /> : <LandingPage onLogin={openLogin} />} 
        />
        <Route 
          path="/dashboard/*" 
          element={isLoggedIn ? <Dashboard onLogout={handleLogout} /> : <Navigate to="/" />} 
        />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>


      {/* Login Modal */}
      <div
        className={`modal-overlay ${showLoginModal ? 'active' : ''}`}
        onClick={(e) => {
          if (e.target.className.includes('modal-overlay')) closeLogin();
        }}
      >
        <div className="modal-content">
          <button className="modal-close" onClick={closeLogin}>
            <X size={24} />
          </button>
          <div className="modal-header">
            <h2>Enterprise Login</h2>
            <p>Secure Access for Authorized Personnel</p>
          </div>
          <form onSubmit={handleLogin}>
            <div className="input-group">
              <label>Work Email</label>
              <input type="email" placeholder="name@organization.com" required />
            </div>
            <div className="input-group">
              <label>Password</label>
              <input type="password" placeholder="••••••••" required />
            </div>
            <div
              style={{
                marginBottom: '20px',
                fontSize: '0.85rem',
                color: '#666',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <Shield size={14} /> SSO Enabled for your domain
            </div>
            <button
              type="submit"
              className="btn btn-primary full-width"
              style={{ width: '100%', justifyContent: 'center' }}
            >
              Authenticate & Sign In
            </button>
          </form>
          <div className="modal-footer" style={{ textAlign: 'center' }}>
            <a href="#" style={{ fontSize: '0.8rem', color: '#555' }}>
              Forgot Password?
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;