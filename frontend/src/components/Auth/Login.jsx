import { useState, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { authAPI } from '../../services/api';
import { supabase } from '../../lib/supabase';
import './Auth.css';

/* ── base64url helpers for WebAuthn ── */
const b64urlEncode = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const b64urlToBuffer = (b64) => {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
};

const Login = () => {
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [pin, setPin]           = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [mode, setMode]         = useState('password'); // 'password' | 'pin' | 'biometric'
  const [pinStep, setPinStep]   = useState('email');    // 'email' | 'pin'
  const { login } = useAuth();
  const navigate  = useNavigate();
  const pinRef    = useRef(null);

  /* ── Email + Password ── */
  const handlePasswordLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  /* ── PIN login ── */
  const handlePinEmailNext = (e) => {
    e.preventDefault();
    if (!email) { setError('Enter your email first'); return; }
    setError('');
    setPinStep('pin');
    setTimeout(() => pinRef.current?.focus(), 50);
  };

  const handlePinLogin = async (e) => {
    e.preventDefault();
    if (!pin.match(/^\d{4,8}$/)) { setError('PIN must be 4–8 digits'); return; }
    setError('');
    setLoading(true);
    try {
      const res = await authAPI.pinLoginVerify(email, pin);
      if (res.success) {
        // Exchange OTP for a real session (no email sent)
        const { error: sessionErr } = await supabase.auth.verifyOtp({
          email,
          token: res.otp,
          type: 'email',
        });
        if (sessionErr) {
          setError('PIN verified but session failed: ' + sessionErr.message);
        } else {
          navigate('/dashboard');
        }
      } else {
        setError('Incorrect PIN');
      }
    } catch (err) {
      setError(err?.response?.data?.detail || 'Invalid email or PIN');
    } finally {
      setLoading(false);
    }
  };

  /* ── Biometric (WebAuthn) login ── */
  const handleBiometricLogin = async () => {
    if (!email) { setError('Enter your email address first'); return; }
    setError('');
    setLoading(true);
    try {
      // 1. Resolve user_id from email
      const { user_id } = await authAPI.userIdByEmail(email);

      // 2. Get WebAuthn challenge
      const opts = await authAPI.webauthnAuthBegin(user_id);

      // 3. Browser biometric prompt
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge:        b64urlToBuffer(opts.challenge),
          rpId:             opts.rpId,
          allowCredentials: opts.allowCredentials.map(c => ({
            ...c, id: b64urlToBuffer(c.id),
          })),
          userVerification: opts.userVerification,
          timeout:          opts.timeout,
        },
      });

      // 4. Verify credential on backend
      const verifyRes = await authAPI.webauthnAuthFinish({
        user_id,
        credential_id:      b64urlEncode(assertion.rawId),
        authenticator_data: b64urlEncode(assertion.response.authenticatorData),
        client_data_json:   b64urlEncode(assertion.response.clientDataJSON),
        signature:          b64urlEncode(assertion.response.signature),
      });

      // 5. Credential verified — exchange OTP for a real session (no email sent)
      const { error: sessionErr } = await supabase.auth.verifyOtp({
        email,
        token: verifyRes.otp,
        type: 'email',
      });
      if (sessionErr) {
        setError('Biometric verified but session failed: ' + sessionErr.message);
      } else {
        navigate('/dashboard');
      }
    } catch (err) {
      const msg =
        err?.name === 'NotAllowedError'   ? 'Biometric prompt was cancelled' :
        err?.response?.data?.detail       ? err.response.data.detail :
        err?.message                      || 'Biometric login failed';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-brand">
            <img src="/pixel-shield.svg" alt="SecureScan logo" className="auth-brand-logo" />
            <h1 className="auth-brand-title">SecureScan <span className="auth-brand-pro">Pro</span></h1>
          </div>
          <p>Sign in to your account</p>
        </div>

        {/* ── Quick login method selector ── */}
        <div className="auth-quick-btns">
          <button
            type="button"
            className={`auth-quick-btn${mode === 'biometric' ? ' active' : ''}`}
            onClick={() => { setMode('biometric'); setError(''); }}
            title="Sign in with fingerprint or Face ID"
          >
            <span className="auth-quick-icon">☝</span>
            <span>Biometric</span>
          </button>
          <button
            type="button"
            className={`auth-quick-btn${mode === 'pin' ? ' active' : ''}`}
            onClick={() => { setMode('pin'); setPinStep('email'); setError(''); }}
            title="Sign in with PIN"
          >
            <span className="auth-quick-icon">🔑</span>
            <span>PIN</span>
          </button>
          <button
            type="button"
            className={`auth-quick-btn${mode === 'password' ? ' active' : ''}`}
            onClick={() => { setMode('password'); setError(''); }}
            title="Sign in with email & password"
          >
            <span className="auth-quick-icon">🔒</span>
            <span>Password</span>
          </button>
        </div>

        {error && <div className="error-message">{error}</div>}

        {/* ── Password form ── */}
        {mode === 'password' && (
          <form onSubmit={handlePasswordLogin} className="auth-form">
            <div className="form-group">
              <label htmlFor="email">Email</label>
              <input type="email" id="email" value={email}
                onChange={e => setEmail(e.target.value)} required placeholder="your@email.com" />
            </div>
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input type="password" id="password" value={password}
                onChange={e => setPassword(e.target.value)} required placeholder="••••••••" />
            </div>
            <button type="submit" className="btn-primary btn-block" disabled={loading}>
              {loading ? 'Signing in…' : 'Sign In'}
            </button>
          </form>
        )}

        {/* ── PIN form ── */}
        {mode === 'pin' && (
          <form onSubmit={pinStep === 'email' ? handlePinEmailNext : handlePinLogin} className="auth-form">
            <div className="form-group">
              <label htmlFor="pin-email">Email</label>
              <input type="email" id="pin-email" value={email}
                onChange={e => setEmail(e.target.value)} required placeholder="your@email.com"
                disabled={pinStep === 'pin'} />
            </div>
            {pinStep === 'pin' && (
              <div className="form-group">
                <label>PIN</label>
                <div className="auth-pin-dots">
                  {Array.from({ length: Math.max(4, pin.length) }).map((_, i) => (
                    <div key={i} className={`auth-pin-dot${i < pin.length ? ' filled' : ''}`} />
                  ))}
                </div>
                <input
                  ref={pinRef}
                  type="password"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={8}
                  value={pin}
                  onChange={e => setPin(e.target.value.replace(/\D/g, ''))}
                  placeholder="••••"
                  className="auth-pin-field"
                />
              </div>
            )}
            <button type="submit" className="btn-primary btn-block" disabled={loading}>
              {loading ? 'Verifying…' : pinStep === 'email' ? 'Continue →' : 'Sign In with PIN'}
            </button>
            {pinStep === 'pin' && (
              <button type="button" className="auth-back-btn"
                onClick={() => { setPinStep('email'); setPin(''); setError(''); }}>
                ← Back
              </button>
            )}
          </form>
        )}

        {/* ── Biometric form ── */}
        {mode === 'biometric' && (
          <div className="auth-form">
            <div className="form-group">
              <label htmlFor="bio-email">Email</label>
              <input type="email" id="bio-email" value={email}
                onChange={e => setEmail(e.target.value)} placeholder="your@email.com" />
            </div>
            <p className="auth-bio-hint">
              Register your biometric first in <strong>Settings → Security &amp; Auth</strong>.
            </p>
            <button type="button" className="btn-primary btn-block auth-bio-btn"
              onClick={handleBiometricLogin} disabled={loading}>
              {loading ? 'Verifying…' : '☝  Verify with Biometric'}
            </button>
          </div>
        )}

        <div className="auth-footer">
          <p>Don't have an account? <Link to="/register">Sign up</Link></p>
        </div>
      </div>
    </div>
  );
};

export default Login;
