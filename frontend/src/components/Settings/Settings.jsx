import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { usersAPI, integrationsAPI, authAPI } from '../../services/api';
import './Settings.css';

/* ── base64url helpers ── */
const b64urlEncode = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const b64urlToBuffer = (b64) => {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
};

/* ════════════════════════════════════════
   Security Tab — PIN + Biometric management
════════════════════════════════════════ */
const SecurityTab = ({ userId }) => {
  const [hasPin, setHasPin]           = useState(false);
  const [pinMode, setPinMode]         = useState(null); // null | 'setup' | 'change'
  const [passkeys, setPasskeys]       = useState([]);
  const [pin, setPin]                 = useState('');
  const [confirm, setConfirm]         = useState('');
  const [oldPin, setOldPin]           = useState('');
  const [busy, setBusy]               = useState(false);
  const [bioStatus, setBioStatus]     = useState(null); // null | 'ok' | 'err'
  const [bioMsg, setBioMsg]           = useState('');
  const [msg, setMsg]                 = useState(null);
  const pinRef = useRef(null);

  const flash = (text, ok = true) => {
    setMsg({ text, ok });
    setTimeout(() => setMsg(null), 4000);
  };

  useEffect(() => { if (userId) load(); }, [userId]);

  const load = async () => {
    try {
      const [status, creds] = await Promise.all([
        authAPI.pinStatus(userId),
        authAPI.listPasskeys(userId).catch(() => []),
      ]);
      setHasPin(status.has_pin);
      setPasskeys(creds);
    } catch { /* ignore */ }
  };

  /* ── PIN ── */
  const handlePinSave = async () => {
    if (!pin.match(/^\d{4,8}$/)) { flash('PIN must be 4–8 digits', false); return; }
    if (pin !== confirm) { flash('PINs do not match', false); return; }
    if (pinMode === 'change' && !oldPin.match(/^\d{4,8}$/)) { flash('Enter your current PIN', false); return; }
    setBusy(true);
    try {
      if (pinMode === 'change') {
        await authAPI.pinVerify(userId, oldPin);
      }
      await authAPI.pinSetup(userId, pin);
      flash(hasPin ? 'PIN changed successfully' : 'PIN set successfully');
      setHasPin(true);
      setPinMode(null);
      setPin(''); setConfirm(''); setOldPin('');
    } catch (e) {
      flash(e?.response?.data?.detail || 'PIN operation failed', false);
    } finally {
      setBusy(false);
    }
  };

  const handlePinRemove = async () => {
    if (!window.confirm('Remove your PIN?')) return;
    setBusy(true);
    try {
      await authAPI.pinRemove(userId);
      flash('PIN removed');
      setHasPin(false);
    } catch (e) {
      flash(e?.response?.data?.detail || 'Failed to remove PIN', false);
    } finally {
      setBusy(false);
    }
  };

  /* ── Biometric ── */
  const handleRegisterBiometric = async () => {
    setBioStatus(null); setBioMsg(''); setBusy(true);
    try {
      const opts = await authAPI.webauthnRegisterBegin(userId);
      const credential = await navigator.credentials.create({
        publicKey: {
          ...opts,
          challenge: b64urlToBuffer(opts.challenge),
          user: { ...opts.user, id: b64urlToBuffer(opts.user.id) },
        },
      });
      await authAPI.webauthnRegisterFinish({
        user_id:           userId,
        credential_id:     b64urlEncode(credential.rawId),
        public_key:        b64urlEncode(credential.response.getPublicKey?.() || new ArrayBuffer(0)),
        attestation_object: b64urlEncode(credential.response.attestationObject),
        client_data_json:  b64urlEncode(credential.response.clientDataJSON),
      });
      setBioStatus('ok');
      setBioMsg('Biometric registered! You can now use it to log in.');
      flash('Biometric registered successfully');
      await load();
    } catch (err) {
      const m = err?.name === 'NotAllowedError'
        ? 'Prompt cancelled'
        : err?.response?.data?.detail || err?.message || 'Registration failed';
      setBioStatus('err'); setBioMsg(m);
      flash(m, false);
    } finally {
      setBusy(false);
    }
  };

  const handleRemovePasskey = async (credId) => {
    if (!window.confirm('Remove this passkey?')) return;
    try {
      await authAPI.deletePasskey(userId, credId);
      flash('Passkey removed');
      setPasskeys(prev => prev.filter(p => p.id !== credId));
    } catch {
      flash('Failed to remove passkey', false);
    }
  };

  return (
    <div className="settings-group">
      <h3>Security &amp; Authentication</h3>
      <p className="settings-hint">
        Set up a PIN or biometric (Touch ID / Face ID / Windows Hello) so you can log in
        without typing your password every time.
      </p>

      {msg && (
        <div className={`integrations-msg ${msg.ok ? 'integrations-msg--ok' : 'integrations-msg--err'}`}>
          {msg.ok ? '✓' : '✕'} {msg.text}
        </div>
      )}

      {/* ── PIN Section ── */}
      <div className="sec-section">
        <div className="sec-section-header">
          <span className="sec-section-icon">🔑</span>
          <div>
            <strong>PIN Login</strong>
            <p className="sec-section-sub">
              {hasPin ? 'A PIN is set. You can use it to log in quickly.' : 'No PIN set yet.'}
            </p>
          </div>
          <div className="sec-section-actions">
            {!hasPin && (
              <button className="btn-sm btn-primary" onClick={() => { setPinMode('setup'); setTimeout(() => pinRef.current?.focus(), 50); }}>
                Set PIN
              </button>
            )}
            {hasPin && (
              <>
                <button className="btn-sm btn-secondary" onClick={() => { setPinMode('change'); setTimeout(() => pinRef.current?.focus(), 50); }}>
                  Change
                </button>
                <button className="btn-sm btn-danger" onClick={handlePinRemove} disabled={busy}>
                  Remove
                </button>
              </>
            )}
          </div>
        </div>

        {pinMode && (
          <div className="sec-pin-form">
            {pinMode === 'change' && (
              <div className="setting-item">
                <label>Current PIN</label>
                <input type="password" inputMode="numeric" maxLength={8}
                  value={oldPin} onChange={e => setOldPin(e.target.value.replace(/\D/g, ''))}
                  placeholder="Current PIN" className="sec-pin-input" />
              </div>
            )}
            <div className="setting-item">
              <label>{pinMode === 'change' ? 'New PIN' : 'PIN'} (4–8 digits)</label>
              <input ref={pinRef} type="password" inputMode="numeric" maxLength={8}
                value={pin} onChange={e => setPin(e.target.value.replace(/\D/g, ''))}
                placeholder="••••" className="sec-pin-input" />
            </div>
            <div className="setting-item">
              <label>Confirm PIN</label>
              <input type="password" inputMode="numeric" maxLength={8}
                value={confirm} onChange={e => setConfirm(e.target.value.replace(/\D/g, ''))}
                placeholder="••••" className="sec-pin-input"
                onKeyDown={e => e.key === 'Enter' && handlePinSave()} />
            </div>
            <div className="sec-pin-form-actions">
              <button className="btn-secondary btn-sm" onClick={() => { setPinMode(null); setPin(''); setConfirm(''); setOldPin(''); }}>
                Cancel
              </button>
              <button className="btn-primary btn-sm" onClick={handlePinSave} disabled={busy}>
                {busy ? 'Saving…' : pinMode === 'change' ? 'Change PIN' : 'Set PIN'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Biometric Section ── */}
      <div className="sec-section">
        <div className="sec-section-header">
          <span className="sec-section-icon">☝</span>
          <div>
            <strong>Biometric Login</strong>
            <p className="sec-section-sub">
              {passkeys.length > 0
                ? `${passkeys.length} passkey(s) registered. Use fingerprint or Face ID to log in.`
                : 'No biometric registered yet.'}
            </p>
          </div>
          <button className="btn-sm btn-primary" onClick={handleRegisterBiometric} disabled={busy}>
            {passkeys.length > 0 ? '+ Add Another' : 'Register'}
          </button>
        </div>

        {bioMsg && (
          <p className={`sec-bio-msg${bioStatus === 'ok' ? ' ok' : ' err'}`}>{bioMsg}</p>
        )}

        {passkeys.length > 0 && (
          <div className="sec-passkey-list">
            {passkeys.map((pk, i) => (
              <div key={pk.id || i} className="sec-passkey-row">
                <span className="sec-passkey-icon">🔐</span>
                <div className="sec-passkey-info">
                  <strong>{pk.name || `Passkey ${i + 1}`}</strong>
                  <span>{pk.created_at ? new Date(pk.created_at).toLocaleDateString() : 'Registered'}</span>
                </div>
                <button className="btn-sm btn-danger" onClick={() => handleRemovePasskey(pk.id)}>
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Password note ── */}
      <div className="sec-section sec-section--note">
        <span className="sec-section-icon">🔒</span>
        <p className="settings-hint" style={{ margin: 0 }}>
          Password changes and email MFA are managed through <strong>Supabase Auth</strong>.
        </p>
      </div>
    </div>
  );
};

// ── Integrations Tab ──────────────────────────────────────────────────────────
const INTEGRATION_TYPES = [
  {
    id: 'slack',
    label: 'Slack',
    icon: '💬',
    fields: [
      { key: 'webhook_url', label: 'Incoming Webhook URL', placeholder: 'https://hooks.slack.com/services/…', type: 'url' },
      { key: 'channel', label: 'Channel (optional)', placeholder: '#security-alerts', type: 'text' },
    ],
  },
  {
    id: 'teams',
    label: 'Microsoft Teams',
    icon: '🟣',
    fields: [
      { key: 'webhook_url', label: 'Incoming Webhook URL', placeholder: 'https://outlook.office.com/webhook/…', type: 'url' },
    ],
  },
  {
    id: 'webhook',
    label: 'Custom Webhook',
    icon: '🔗',
    fields: [
      { key: 'url', label: 'Endpoint URL', placeholder: 'https://your-server.com/webhook', type: 'url' },
      { key: 'secret', label: 'HMAC Secret (optional)', placeholder: 'Used to sign payloads', type: 'text' },
    ],
  },
  {
    id: 'email',
    label: 'Email (SendGrid)',
    icon: '📧',
    fields: [
      { key: 'api_key', label: 'SendGrid API Key', placeholder: 'SG.xxxx', type: 'text' },
      { key: 'from_email', label: 'From Email', placeholder: 'alerts@yourdomain.com', type: 'email' },
    ],
  },
];

const IntegrationsTab = () => {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(null);
  const [formValues, setFormValues] = useState({});
  const [formName, setFormName] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(null);
  const [msg, setMsg] = useState(null);

  const flash = (text, ok = true) => {
    setMsg({ text, ok });
    setTimeout(() => setMsg(null), 4000);
  };

  useEffect(() => { load(); }, []);

  const load = async () => {
    setLoading(true);
    try {
      const data = await integrationsAPI.list();
      setIntegrations(data);
    } catch {
      flash('Failed to load integrations', false);
    } finally {
      setLoading(false);
    }
  };

  const handleAdd = async (typeDef) => {
    setSaving(true);
    try {
      await integrationsAPI.create(typeDef.id, formName || typeDef.label, formValues);
      flash(`${typeDef.label} integration added!`);
      setAdding(null);
      setFormValues({});
      setFormName('');
      await load();
    } catch (e) {
      flash(e?.response?.data?.detail || 'Failed to save integration', false);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id, name) => {
    if (!window.confirm(`Remove "${name}"?`)) return;
    try {
      await integrationsAPI.delete(id);
      flash('Integration removed');
      setIntegrations(prev => prev.filter(i => i.id !== id));
    } catch {
      flash('Failed to remove', false);
    }
  };

  const handleTest = async (id) => {
    setTesting(id);
    try {
      const res = await integrationsAPI.test(id);
      flash(res.message || 'Test sent!', res.status === 'success');
    } catch (e) {
      flash(e?.response?.data?.detail || 'Test failed', false);
    } finally {
      setTesting(null);
    }
  };

  const typeDef = INTEGRATION_TYPES.find(t => t.id === adding);

  if (loading) return <div className="integrations-loading">Loading integrations…</div>;

  return (
    <div className="integrations-tab">
      {msg && (
        <div className={`integrations-msg ${msg.ok ? 'integrations-msg--ok' : 'integrations-msg--err'}`}>
          {msg.ok ? '✓' : '✕'} {msg.text}
        </div>
      )}

      {integrations.length > 0 && (
        <div className="integrations-list">
          <h4>Active Integrations</h4>
          {integrations.map(i => {
            const def = INTEGRATION_TYPES.find(t => t.id === i.type);
            return (
              <div key={i.id} className="integration-row">
                <span className="integration-row__icon">{def?.icon || '🔌'}</span>
                <div className="integration-row__info">
                  <strong>{i.name}</strong>
                  <span className="integration-row__type">{i.type}</span>
                </div>
                <div className="integration-row__actions">
                  <button className="btn-sm btn-secondary" onClick={() => handleTest(i.id)} disabled={testing === i.id}>
                    {testing === i.id ? 'Sending…' : 'Test'}
                  </button>
                  <button className="btn-sm btn-danger" onClick={() => handleDelete(i.id, i.name)}>
                    Remove
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {!adding ? (
        <div className="integrations-add-grid">
          <h4>Add Integration</h4>
          <div className="integration-type-grid">
            {INTEGRATION_TYPES.map(t => (
              <button key={t.id} className="integration-type-card"
                onClick={() => { setAdding(t.id); setFormValues({}); setFormName(t.label); }}>
                <span className="integration-type-card__icon">{t.icon}</span>
                <span>{t.label}</span>
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="integration-form">
          <h4>{typeDef?.icon} Configure {typeDef?.label}</h4>
          <div className="setting-item">
            <label>Name</label>
            <input type="text" value={formName} onChange={e => setFormName(e.target.value)} placeholder={`My ${typeDef?.label}`} />
          </div>
          {typeDef?.fields.map(f => (
            <div key={f.key} className="setting-item">
              <label>{f.label}</label>
              <input type={f.type} value={formValues[f.key] || ''}
                onChange={e => setFormValues(prev => ({ ...prev, [f.key]: e.target.value }))}
                placeholder={f.placeholder} />
            </div>
          ))}
          <div className="integration-form-actions">
            <button className="btn-secondary" onClick={() => setAdding(null)}>Cancel</button>
            <button className="btn-primary" onClick={() => handleAdd(typeDef)} disabled={saving}>
              {saving ? 'Saving…' : 'Save Integration'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// ── Main Settings Component ───────────────────────────────────────────────────
const TABS = ['General', 'Notifications', 'Integrations', 'Security & Auth'];

const Settings = () => {
  const { user, updateUser } = useAuth();
  const [activeTab, setActiveTab] = useState('General');
  const [settings, setSettings] = useState({
    theme: 'dark',
    notifications: {
      email: true,
      browser: true,
      sms: false,
    },
    default_scan_depth: 'medium',
    auto_save: true,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => { loadSettings(); }, []);

  const loadSettings = async () => {
    try {
      const data = await usersAPI.getSettings();
      setSettings(data);
    } catch (error) {
      console.error('Failed to load settings:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage('');
    try {
      const updated = await usersAPI.updateSettings(settings);
      setSettings(updated.settings);
      updateUser({ settings: updated.settings });
      setMessage('Settings saved successfully!');
      setTimeout(() => setMessage(''), 3000);
    } catch {
      setMessage('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const updateSetting = (key, value) => {
    if (key.includes('.')) {
      const [parent, child] = key.split('.');
      setSettings(s => ({ ...s, [parent]: { ...s[parent], [child]: value } }));
    } else {
      setSettings(s => ({ ...s, [key]: value }));
    }
  };

  if (loading) return <div className="loading">Loading settings…</div>;

  return (
    <section className="settings-section">
      <div className="section-header">
        <h1 className="section-title">Settings</h1>
        <p className="section-subtitle">Manage your preferences and account settings</p>
      </div>

      {message && (
        <div className={`message ${message.includes('success') ? 'success' : 'error'}`}>
          {message}
        </div>
      )}

      <div className="settings-container">
        <div className="settings-tabs">
          {TABS.map(tab => (
            <button key={tab} className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
              onClick={() => setActiveTab(tab)}>
              {tab}
            </button>
          ))}
        </div>

        <div className="settings-content">

          {activeTab === 'General' && (
            <div className="settings-group">
              <h3>General Settings</h3>
              <div className="setting-item">
                <label>Theme</label>
                <select value={settings.theme} onChange={e => updateSetting('theme', e.target.value)}>
                  <option value="dark">Dark Mode</option>
                  <option value="light">Light Mode</option>
                  <option value="auto">Auto</option>
                </select>
              </div>
              <div className="setting-item">
                <label>Default Scan Depth</label>
                <select value={settings.default_scan_depth} onChange={e => updateSetting('default_scan_depth', e.target.value)}>
                  <option value="shallow">Shallow — Quick scan</option>
                  <option value="medium">Medium — Standard scan</option>
                  <option value="deep">Deep — Comprehensive scan</option>
                </select>
              </div>
              <div className="setting-item">
                <label className="checkbox-label">
                  <input type="checkbox" checked={settings.auto_save}
                    onChange={e => updateSetting('auto_save', e.target.checked)} />
                  Auto-save scan configurations
                </label>
              </div>
            </div>
          )}

          {activeTab === 'Notifications' && (
            <div className="settings-group">
              <h3>Notification Preferences</h3>
              <div className="setting-item">
                <label className="checkbox-label">
                  <input type="checkbox" checked={settings.notifications?.email}
                    onChange={e => updateSetting('notifications.email', e.target.checked)} />
                  Email notifications
                </label>
              </div>
              <div className="setting-item">
                <label className="checkbox-label">
                  <input type="checkbox" checked={settings.notifications?.browser}
                    onChange={e => updateSetting('notifications.browser', e.target.checked)} />
                  Browser notifications
                </label>
              </div>
              <div className="setting-item">
                <label className="checkbox-label">
                  <input type="checkbox" checked={settings.notifications?.sms}
                    onChange={e => updateSetting('notifications.sms', e.target.checked)} />
                  SMS notifications
                </label>
              </div>
            </div>
          )}

          {activeTab === 'Integrations' && <IntegrationsTab />}

          {activeTab === 'Security & Auth' && (
            <SecurityTab userId={user?.id} />
          )}

        </div>

        {activeTab !== 'Integrations' && activeTab !== 'Security & Auth' && (
          <div className="settings-actions">
            <button className="btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? 'Saving…' : 'Save Settings'}
            </button>
          </div>
        )}
      </div>
    </section>
  );
};

export default Settings;
