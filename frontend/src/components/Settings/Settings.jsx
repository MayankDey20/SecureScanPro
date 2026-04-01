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

/* ── Cyber UI Components ── */
const CyberToggle = ({ checked, onChange, label, desc }) => (
  <div className="setting-item">
    <div className="setting-item-label">
      <label>{label}</label>
      {desc && <p className="setting-item-desc">{desc}</p>}
    </div>
    <label className="cyber-toggle">
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} />
      <span className="toggle-slider"></span>
    </label>
  </div>
);

const CyberSelect = ({ value, onChange, label, options, desc }) => (
  <div className="setting-item">
    <div className="setting-item-label">
      <label>{label}</label>
      {desc && <p className="setting-item-desc">{desc}</p>}
    </div>
    <select className="cyber-select" value={value} onChange={e => onChange(e.target.value)}>
      {options.map(opt => (
        <option key={opt.value} value={opt.value}>{opt.label}</option>
      ))}
    </select>
  </div>
);

/* ════════════════════════════════════════
   Security Section — PIN + Biometric
   ════════════════════════════════════════ */
const SecurityCard = ({ userId }) => {
  const [hasPin, setHasPin]           = useState(false);
  const [pinMode, setPinMode]         = useState(null); 
  const [passkeys, setPasskeys]       = useState([]);
  const [pin, setPin]                 = useState('');
  const [confirm, setConfirm]         = useState('');
  const [busy, setBusy]               = useState(false);
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

  const handlePinSave = async () => {
    if (!pin.match(/^\d{4,8}$/)) { flash('PIN must be 4–8 digits', false); return; }
    if (pin !== confirm) { flash('PINs parity mismatch', false); return; }
    setBusy(true);
    try {
      await authAPI.pinSetup(userId, pin);
      flash(hasPin ? 'PIN_REVISED' : 'PIN_ESTABLISHED');
      setHasPin(true); setPinMode(null); setPin(''); setConfirm('');
    } catch (e) {
      flash('PIN_SET_DENIED', false);
    } finally { setBusy(false); }
  };

  const handleRegisterBiometric = async () => {
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
      flash('BIO_IDENTITY_LINKED');
      await load();
    } catch (err) {
      flash('HANDSHAKE_FAILED', false);
    }
  };

  return (
    <div className="settings-card">
      <h3>Access Security</h3>
      <div className="sec-section-header mb-6 items-center gap-4">
        <span className="material-symbols-outlined text-2xl text-secondary">dialpad</span>
        <div className="flex-1">
          <label className="text-[10px] font-pixel text-slate-500 uppercase">PIN Authentication</label>
          <div className="text-xs font-mono text-primary mt-1">{hasPin ? 'ENCRYPTED_PIN_ACTIVE' : 'NO_PIN_DETECTED'}</div>
        </div>
        <button className="btn-cyber-action" onClick={() => { setPinMode('setup'); setTimeout(() => pinRef.current?.focus(), 50); }}>
          {hasPin ? 'REVISE' : 'ESTABLISH'}
        </button>
      </div>

      {pinMode && (
        <div className="bg-black/20 p-6 rounded-xl border border-white/5 grid gap-4 mb-8">
           <div className="flex justify-between items-center bg-white/5 p-3 rounded">
              <label className="text-[8px] font-pixel text-slate-500 uppercase">Input PIN</label>
              <input ref={pinRef} type="password" inputMode="numeric" maxLength={8} value={pin} onChange={e => setPin(e.target.value.replace(/\D/g, ''))} className="bg-transparent text-right text-primary font-mono outline-none w-24" />
           </div>
           <div className="flex justify-between items-center bg-white/5 p-3 rounded">
              <label className="text-[8px] font-pixel text-slate-500 uppercase">Verify PIN</label>
              <input type="password" inputMode="numeric" maxLength={8} value={confirm} onChange={e => setConfirm(e.target.value.replace(/\D/g, ''))} className="bg-transparent text-right text-primary font-mono outline-none w-24" />
           </div>
           <div className="flex justify-end gap-2 mt-2">
              <button className="btn-sm btn-secondary" onClick={() => setPinMode(null)}>Abort</button>
              <button className="btn-sm btn-primary" onClick={handlePinSave} disabled={busy}>Commit</button>
           </div>
        </div>
      )}

      <div className="sec-section-header items-center gap-4 border-t border-white/5 pt-6">
        <span className="material-symbols-outlined text-2xl text-primary">fingerprint</span>
        <div className="flex-1">
          <label className="text-[10px] font-pixel text-slate-500 uppercase">Biometric Mapping</label>
          <div className="text-xs font-mono text-primary mt-1">{passkeys.length > 0 ? `${passkeys.length}_ID_VECTORS` : 'NO_ID_MAPPING'}</div>
        </div>
        <button className="btn-cyber-action" onClick={handleRegisterBiometric}>LINK</button>
      </div>

      {msg && (
        <div className={`mt-6 text-center text-[8px] font-pixel tracking-widest ${msg.ok ? 'text-primary' : 'text-red-500'}`}>
          {msg.text}
        </div>
      )}
    </div>
  );
};

/* ── Integrations ── */
const INTEGRATION_TYPES = [
  { id: 'slack', label: 'Slack', icon: '💬', color: 'text-purple-400' },
  { id: 'teams', label: 'Teams', icon: '🟣', color: 'text-blue-500' },
  { id: 'webhook', label: 'Webhook', icon: '🔗', color: 'text-emerald-400' },
  { id: 'email', label: 'Email', icon: '📧', color: 'text-blue-400' },
];

const IntegrationsCard = () => {
  const [integrations, setIntegrations] = useState([]);

  useEffect(() => { integrationsAPI.list().then(setIntegrations); }, []);

  return (
    <div className="settings-card">
      <h3>Communication Matrix</h3>
      <div className="integration-type-grid">
         {INTEGRATION_TYPES.map(t => {
           const linked = integrations.find(i => i.type === t.id);
           return (
             <div key={t.id} className="integration-type-card hover:translate-y-[-2px]">
               <span className={`integration-type-card__icon ${t.color}`}>{t.icon}</span>
               <div className="text-[8px] font-pixel text-slate-500 uppercase tracking-widest mt-1">{t.label}</div>
               <span className={`status-badge mt-2 ${linked ? 'active' : ''}`}>
                 {linked ? 'LINKED' : 'VOID'}
               </span>
             </div>
           );
         })}
      </div>
    </div>
  );
};

/* ── Main Dashboard ── */
const Settings = () => {
  const { user, updateUser } = useAuth();
  const [settings, setSettings] = useState({
    theme: 'dark',
    notifications: { email: true, browser: true, sms: false },
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
    } catch { /* ignore */ } finally { setLoading(false); }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const updated = await usersAPI.updateSettings(settings);
      setSettings(updated.settings);
      updateUser({ settings: updated.settings });
      setMessage('SUCCESS: SYS_PARAMS_SYNCED');
      setTimeout(() => setMessage(''), 3000);
    } catch { setMessage('ERROR: SYNC_FAILED'); } finally { setSaving(false); }
  };

  const updateSetting = (key, value) => {
    if (key.includes('.')) {
      const [parent, child] = key.split('.');
      setSettings(s => ({ ...s, [parent]: { ...s[parent], [child]: value } }));
    } else {
      setSettings(s => ({ ...s, [key]: value }));
    }
  };

  if (loading) return <div className="loading-container"><div className="spinner"></div><span>QUERYING_CONFIG...</span></div>;

  return (
    <section className="settings-section">
      <div className="section-header">
        <h1 className="section-title">Command Center</h1>
        <p className="section-subtitle">System configuration & operational parameters</p>
      </div>

      <div className="max-w-6xl mx-auto">
        {message && (
          <div className={`mb-12 p-6 rounded-xl font-pixel text-[10px] text-center border ${message.includes('SUCCESS') ? 'bg-primary/10 border-primary/20 text-primary' : 'bg-red-500/10 border-red-500/20 text-red-500'}`}>
            {message}
          </div>
        )}

        <div className="settings-grid">
          {/* General Card */}
          <div className="settings-card">
            <h3>Operational Base</h3>
            <CyberSelect 
              label="UI Theme Layer" 
              desc="System visual core synchronization"
              value={settings.theme} 
              onChange={v => updateSetting('theme', v)}
              options={[
                { value: 'dark', label: 'VOID_PROTOCOL (DARK)' },
                { value: 'light', label: 'PRISM_ARRAY (LIGHT)' },
                { value: 'auto', label: 'AUTO_SYNC' }
              ]}
            />
            <CyberSelect 
              label="Inspection Depth" 
              desc="Baseline recursive scan density"
              value={settings.default_scan_depth} 
              onChange={v => updateSetting('default_scan_depth', v)}
              options={[
                { value: 'shallow', label: 'L1_SUPERFICIAL' },
                { value: 'medium', label: 'L2_BALANCED' },
                { value: 'deep', label: 'L3_HEAVY_SCAN' }
              ]}
            />
            <CyberToggle 
              label="State Persistence" 
              desc="Auto-commit vector configurations"
              checked={settings.auto_save} 
              onChange={v => updateSetting('auto_save', v)} 
            />
          </div>

          {/* Notifications Card */}
          <div className="settings-card">
            <h3>Alerting Vectors</h3>
            <CyberToggle 
              label="Secure Relay (Email)" 
              desc="Push alerts to verified SMTP channel"
              checked={settings.notifications?.email} 
              onChange={v => updateSetting('notifications.email', v)} 
            />
            <CyberToggle 
              label="Overlay Push (Browser)" 
              desc="OS-level notification broadcast"
              checked={settings.notifications?.browser} 
              onChange={v => updateSetting('notifications.browser', v)} 
            />
            <CyberToggle 
              label="Mobile Dispatch (SMS)" 
              desc="Critical cellular override alerts"
              checked={settings.notifications?.sms} 
              onChange={v => updateSetting('notifications.sms', v)} 
            />
          </div>

          {/* Security Card */}
          <SecurityCard userId={user?.id} />

          {/* Integrations Card */}
          <IntegrationsCard />
        </div>

        <div className="mt-12 flex justify-center">
           <button className="btn-update min-w-[300px]" onClick={handleSave} disabled={saving}>
             {saving ? 'SYNCING_PARAMS...' : 'COMMIT ALL CHANGES'}
           </button>
        </div>
      </div>
    </section>
  );
};

export default Settings;
