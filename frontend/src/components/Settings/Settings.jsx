import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { usersAPI } from '../../services/api';
import './Settings.css';

const Settings = () => {
  const { user, updateUser } = useAuth();
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

  useEffect(() => {
    loadSettings();
  }, []);

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
    } catch (error) {
      setMessage('Failed to save settings');
      console.error('Failed to save settings:', error);
    } finally {
      setSaving(false);
    }
  };

  const updateSetting = (key, value) => {
    if (key.includes('.')) {
      const [parent, child] = key.split('.');
      setSettings({
        ...settings,
        [parent]: {
          ...settings[parent],
          [child]: value,
        },
      });
    } else {
      setSettings({ ...settings, [key]: value });
    }
  };

  if (loading) {
    return <div className="loading">Loading settings...</div>;
  }

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
          <button className="tab-btn active">General</button>
          <button className="tab-btn">Notifications</button>
          <button className="tab-btn">Security</button>
        </div>

        <div className="settings-content">
          <div className="settings-group">
            <h3>General Settings</h3>

            <div className="setting-item">
              <label>Theme</label>
              <select
                value={settings.theme}
                onChange={(e) => updateSetting('theme', e.target.value)}
              >
                <option value="dark">Dark Mode</option>
                <option value="light">Light Mode</option>
                <option value="auto">Auto</option>
              </select>
            </div>

            <div className="setting-item">
              <label>Default Scan Depth</label>
              <select
                value={settings.default_scan_depth}
                onChange={(e) => updateSetting('default_scan_depth', e.target.value)}
              >
                <option value="shallow">Shallow - Quick scan</option>
                <option value="medium">Medium - Standard scan</option>
                <option value="deep">Deep - Comprehensive scan</option>
              </select>
            </div>

            <div className="setting-item">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={settings.auto_save}
                  onChange={(e) => updateSetting('auto_save', e.target.checked)}
                />
                Auto-save scan configurations
              </label>
            </div>
          </div>

          <div className="settings-group">
            <h3>Notification Preferences</h3>

            <div className="setting-item">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={settings.notifications.email}
                  onChange={(e) => updateSetting('notifications.email', e.target.checked)}
                />
                Email notifications
              </label>
            </div>

            <div className="setting-item">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={settings.notifications.browser}
                  onChange={(e) => updateSetting('notifications.browser', e.target.checked)}
                />
                Browser notifications
              </label>
            </div>

            <div className="setting-item">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={settings.notifications.sms}
                  onChange={(e) => updateSetting('notifications.sms', e.target.checked)}
                />
                SMS notifications
              </label>
            </div>
          </div>
        </div>

        <div className="settings-actions">
          <button className="btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </div>
    </section>
  );
};

export default Settings;

