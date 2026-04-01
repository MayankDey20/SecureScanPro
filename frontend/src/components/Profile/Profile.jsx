import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { usersAPI } from '../../services/api';
import './Profile.css';

const Profile = () => {
  const { user, updateUser } = useAuth();
  const [formData, setFormData] = useState({
    full_name: '',
    email: '',
  });
  const [passwordData, setPasswordData] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (user) {
      setFormData({
        full_name: user.full_name || '',
        email: user.email || '',
      });
    }
  }, [user]);

  const handleProfileUpdate = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const updated = await usersAPI.updateProfile(formData);
      updateUser(updated);
      setMessage('SUCCESS: Profile synchronized');
      setTimeout(() => setMessage(''), 5000);
    } catch (error) {
      setMessage(`ERROR: ${error.response?.data?.detail || 'Handshake failed'}`);
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    if (passwordData.new_password !== passwordData.confirm_password) {
      setMessage('ERROR: Passwords parity mismatch');
      setLoading(false);
      return;
    }

    try {
      await usersAPI.changePassword(
        passwordData.current_password,
        passwordData.new_password
      );
      setMessage('SUCCESS: Security credentials updated');
      setPasswordData({
        current_password: '',
        new_password: '',
        confirm_password: '',
      });
      setTimeout(() => setMessage(''), 5000);
    } catch (error) {
      setMessage(`ERROR: ${error.response?.data?.detail || 'Authorization failed'}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="profile-section">
      <div className="section-header">
        <h1 className="section-title">Identity Manager</h1>
        <p className="section-subtitle">Core account parameters & security credentials</p>
      </div>

      <div className="max-w-4xl mx-auto">
        {message && (
          <div className={`message ${message.includes('SUCCESS') ? 'success' : 'error'}`}>
             <span className="material-symbols-outlined align-middle mr-2 text-sm">
                {message.includes('SUCCESS') ? 'check_circle' : 'warning'}
             </span>
             {message}
          </div>
        )}

        <div className="profile-container">
          {/* Profile Card */}
          <div className="profile-card">
            <h3>
              Profile Info
            </h3>
            <form onSubmit={handleProfileUpdate}>
              <div className="form-group">
                <div className="field-label-wrapper">
                  <span className="material-symbols-outlined text-sm text-primary">person</span>
                  <label>Full Name</label>
                </div>
                <div className="input-wrapper">
                  <input
                    type="text"
                    value={formData.full_name}
                    onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                    placeholder="Enter full name..."
                  />
                </div>
              </div>

              <div className="form-group">
                <div className="field-label-wrapper">
                  <span className="material-symbols-outlined text-sm text-primary">alternate_email</span>
                  <label>Email Address</label>
                </div>
                <div className="input-wrapper">
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    placeholder="Enter email address..."
                  />
                </div>
              </div>

              <button type="submit" className="btn-update" disabled={loading}>
                {loading ? 'SYNCING...' : 'Update Identity'}
              </button>
            </form>
          </div>

          {/* Password Card */}
          <div className="profile-card">
            <h3>
              Security
            </h3>
            <form onSubmit={handlePasswordChange}>
              <div className="form-group">
                <div className="field-label-wrapper">
                  <span className="material-symbols-outlined text-sm text-secondary">lock</span>
                  <label>Current Password</label>
                </div>
                <div className="input-wrapper">
                  <input
                    type="password"
                    value={passwordData.current_password}
                    onChange={(e) =>
                      setPasswordData({ ...passwordData, current_password: e.target.value })
                    }
                    placeholder="••••••••"
                  />
                </div>
              </div>

              <div className="form-group">
                <div className="field-label-wrapper">
                  <span className="material-symbols-outlined text-sm text-secondary">key</span>
                  <label>New Password</label>
                </div>
                <div className="input-wrapper">
                  <input
                    type="password"
                    value={passwordData.new_password}
                    onChange={(e) =>
                      setPasswordData({ ...passwordData, new_password: e.target.value })
                    }
                    placeholder="••••••••"
                    minLength={6}
                  />
                </div>
              </div>

              <div className="form-group">
                <div className="field-label-wrapper">
                  <span className="material-symbols-outlined text-sm text-secondary">verified_user</span>
                  <label>Verify Password</label>
                </div>
                <div className="input-wrapper">
                  <input
                    type="password"
                    value={passwordData.confirm_password}
                    onChange={(e) =>
                      setPasswordData({ ...passwordData, confirm_password: e.target.value })
                    }
                    placeholder="••••••••"
                  />
                </div>
              </div>

              <button type="submit" className="btn-update" disabled={loading}>
                {loading ? 'SECURING...' : 'Revise Credentials'}
              </button>
            </form>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Profile;
