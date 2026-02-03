import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useState } from 'react';
import './Navbar.css';

const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [showMenu, setShowMenu] = useState(false);

  const isActive = (path) => {
    return location.pathname === path;
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const userInitials = user?.full_name
    ? user.full_name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : user?.email?.[0].toUpperCase() || 'U';

  return (
    <nav className="navbar">
      <div className="nav-container">
        <div className="nav-brand">
          <i className="fas fa-shield-alt"></i>
          <span className="brand-text">SecureScan <span className="brand-pro">Pro</span></span>
        </div>
        <ul className="nav-menu">
          <li>
            <Link to="/dashboard" className={`nav-link ${isActive('/dashboard') ? 'active' : ''}`}>
              <i className="fas fa-home"></i> Dashboard
            </Link>
          </li>
          <li>
            <Link to="/scanner" className={`nav-link ${isActive('/scanner') ? 'active' : ''}`}>
              <i className="fas fa-search"></i> Scanner
            </Link>
          </li>
          <li>
            <Link to="/results" className={`nav-link ${isActive('/results') ? 'active' : ''}`}>
              <i className="fas fa-chart-bar"></i> Results
            </Link>
          </li>
          <li>
            <Link to="/analytics" className={`nav-link ${isActive('/analytics') ? 'active' : ''}`}>
              <i className="fas fa-chart-line"></i> Analytics
            </Link>
          </li>
          <li>
            <Link to="/threat-intel" className={`nav-link ${isActive('/threat-intel') ? 'active' : ''}`}>
              <i className="fas fa-shield-virus"></i> Threat Intel
            </Link>
          </li>
          <li>
            <Link to="/reports" className={`nav-link ${isActive('/reports') ? 'active' : ''}`}>
              <i className="fas fa-file-alt"></i> Reports
            </Link>
          </li>
        </ul>
        <div className="nav-actions">
          <button className="btn-icon" id="notificationBtn">
            <i className="fas fa-bell"></i>
            <span className="badge">3</span>
          </button>
          <Link to="/settings" className="btn-icon">
            <i className="fas fa-cog"></i>
          </Link>
          <div className="user-profile" onClick={() => setShowMenu(!showMenu)}>
            <div className="user-avatar">{userInitials}</div>
            <span>{user?.full_name || user?.email || 'User'}</span>
            <i className="fas fa-chevron-down"></i>
            {showMenu && (
              <div className="user-menu">
                <Link to="/profile" onClick={() => setShowMenu(false)}>
                  <i className="fas fa-user"></i> My Profile
                </Link>
                <Link to="/settings" onClick={() => setShowMenu(false)}>
                  <i className="fas fa-cog"></i> Settings
                </Link>
                <hr />
                <button onClick={handleLogout}>
                  <i className="fas fa-sign-out-alt"></i> Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;

