import { useState, useEffect } from 'react';
import { threatsAPI } from '../../services/api';
import './ThreatIntelligence.css';

const ThreatIntelligence = () => {
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    severity: '',
    category: '',
    skip: 0,
    limit: 50,
  });

  useEffect(() => {
    loadThreats();
    loadStats();
  }, [filters]);

  const loadThreats = async () => {
    try {
      setLoading(true);
      const data = await threatsAPI.list(filters);
      setThreats(data);
    } catch (error) {
      console.error('Failed to load threats:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const data = await threatsAPI.getStats();
      setStats(data);
    } catch (error) {
      console.error('Failed to load threat stats:', error);
    }
  };

  const handleSync = async () => {
    try {
      await threatsAPI.sync();
      await loadThreats();
      await loadStats();
      alert('Threats synced successfully!');
    } catch (error) {
      console.error('Failed to sync threats:', error);
      alert('Failed to sync threats');
    }
  };

  if (loading && threats.length === 0) {
    return <div className="loading">Loading threat intelligence...</div>;
  }

  return (
    <section className="threat-section">
      <div className="section-header">
        <div>
          <h1 className="section-title">Threat Intelligence</h1>
          <p className="section-subtitle">Real-time threat data from the last 30 days</p>
        </div>
        <button className="btn-primary" onClick={handleSync}>
          <i className="fas fa-sync-alt"></i> Sync Threats
        </button>
      </div>

      {stats && (
        <div className="threat-stats">
          <h3>Threat Statistics</h3>
          <div className="stats-grid">
            <div className="stat-item critical">
              <div className="stat-number">{stats.critical}</div>
              <div className="stat-label">Critical</div>
            </div>
            <div className="stat-item high">
              <div className="stat-number">{stats.high}</div>
              <div className="stat-label">High</div>
            </div>
            <div className="stat-item medium">
              <div className="stat-number">{stats.medium}</div>
              <div className="stat-label">Medium</div>
            </div>
            <div className="stat-item low">
              <div className="stat-number">{stats.low}</div>
              <div className="stat-label">Low</div>
            </div>
            <div className="stat-item trending">
              <div className="stat-number">{stats.trending}</div>
              <div className="stat-label">Trending</div>
            </div>
            <div className="stat-item exploit">
              <div className="stat-number">{stats.with_exploits}</div>
              <div className="stat-label">With Exploits</div>
            </div>
          </div>
        </div>
      )}

      <div className="threat-filters">
        <select
          value={filters.severity}
          onChange={(e) => setFilters({ ...filters, severity: e.target.value, skip: 0 })}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filters.category}
          onChange={(e) => setFilters({ ...filters, category: e.target.value, skip: 0 })}
        >
          <option value="">All Categories</option>
          <option value="Injection">Injection</option>
          <option value="XSS">XSS</option>
          <option value="Authentication">Authentication</option>
          <option value="DoS">DoS</option>
        </select>
      </div>

      <div className="threat-list">
        {threats.map((threat) => (
          <div key={threat._id} className={`threat-card ${threat.severity}`}>
            <div className="threat-header">
              <span className={`severity-badge ${threat.severity}`}>
                {threat.severity.toUpperCase()}
              </span>
              {threat.trending && <span className="trending-badge">Trending</span>}
            </div>
            <h4 className="threat-title">{threat.cve_id}</h4>
            <p className="threat-description">{threat.title}</p>
            <div className="threat-meta">
              <span className="threat-cvss">CVSS: {threat.cvss_score}</span>
              <span className="threat-category">{threat.category}</span>
            </div>
          </div>
        ))}
      </div>

      {threats.length === 0 && !loading && (
        <div className="empty-state">
          <p>No threats found. Click "Sync Threats" to load threat data.</p>
        </div>
      )}
    </section>
  );
};

export default ThreatIntelligence;

