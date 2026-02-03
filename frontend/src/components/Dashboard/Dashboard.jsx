import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanAPI, threatsAPI } from '../../services/api';
import ThreatTicker from './ThreatTicker';
// NetworkBackground moved to App.jsx for global scope
import './Dashboard.css';

// Animated Counter Component
const CountUp = ({ end, duration = 2000, suffix = '' }) => {
  const [count, setCount] = useState(0);
  const startTimeRef = useRef(null);
  const animationFrameRef = useRef(null);

  useEffect(() => {
    const animate = (timestamp) => {
      if (!startTimeRef.current) startTimeRef.current = timestamp;
      const progress = timestamp - startTimeRef.current;
      const percentage = Math.min(progress / duration, 1);
      const easeOutQuart = 1 - Math.pow(1 - percentage, 4);
      
      setCount(Math.floor(easeOutQuart * end));

      if (progress < duration) {
        animationFrameRef.current = requestAnimationFrame(animate);
      } else {
        setCount(end); // Ensure final value is exact
      }
    };

    animationFrameRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrameRef.current);
  }, [end, duration]);

  return <>{count.toLocaleString()}{suffix}</>;
};

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalScans: 0,
    criticalStats: { total: 0, delta: 0 },
    securityScore: 0,
    activeScans: 0,
  });
  const [recentScans, setRecentScans] = useState([]);
  const [latestThreats, setLatestThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isLive, setIsLive] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const navigate = useNavigate();

  // Polling for "Live" feel
  useEffect(() => {
    loadDashboardData(true);
    
    const interval = setInterval(() => {
      setIsLive(true);
      loadDashboardData(false); // Silent update
      setTimeout(() => setIsLive(false), 2000); // Pulse effect duration
    }, 15000); // Poll every 15s

    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async (initial = false) => {
    try {
      if (initial) setLoading(true);
      
      // Parallel data fetching with resilience
      const [scansResult, threatsResult] = await Promise.allSettled([
        scanAPI.list(0, 50),
        threatsAPI.list({ limit: 5, severity: 'critical' })
      ]);

      const scans = scansResult.status === 'fulfilled' ? scansResult.value : [];
      const threats = threatsResult.status === 'fulfilled' ? threatsResult.value : [];

      if (scansResult.status === 'rejected') console.error('Failed to load scans:', scansResult.reason);
      if (threatsResult.status === 'rejected') console.error('Failed to load threats:', threatsResult.reason);

      // If no threats, trigger a sync to populate initial DB
      if (threats.length === 0 && initial) {
         try { await threatsAPI.sync(); } catch(e) { console.warn("Auto-sync failed", e); }
      }

      setLastUpdated(new Date());

      // Process Scans
      const completedScans = scans.filter(s => s.status === 'completed');
      const activeRunning = scans.filter(s => ['running', 'queued'].includes(s.status)).length;
      
      // Calculate Score (Weighted average of recent scans)
      const avgScore = completedScans.length > 0
        ? Math.round(completedScans.slice(0, 10).reduce((sum, s) => sum + (s.security_score || 0), 0) / Math.min(completedScans.length, 10))
        : 85; 

      setStats({
        totalScans: scans.length,
        criticalStats: { total: threats.length, delta: 2 }, // Delta would be calculated from historical data in a real app
        securityScore: avgScore,
        activeScans: activeRunning,
      });

      setRecentScans(scans.slice(0, 5));
      setLatestThreats(threats);

    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      if (initial) setLoading(false);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 90) return 'text-success';
    if (score >= 70) return 'text-warning';
    return 'text-danger';
  };

  if (loading) {
    return (
      <div className="loading-state">
        <div className="spinner"></div>
        <p className="loading-text">Establishing Secure Connection...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      {/* NetworkBackground is now global in App.jsx */}
      
      {/* Header */}
      <header className="dashboard-header">
        <div>
          <h1 className="page-title">Command Center</h1>
          <p className="page-subtitle">
            <span className={`status-dot ${isLive ? 'pulse-green' : ''}`}></span>
            System Status: <strong>Operational</strong> • Last Updated: {lastUpdated.toLocaleTimeString()}
          </p>
        <div className="header-actions">
           <button className="btn btn-primary" onClick={() => navigate('/scanner')}>
             <i className="fas fa-crosshairs"></i> New Target Scan
           </button>
           <button className="btn btn-secondary" onClick={() => threatsAPI.sync()}>
             <i className="fas fa-sync"></i> Sync Intel
           </button>
        </div>
        </div>
      </header>

      {/* Global Threat News Ticker */}
      {latestThreats.length > 0 && <ThreatTicker threats={latestThreats} />}

      {/* Hero Stats */}
      <div className="stats-grid">
        <div className="stat-card glass-panel">
          <div className="stat-header">
            <span className="stat-label">Total Scans</span>
            <div className="stat-trend positive">
              <i className="fas fa-level-up-alt"></i> +5%
            </div>
          </div>
          <div className="stat-body">
            <h3 className="stat-value"><CountUp end={stats.totalScans} /></h3>
            <div className="stat-chart-mini">
              {/* Decorative mini-chart */}
              <svg width="60" height="30">
                 <path d="M0,25 Q10,25 20,20 T40,10 T60,5" fill="none" stroke="var(--primary-500)" strokeWidth="2" />
              </svg>
            </div>
          </div>
        </div>

        <div className="stat-card glass-panel" style={{ '--card-glow': 'var(--status-critical)' }}>
          <div className="stat-header">
            <span className="stat-label">Global Critical Threats</span>
            <div className="stat-trend negative">
              <i className="fas fa-exclamation"></i> New
            </div>
          </div>
          <div className="stat-body">
            <h3 className="stat-value text-critical"><CountUp end={stats.criticalStats.total} /></h3>
             <div className="pulse-icon red">
                <i className="fas fa-biohazard"></i>
             </div>
          </div>
        </div>

        <div className="stat-card glass-panel">
          <div className="stat-header">
            <span className="stat-label">Security Posture</span>
            <span className="stat-badge">A+</span>
          </div>
          <div className="stat-body">
            <h3 className={`stat-value ${getScoreColor(stats.securityScore)}`}>
              <CountUp end={stats.securityScore} />
            </h3>
             <div className="score-meter">
               <div className="meter-fill" style={{width: `${stats.securityScore}%`}}></div>
             </div>
          </div>
        </div>

        <div className="stat-card glass-panel">
          <div className="stat-header">
            <span className="stat-label">Active Operations</span>
            <div className="stat-live-indicator">
               {stats.activeScans > 0 ? (
                 <><span className="blink"></span> Live</>
               ) : (
                 <span className="text-muted">Idle</span>
               )}
            </div>
          </div>
          <div className="stat-body">
            <h3 className="stat-value text-info"><CountUp end={stats.activeScans} /></h3>
            <i className={`fas fa-radar stat-bg-icon ${stats.activeScans > 0 ? 'fa-spin-slow' : ''}`}></i>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="dashboard-grid">
        
        {/* Left Column: Recent Activity & Threats */}
        <div className="dashboard-col-main">
          
          {/* Latest Threat Intel Feed (Real NVD Data) */}
          <div className="glass-panel feed-section">
             <div className="panel-header">
               <h3><i className="fas fa-globe-americas"></i> Global Threat Feed (NVD)</h3>
               <button className="btn-text">View All</button>
             </div>
             <div className="threat-feed">
                {latestThreats.length > 0 ? (
                  latestThreats.map((threat, i) => (
                    <div key={i} className="threat-item">
                       <div className={`threat-severity-bar ${threat.severity}`}></div>
                       <div className="threat-content">
                          <div className="threat-header">
                             <span className="threat-id">{threat.cve_id || 'CVE-UNKNOWN'}</span>
                             <span className="threat-date">{new Date(threat.published_date).toLocaleDateString()}</span>
                          </div>
                          <p className="threat-desc" title={threat.description}>
                            {threat.description?.length > 100 ? threat.description.substring(0, 100) + '...' : threat.description}
                          </p>
                          <div className="threat-tags">
                             <span className="tag">{threat.category || 'Vulnerability'}</span>
                             <span className="tag score">CVSS {threat.cvss_score}</span>
                          </div>
                       </div>
                    </div>
                  ))
                ) : (
                  <div className="empty-state">
                    <i className="fas fa-shield-alt"></i>
                    <p>No critical threats detected in feed.</p>
                  </div>
                )}
             </div>
          </div>

          {/* Recent Scans Table */}
          <div className="glass-panel table-section">
             <div className="panel-header">
               <h3><i className="fas fa-history"></i> Recent Scans</h3>
            </div>
            <table className="modern-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Target</th>
                  <th>Date</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan, index) => (
                  <tr key={index}>
                     <td>
                        <span className={`status-pill ${scan.status}`}>
                          <span className="dot"></span> {scan.status}
                        </span>
                     </td>
                     <td className="font-mono">{scan.target_url || 'N/A'}</td>
                     <td>{new Date(scan.created_at).toLocaleDateString()}</td>
                     <td>
                       <button className="action-btn"><i className="fas fa-chevron-right"></i></button>
                     </td>
                  </tr>
                ))}
                {recentScans.length === 0 && (
                   <tr><td colSpan="4" className="text-center p-4 text-muted">No recent scans found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Widgets */}
        <div className="dashboard-col-side">
           
           {/* Quick Actions */}
           <div className="glass-panel actions-card">
              <div className="panel-header">
                 <h3>Quick Actions</h3>
              </div>
              <div className="quick-actions-grid">
                 <button className="quick-action-btn" onClick={() => navigate('/scanner')}>
                    <i className="fas fa-bug"></i>
                    <span>Quick Scan</span>
                 </button>
                 <button className="quick-action-btn" onClick={() => navigate('/scanner')}>
                    <i className="fas fa-network-wired"></i>
                    <span>Port Check</span>
                 </button>
                 <button className="quick-action-btn" onClick={() => navigate('/reports')}>
                    <i className="fas fa-file-pdf"></i>
                    <span>Report</span>
                 </button>
                 <button className="quick-action-btn" onClick={() => navigate('/scanner')}>
                    <i className="fas fa-user-shield"></i>
                    <span>Auth Test</span>
                 </button>
              </div>
           </div>

           {/* System Status */}
           <div className="glass-panel status-card">
              <div className="panel-header">
                 <h3>Infrastructure Status</h3>
              </div>
              <div className="system-items">
                 <div className="sys-item">
                    <span><i className="fas fa-server"></i> API Gateway</span>
                    <span className="sys-status online">Online</span>
                 </div>
                 <div className="sys-item">
                    <span><i className="fas fa-database"></i> Threat DB</span>
                    <span className="sys-status online">Synced</span>
                 </div>
                 <div className="sys-item">
                    <span><i className="fas fa-satellite-dish"></i> NVD Feed</span>
                    <span className={`sys-status ${latestThreats.length > 0 ? 'online' : 'busy'}`}>
                      {latestThreats.length > 0 ? 'Active' : 'Syncing'}
                    </span>
                 </div>
              </div>
           </div>
        </div>

      </div>
    </div>
  );
};

export default Dashboard;

