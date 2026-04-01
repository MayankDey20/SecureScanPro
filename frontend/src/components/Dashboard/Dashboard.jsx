import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanAPI, threatsAPI, analyticsAPI } from '../../services/api';
import { useAuth } from '../../contexts/AuthContext';
import './Dashboard.css';

const Dashboard = () => {
  const [stats, setStats] = useState({ totalScans:0, criticalStats:{total:0,delta:0}, securityScore:85, activeScans:0, vulnCount:0 });
  const [recentScans, setRecentScans] = useState([]);
  const [latestThreats, setLatestThreats] = useState([]);
  const [activityData, setActivityData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isLive, setIsLive] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const navigate = useNavigate();
  const { user } = useAuth();
  const firstName = (user?.user_metadata?.full_name?.split(' ')[0]) ||
    (user?.email?.split('@')[0].replace(/[^a-zA-Z]/g, ' ').trim().split(' ')[0]) ||
    'Agent';
  const displayName = firstName.charAt(0).toUpperCase() + firstName.slice(1).toLowerCase();

  useEffect(() => {
    loadDashboardData(true);
    const iv = setInterval(() => {
      setIsLive(true);
      loadDashboardData(false);
      setTimeout(() => setIsLive(false), 2000);
    }, 15000);
    return () => clearInterval(iv);
  }, []);

  const loadDashboardData = async (initial = false) => {
    try {
      if (initial) setLoading(true);
      const [sr, tr, ar] = await Promise.allSettled([
        scanAPI.list(0, 50),
        threatsAPI.list({ limit: 8, severity: 'critical' }),
        analyticsAPI.getTrends('30d'),
      ]);
      const scans    = sr.status === 'fulfilled' ? sr.value : [];
      const threats  = tr.status === 'fulfilled' ? tr.value : [];
      const analytic = ar.status === 'fulfilled' ? ar.value : null;
      if (analytic) setActivityData(analytic);
      if (threats.length === 0 && initial) { try { await threatsAPI.sync(); } catch(e) {} }
      setLastUpdated(new Date());
      const done    = scans.filter(s => s.status === 'completed');
      const running = scans.filter(s => ['running','queued'].includes(s.status)).length;
      const score   = done.length > 0
        ? Math.round(done.slice(0,10).reduce((a,s) => a + (s.security_score||0), 0) / Math.min(done.length,10))
        : 85;
      const vulns = done.reduce((a,s) => {
        const vc = s.vulnerabilities_count;
        if (!vc) return a;
        if (typeof vc === 'number') return a + vc;
        // DB stores it as {critical:N, high:N, medium:N, low:N, info:N}
        if (typeof vc === 'object') return a + Object.values(vc).reduce((x,n) => x + (Number(n)||0), 0);
        return a;
      }, 0);
      setStats({ totalScans: scans.length, criticalStats: { total: threats.length, delta: 2 }, securityScore: score, activeScans: running, vulnCount: vulns });
      setRecentScans(scans.slice(0, 8));
      setLatestThreats(threats);
    } catch(e) { console.error(e); }
    finally { if (initial) setLoading(false); }
  };

  if (loading) return (
    <div className="loading-state">
      <div className="spinner"></div>
      <p className="loading-text">Establishing Secure Connection…</p>
    </div>
  );

  const grade = stats.securityScore >= 90 ? 'A+' : stats.securityScore >= 80 ? 'A' : stats.securityScore >= 70 ? 'B+' : stats.securityScore >= 60 ? 'B' : stats.securityScore >= 50 ? 'C' : 'D';
  const gradeDesc = stats.securityScore >= 90 ? 'Excellent — minimal exposure'
    : stats.securityScore >= 80 ? 'Good — a few issues to address'
    : stats.securityScore >= 70 ? 'Fair — notable vulnerabilities present'
    : stats.securityScore >= 60 ? 'Below average — significant risk'
    : stats.securityScore >= 50 ? 'Poor — critical issues found'
    : 'Critical — immediate action needed';

  return (
    <div className="dashboard-container">

      {/* ── Top bar ── */}
      <div className="db-topbar">
        <div className="db-hello">
          <h1>Hello, {displayName} <span className="db-wave">👋</span></h1>
          <p className={`db-status-line ${isLive ? 'live' : ''}`}>
            <span className="db-status-dot"></span>
            System Operational &nbsp;·&nbsp; Last updated {lastUpdated.toLocaleTimeString()}
          </p>
        </div>
        <div className="db-topbar-actions">
          <button className="db-btn-primary" onClick={() => navigate('/scanner')}>
            <i className="fas fa-crosshairs"></i> New Scan
          </button>
          <button className="db-btn-secondary" onClick={() => threatsAPI.sync()}>
            <i className="fas fa-sync-alt"></i> Sync Intel
          </button>
          <button className="db-btn-secondary" onClick={() => navigate('/analytics')}>
            <i className="fas fa-chart-bar"></i> Analytics
          </button>
        </div>
      </div>

      {/* ── 4 Hero stat cards ── */}
      <div className="hero-cards">
        <div className="hero-card hero-card--teal">
          <div className="hero-card-bg-icon"><i className="fas fa-shield-alt"></i></div>
          <p className="hero-card-label">Total Scans</p>
          <h2 className="hero-card-value"><CountUp end={stats.totalScans} /></h2>
          <div className="hero-card-footer">
            <span className="hc-badge hc-badge--green"><i className="fas fa-arrow-up"></i> +5%</span>
            <button className="hero-card-link" onClick={() => navigate('/results')}>View all →</button>
          </div>
        </div>
        <div className="hero-card hero-card--amber">
          <div className="hero-card-bg-icon"><i className="fas fa-biohazard"></i></div>
          <p className="hero-card-label">Active Threats</p>
          <h2 className="hero-card-value"><CountUp end={stats.criticalStats.total} /></h2>
          <div className="hero-card-footer">
            <span className={`hc-badge ${stats.criticalStats.total > 0 ? 'hc-badge--red' : 'hc-badge--green'}`}>
              {stats.criticalStats.total > 0 ? '⚠ Critical' : '✓ Clear'}
            </span>
            <button className="hero-card-link" onClick={() => navigate('/threat-intel')}>View all →</button>
          </div>
        </div>
        <div className="hero-card hero-card--pink">
          <div className="hero-card-bg-icon"><i className="fas fa-chart-line"></i></div>
          <p className="hero-card-label">Security Score</p>
          <h2 className="hero-card-value"><CountUp end={stats.securityScore} /></h2>
          <div className="hero-card-footer">
            <span className="hc-badge hc-badge--blue" title={gradeDesc}>{grade} Grade ⓘ</span>
            <button className="hero-card-link" onClick={() => navigate('/analytics')}>Details →</button>
          </div>
        </div>
        <div className="hero-card hero-card--violet">
          <div className="hero-card-bg-icon"><i className="fas fa-bug"></i></div>
          <p className="hero-card-label">Vulnerabilities</p>
          <h2 className="hero-card-value"><CountUp end={stats.vulnCount} /></h2>
          <div className="hero-card-footer">
            <span className="hc-badge hc-badge--orange">{stats.activeScans} Running</span>
            <button className="hero-card-link" onClick={() => navigate('/results')}>Details →</button>
          </div>
        </div>
      </div>

      {/* ── Main grid: chart | globe+threats | right sidebar ── */}
      <div className="db-main-grid">

        {/* Scan activity chart */}
        <div className="db-panel db-chart-panel">
          <div className="db-panel-header">
            <div>
              <h3>Scan Activity</h3>
              <p className="db-panel-sub">7-day scan volume overview</p>
            </div>
            <div className="db-panel-controls">
              <span className="db-select-pill"><i className="fas fa-calendar-alt"></i> Last 7 days</span>
              <button className="db-btn-pill db-btn-pill--yellow" onClick={() => navigate('/reports')}>
                <i className="fas fa-download"></i> Export
              </button>
            </div>
          </div>
          <ScanActivityChart activityData={activityData} allScans={stats.totalScans} />
          <div className="db-chart-footer">
            <div className="db-chart-legend">
              <span><span className="legend-dot" style={{background:'#3b82f6'}}></span> Completed</span>
              <span><span className="legend-dot ld-dash" style={{background:'#8b5cf6'}}></span> Failed / Active</span>
            </div>
            <div className="db-chart-stats">
              <div className="db-cs-item"><span>Peak</span><strong>{Math.max(stats.totalScans, 1)}</strong></div>
              <div className="db-cs-item"><span>Avg/day</span><strong>{Math.max(Math.floor(stats.totalScans / 7), 0)}</strong></div>
              <div className="db-cs-item"><span>Active</span><strong style={{color:'#60a5fa'}}>{stats.activeScans}</strong></div>
            </div>
          </div>
        </div>

        {/* Globe + CVE list */}
        <div className="db-panel db-globe-panel">
          <div className="db-panel-header">
            <div>
              <h3><i className="fas fa-globe-americas"></i> Global Threats</h3>
              <p className="db-panel-sub">Live threat feed</p>
            </div>
            <button className="db-btn-text" onClick={() => navigate('/threat-intel')}>View All</button>
          </div>
          <ThreatGlobe threats={latestThreats} />
        </div>

        {/* Right sidebar: donut + stats + ops — all in one unified card */}
        <div className="db-panel db-sidebar-panel">
          {/* Donut */}
          <div className="db-sidebar-section db-donut-section">
            <div className="db-score-top">
              <div className="db-score-icon"><i className="fas fa-shield-alt"></i></div>
              <div>
                <p className="db-score-label">SecureScan Pro</p>
                <p className="db-score-sub">Threat Analysis</p>
              </div>
            </div>
            <ScoreDonut score={stats.securityScore} />
            <div className="db-score-legend">
              <span><span className="legend-dot" style={{background:'#3b82f6'}}></span> Secure</span>
              <span><span className="legend-dot" style={{background:'#14b8a6'}}></span> Low Risk</span>
              <span><span className="legend-dot" style={{background:'#ef4444'}}></span> Critical</span>
              <span><span className="legend-dot" style={{background:'#22c55e'}}></span> Resolved</span>
            </div>
          </div>

          <div className="db-sidebar-divider"></div>

          {/* Stats rows */}
          <div className="db-sidebar-section">
            <div className="db-sidebar-date-row">
              <span className="db-select-pill"><i className="fas fa-calendar-alt"></i> Last 30 days</span>
            </div>
            <div className="db-stat-row"><span><i className="fas fa-search"></i> Total Scans</span><strong>{stats.totalScans}</strong></div>
            <div className="db-stat-row"><span><i className="fas fa-skull-crossbones"></i> Active Threats</span>
              <strong className={stats.criticalStats.total > 0 ? 'db-val--warn' : ''}>
                {stats.criticalStats.total}
                {stats.criticalStats.total > 0 && <em className="db-delta"> +{stats.criticalStats.delta}</em>}
              </strong>
            </div>
            <div className="db-stat-row"><span><i className="fas fa-spinner"></i> Running</span><strong>{stats.activeScans}</strong></div>
            <div className="db-stat-row"><span><i className="fas fa-star"></i> Score</span><strong className="db-val--score">{stats.securityScore}</strong></div>
          </div>

          <div className="db-sidebar-divider"></div>

          {/* Progress bars */}
          <div className="db-sidebar-section">
            <p className="db-ops-heading">Operations</p>
            <div className="db-ops-item">
              <div className="db-ops-meta">
                <span className="db-ops-label">Running Scans</span>
                <span className="db-ops-value">{stats.activeScans}</span>
              </div>
              <div className="db-ops-bar">
                <div className="db-ops-fill" style={{width:`${Math.min(stats.activeScans*10,100)}%`, background:'#3b82f6'}}></div>
              </div>
            </div>
            <div className="db-ops-item">
              <div className="db-ops-meta">
                <span className="db-ops-label">Completed</span>
                <span className="db-ops-value">{stats.totalScans}</span>
              </div>
              <div className="db-ops-bar">
                <div className="db-ops-fill" style={{width:`${Math.min(stats.totalScans*5,100)}%`, background:'#8b5cf6'}}></div>
              </div>
            </div>
            <div className="db-ops-item">
              <div className="db-ops-meta">
                <span className="db-ops-label">Threat Coverage</span>
                <span className="db-ops-value">{stats.securityScore}%</span>
              </div>
              <div className="db-ops-bar">
                <div className="db-ops-fill" style={{width:`${stats.securityScore}%`, background:'#14b8a6'}}></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Bottom grid: weekly bars | table ── */}
      <div className="db-bottom-grid">
        <div className="db-panel db-weekly-panel">
          <div className="db-panel-header">
            <div>
              <h3>Weekly Vulnerabilities</h3>
              <p className="db-panel-sub">Detections by day</p>
            </div>
          </div>
          <WeeklyVulnBars activityData={activityData} />
          <div className="db-weekly-legend">
            <span className="wl-dot" style={{background:'#f97316'}}></span> High &nbsp;
            <span className="wl-dot" style={{background:'#ef4444'}}></span> Critical &nbsp;
            <span className="wl-dot" style={{background:'#22c55e'}}></span> Low
          </div>
        </div>

        <div className="db-panel db-table-panel">
          <div className="db-panel-header">
            <div>
              <h3>Recent Scans</h3>
              <p className="db-panel-sub">{recentScans.length} most recent</p>
            </div>
            <div className="db-panel-controls">
              <button className="db-btn-pill"><i className="fas fa-filter"></i> Filter</button>
              <button className="db-btn-pill db-btn-pill--yellow" onClick={() => navigate('/results')}>
                <i className="fas fa-table"></i> View All
              </button>
            </div>
          </div>
          <div className="db-table-wrap">
            <table className="db-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Target</th>
                  <th>Date</th>
                  <th>Score</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((s, i) => (
                  <tr key={i} onClick={() => navigate('/results')} style={{cursor:'pointer'}}>
                    <td className="db-td-mono">{s.id?.toString().slice(-6) || String(i+1).padStart(6,'0')}</td>
                    <td className="db-td-target">{s.target_url || 'N/A'}</td>
                    <td>{new Date(s.created_at).toLocaleDateString()}</td>
                    <td>
                      <span className={`db-score-pill ${(s.security_score??0)>=80?'good':(s.security_score??0)>=50?'warn':'bad'}`}>
                        {s.security_score ?? '—'}
                      </span>
                    </td>
                    <td><span className={`db-status-pill db-status-pill--${s.status}`}>{s.status}</span></td>
                  </tr>
                ))}
                {recentScans.length === 0 && (
                  <tr><td colSpan="5" className="db-empty-row">
                    <i className="fas fa-satellite-dish"></i><br/>No scans yet — run your first scan!
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

    </div>
  );
};

export default Dashboard;

/* ─────────────────────────────────────────────────
   Sub-components
───────────────────────────────────────────────── */

function CountUp({ end, duration = 1600 }) {
  const [n, setN] = useState(0);
  const t0 = useRef(null), af = useRef(null);
  useEffect(() => {
    t0.current = null;
    const run = ts => {
      if (!t0.current) t0.current = ts;
      const p = Math.min((ts - t0.current) / duration, 1);
      setN(Math.floor((1 - Math.pow(1-p, 4)) * end));
      if (p < 1) af.current = requestAnimationFrame(run);
      else setN(end);
    };
    af.current = requestAnimationFrame(run);
    return () => cancelAnimationFrame(af.current);
  }, [end, duration]);
  return <>{n.toLocaleString()}</>;
}

function ScanActivityChart({ activityData, allScans }) {
  const [hoverIndex, setHoverIndex] = useState(null);
  const containerRef = useRef(null);
  const days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];

  let vals, xlabels;
  if (activityData?.scansByDay?.length > 0) {
    const raw = activityData.scansByDay.slice(-7);
    const rawLbl = activityData.labels.slice(-7).map(l => {
      try { return new Date(l + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric' }); }
      catch { return l; }
    });
    vals = [...Array(Math.max(0, 7 - raw.length)).fill(0), ...raw];
    xlabels = [...rawLbl.slice(0, Math.max(0, 7 - rawLbl.length)).map(() => ''), ...rawLbl];
    xlabels = xlabels.map((l, i) => l || days[i]);
  } else {
    const b = allScans || 0;
    vals = [b*.08, b*.14, b*.22, b*.18, b*.28, b*.10, b*.06].map(v => Math.max(Math.floor(v), 0));
    xlabels = days;
  }

  const hasData = vals.some(v => v > 0);
  if (!hasData) return (
    <div className="sac-empty">
      <i className="fas fa-satellite-dish" style={{fontSize:'2rem',color:'#334155',marginBottom:'0.5rem'}}></i>
      <p style={{color:'#475569',fontSize:'0.85rem'}}>Run your first scan to see activity here</p>
    </div>
  );

  const max = Math.max(...vals, 1);
  const W = 500, H = 160, px = 40, py = 20;

  // Projection
  const pts = vals.map((v, i) => ({
    x: px + (i / (vals.length - 1)) * (W - px * 2),
    y: py + (1 - v / max) * (H - py * 2),
    val: v,
    label: xlabels[i]
  }));

  // Bezier Path Helper
  const getBezierPath = (points) => {
    if (points.length < 2) return "";
    let d = `M ${points[0].x} ${points[0].y}`;
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];
      const cp1x = p0.x + (p1.x - p0.x) / 2;
      const cp1y = p0.y;
      const cp2x = p0.x + (p1.x - p0.x) / 2;
      const cp2y = p1.y;
      d += ` C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${p1.x} ${p1.y}`;
    }
    return d;
  };

  const curveLine = getBezierPath(pts);
  const areaPath = curveLine + ` L ${pts[pts.length - 1].x} ${H - py} L ${pts[0].x} ${H - py} Z`;

  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const chartW = rect.width;
    const normalizedX = (x / chartW) * W;
    const idx = Math.round((normalizedX - px) / ((W - px * 2) / (vals.length - 1)));
    if (idx >= 0 && idx < vals.length) setHoverIndex(idx);
    else setHoverIndex(null);
  };

  const ylabels = [max, Math.floor(max / 2), 0];

  return (
    <div className="sac-wrap-highfidelity" ref={containerRef} onMouseMove={handleMouseMove} onMouseLeave={() => setHoverIndex(null)}>
      <div className="sac-ylabels-cyber">{ylabels.map((v, i) => <span key={i}>{v}</span>)}</div>
      <div className="sac-chart-cyber">
        <svg viewBox={`0 0 ${W} ${H}`} className="sac-svg-neon" preserveAspectRatio="none">
          <defs>
            <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur in="SourceAlpha" stdDeviation="4" result="blur" />
              <feOffset in="blur" dx="0" dy="0" result="offsetBlur" />
              <feFlood floodColor="#3b82f6" floodOpacity="0.8" result="offsetColor" />
              <feComposite in="offsetColor" in2="offsetBlur" operator="in" result="glow" />
              <feMerge>
                <feMergeNode in="glow" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <linearGradient id="areaGradCyber" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.3" />
              <stop offset="60%" stopColor="#8b5cf6" stopOpacity="0.05" />
              <stop offset="100%" stopColor="transparent" stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* Oscilloscope Grid */}
          <g className="chart-grid-lines">
            {[0.2, 0.4, 0.6, 0.8].map(fract => (
               <line key={fract} x1={px} y1={py + fract*(H-py*2)} x2={W-px} y2={py + fract*(H-py*2)} stroke="rgba(143, 245, 255, 0.05)" strokeWidth="1" />
            ))}
          </g>

          <path d={areaPath} fill="url(#areaGradCyber)" />
          <path d={curveLine} fill="none" stroke="#3b82f6" strokeWidth="3" filter="url(#neonGlow)" className="path-reveal-anim" />

          {/* Hover State Beam */}
          {hoverIndex !== null && (
            <g className="hover-focus-beam">
              <line x1={pts[hoverIndex].x} y1={py} x2={pts[hoverIndex].x} y2={H - py} stroke="#8ff5ff" strokeWidth="1" strokeDasharray="4,2" />
              <circle cx={pts[hoverIndex].x} cy={pts[hoverIndex].y} r="6" fill="#8ff5ff" className="focus-dot-pulse" />
              <circle cx={pts[hoverIndex].x} cy={pts[hoverIndex].y} r="3" fill="#000" />
            </g>
          )}

          {/* Points */}
          {pts.map((p, i) => (
            <circle key={i} cx={p.x} cy={p.y} r="2.5" fill={hoverIndex === i ? '#8ff5ff' : '#1d4ed8'} />
          ))}
        </svg>

        {/* Floating Tooltip */}
        {hoverIndex !== null && (
          <div 
            className="sac-tooltip-cyber"
            style={{ 
              left: `${(pts[hoverIndex].x / W) * 100}%`,
              top: `${(pts[hoverIndex].y / H) * 100}%`
            }}
          >
            <div className="tt-point-label">{pts[hoverIndex].label}</div>
            <div className="tt-point-value">
              <span className="text-secondary">{pts[hoverIndex].val}</span>
              <span className="text-[8px] ml-1 opacity-50">SCANS</span>
            </div>
          </div>
        )}

        <div className="sac-xlabels-cyber">{xlabels.map((d, i) => <span key={i} className={hoverIndex === i ? 'active' : ''}>{d}</span>)}</div>
      </div>
    </div>
  );
}

function ScoreDonut({ score }) {
  const r = 50, c = 2*Math.PI*r, p = (score||0)/100;
  return (
    <div className="score-donut-wrap">
      <svg viewBox="0 0 130 130" className="score-donut-svg">
        <circle cx="65" cy="65" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="12"/>
        <circle cx="65" cy="65" r={r} fill="none" stroke="#3b82f6"  strokeWidth="12"
          strokeDasharray={`${c*p*.60} ${c}`} strokeDashoffset={c*.25} strokeLinecap="round"/>
        <circle cx="65" cy="65" r={r} fill="none" stroke="#14b8a6"  strokeWidth="12"
          strokeDasharray={`${c*p*.20} ${c}`} strokeDashoffset={-c*p*.60+c*.25} strokeLinecap="round"/>
        <circle cx="65" cy="65" r={r} fill="none" stroke="#22c55e"  strokeWidth="12"
          strokeDasharray={`${c*p*.12} ${c}`} strokeDashoffset={-c*p*.80+c*.25} strokeLinecap="round"/>
        <circle cx="65" cy="65" r={r} fill="none" stroke="#ef4444"  strokeWidth="12"
          strokeDasharray={`${c*(1-p)*.15} ${c}`} strokeDashoffset={-c*p*.92+c*.25} strokeLinecap="round"/>
        <text x="65" y="61" textAnchor="middle" fill="#f1f5f9" fontSize="22" fontWeight="800">{score}</text>
        <text x="65" y="77" textAnchor="middle" fill="#475569"  fontSize="10">/ 100</text>
      </svg>
    </div>
  );
}

function WeeklyVulnBars({ activityData }) {
  const [hoverIdx, setHoverIdx] = useState(null);
  const days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  
  let data = [];
  if (activityData?.vulnerabilitiesByDay?.length > 0) {
    const raw = activityData.vulnerabilitiesByDay.slice(-7);
    data = raw.map((v, i) => {
      const total = Object.values(v).reduce((a, b) => a + (Number(b) || 0), 0);
      let color = '#22c55e'; // Green (Safe)
      let severity = 'Safe';
      
      if (v.critical > 0) { color = '#ef4444'; severity = 'Critical'; }
      else if (v.high > 0) { color = '#f97316'; severity = 'High'; }
      else if (v.medium > 0) { color = '#facc15'; severity = 'Medium'; }
      else if (v.low > 0) { color = '#3b82f6'; severity = 'Low'; }

      return { 
        c: color, 
        h: total > 0 ? Math.min(15 + (total * 8), 100) : 8, 
        total, 
        v,
        severity 
      };
    });
    // Pad to 7 days
    while (data.length < 7) {
      data.unshift({ c: 'rgba(255,255,255,0.03)', h: 5, total: 0, v: {}, severity: 'None' });
    }
  } else {
    // Fallback/Loading state
    data = Array(7).fill(0).map(() => ({ c: 'rgba(255,255,255,0.03)', h: 5, total: 0, v: {}, severity: 'None' }));
  }

  return (
    <div className="wvb-wrap-cyber">
      {data.map((b, i) => (
        <div 
          key={i} 
          className={`wvb-col-cyber ${hoverIdx === i ? 'active' : ''}`}
          onMouseEnter={() => setHoverIdx(i)}
          onMouseLeave={() => setHoverIdx(null)}
        >
          <div className="wvb-track-cyber">
            <div 
              className="wvb-fill-cyber" 
              style={{ 
                height: `${b.h}%`, 
                background: b.c,
                boxShadow: b.total > 0 ? `0 0 15px ${b.c}44` : 'none'
              }}
            >
              {b.total > 0 && <div className="wvb-glow" style={{ background: b.c }}></div>}
            </div>
          </div>
          <span className="wvb-day-cyber">{days[i]}</span>
          
          {hoverIdx === i && b.total > 0 && (
            <div className="wvb-tooltip-cyber">
              <div className="wvb-tt-severity" style={{ color: b.c }}>{b.severity} Risk</div>
              <div className="wvb-tt-stats">
                {b.v.critical > 0 && <span>CRIT: {b.v.critical}</span>}
                {b.v.high > 0 && <span>HIGH: {b.v.high}</span>}
                {b.v.medium > 0 && <span>MED: {b.v.medium}</span>}
                <div className="wvb-tt-total mt-1 border-t border-white/10 pt-1">Total: {b.total}</div>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ThreatGlobe({ threats }) {
  const canvasRef  = useRef(null);
  const animRef    = useRef(null);
  const rotRef     = useRef(0);
  const lastTsRef  = useRef(0);
  const dragging   = useRef(false);
  const lastX      = useRef(0);
  const hoveredRef = useRef(-1);          // index, ref avoids RAF teardown
  const selectedRef= useRef(null);        // { idx, x, y }, ref avoids RAF teardown
  const [tooltip,  setTooltip]  = useState(null);  // only for JSX render

  /* ── severity → colour mapping ── */
  const sevColor = sev => {
    if (!sev) return '#22c55e';
    const s = sev.toLowerCase();
    if (s === 'critical') return '#ef4444';
    if (s === 'high')     return '#ef4444';
    if (s === 'severe')   return '#facc15';
    if (s === 'medium')   return '#facc15';
    return '#22c55e';
  };

  /* ── real-world threat hot-spots with geo coords ── */
  const HOTSPOTS = [
    { lon: -74.0,  lat:  40.7, label: 'New York'    },
    { lon:   2.3,  lat:  48.9, label: 'Paris'       },
    { lon: 139.7,  lat:  35.7, label: 'Tokyo'       },
    { lon: 116.4,  lat:  39.9, label: 'Beijing'     },
    { lon:  37.6,  lat:  55.8, label: 'Moscow'      },
    { lon: -43.2,  lat: -22.9, label: 'Rio'         },
    { lon: 151.2,  lat: -33.9, label: 'Sydney'      },
    { lon:  28.0,  lat:   1.0, label: 'Nairobi'     },
    { lon: -99.1,  lat:  19.4, label: 'Mexico City' },
    { lon:  72.9,  lat:  18.9, label: 'Mumbai'      },
    { lon:  31.2,  lat:  30.1, label: 'Cairo'       },
    { lon: -46.6,  lat: -23.5, label: 'São Paulo'   },
    { lon: 103.8,  lat:   1.3, label: 'Singapore'   },
    { lon:  -0.1,  lat:  51.5, label: 'London'      },
    { lon:  13.4,  lat:  52.5, label: 'Berlin'      },
    { lon:  77.2,  lat:  28.6, label: 'Delhi'       },
  ];

  /* Unique vivid halo colours per hotspot — matches reference image palette */
  const HALO_COLORS = [
    '#f97316','#facc15','#a78bfa','#22d3ee','#f97316','#fb923c',
    '#34d399','#c084fc','#f97316','#fbbf24','#60a5fa','#f472b6',
    '#4ade80','#e879f9','#38bdf8','#f97316',
  ];

  /* Fallback severities so dots are coloured even when API returns no threats */
  const FALLBACK_SEVS = [
    'critical','high','severe','medium','critical','high','medium',
    'severe','critical','high','medium','low','critical','high','severe','medium',
  ];

  /* merge live threats into hotspots by index */
  const spots = HOTSPOTS.map((hs, i) => ({
    ...hs,
    threat: threats.length > 0 ? (threats[i] || null) : null,
    fallbackSev: FALLBACK_SEVS[i % FALLBACK_SEVS.length],
    haloColor: HALO_COLORS[i % HALO_COLORS.length],
  }));

  /* ── dense dot-matrix land mask — [lon, lat] samples covering continents ── */
  /* Generated at 4° grid spacing inside each continent bounding box */
  const LAND_DOTS = (() => {
    // Simple point-in-polygon test
    const pip = (px, py, poly) => {
      let inside = false;
      for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
        const [xi, yi] = poly[i], [xj, yj] = poly[j];
        const intersect = ((yi > py) !== (yj > py)) && (px < ((xj - xi) * (py - yi)) / (yj - yi) + xi);
        if (intersect) inside = !inside;
      }
      return inside;
    };
    const continentPolys = [
      /* North America */
      [[-168,71],[-141,60],[-124,49],[-117,32],[-104,19],[-87,16],[-83,9],[-77,8],
       [-66,11],[-60,14],[-59,18],[-73,20],[-81,25],[-80,32],[-75,45],[-64,44],
       [-67,47],[-60,47],[-60,55],[-75,63],[-83,68],[-97,70],[-120,72],[-140,71],[-168,71]],
      /* South America */
      [[-80,8],[-77,-1],[-75,-15],[-70,-18],[-65,-22],[-57,-38],[-64,-55],[-66,-55],
       [-68,-45],[-72,-42],[-72,-30],[-68,-22],[-60,-15],[-50,-5],[-35,-5],[-35,5],
       [-50,5],[-60,9],[-70,12],[-76,8],[-80,8]],
      /* Europe */
      [[-9,36],[0,36],[12,37],[18,40],[27,41],[30,46],[26,58],[20,60],[14,57],
       [10,55],[4,52],[3,48],[-1,44],[-9,44],[-9,36]],
      /* Africa */
      [[-17,15],[-14,10],[-14,5],[0,5],[10,4],[20,4],[36,11],[42,11],[44,2],[40,-11],
       [35,-18],[32,-30],[25,-35],[20,-35],[15,-30],[10,-22],[9,-5],[2,5],[-5,5],
       [-16,12],[-17,15]],
      /* Asia */
      [[26,42],[36,42],[42,37],[50,30],[58,23],[66,24],[72,20],[80,12],[88,8],[100,5],
       [104,1],[108,3],[110,10],[120,22],[130,33],[140,43],[145,45],[140,55],
       [130,60],[110,70],[90,77],[68,77],[50,72],[40,68],[36,62],[30,58],[26,55],[26,42]],
      /* Australia */
      [[114,-22],[120,-35],[130,-34],[138,-35],[145,-38],[148,-38],[152,-25],[148,-20],
       [138,-13],[130,-12],[122,-18],[114,-22]],
      /* Greenland */
      [[-44,60],[-22,60],[-18,68],[-20,78],[-36,84],[-52,83],[-58,76],[-58,68],[-44,60]],
    ];
    const dots = [];
    for (let lon = -180; lon <= 180; lon += 3.5) {
      for (let lat = -75; lat <= 80; lat += 3.5) {
        for (const poly of continentPolys) {
          if (pip(lon, lat, poly)) { dots.push([lon, lat]); break; }
        }
      }
    }
    return dots;
  })();

  /* ── project lon/lat → canvas xy given current rotation ── */
  function project(lon, lat, R, cx, cy, rot) {
    const phi   = (90 - lat) * (Math.PI / 180);
    const theta = (lon + rot) * (Math.PI / 180);
    const x = cx + R * Math.sin(phi) * Math.cos(theta);
    const y = cy + R * Math.cos(phi);
    const z =      Math.sin(phi) * Math.sin(theta);
    return { x, y, z };
  }

  /* ── draw frame ── */
  function drawFrame(canvas, rot, hovIdx, selData) {
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    const cx = W / 2, cy = H / 2;
    const R  = Math.min(W, H) * 0.44;

    ctx.clearRect(0, 0, W, H);

    /* ── 1. Deep navy ocean sphere ── */
    const oceanGrad = ctx.createRadialGradient(cx - R * .28, cy - R * .28, R * .04, cx, cy, R);
    oceanGrad.addColorStop(0,   'rgba(25,45,110,1)');
    oceanGrad.addColorStop(0.5, 'rgba(10,20,60,1)');
    oceanGrad.addColorStop(1,   'rgba(4,8,28,1)');
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.fillStyle = oceanGrad; ctx.fill();

    /* ── 2. Clip to sphere for land dots ── */
    ctx.save();
    ctx.beginPath(); ctx.arc(cx, cy, R - 0.5, 0, Math.PI * 2); ctx.clip();

    /* ── 3. Land dot matrix — dense small dots like the reference ── */
    LAND_DOTS.forEach(([lon, lat]) => {
      const { x, y, z } = project(lon, lat, R, cx, cy, rot);
      if (z < 0) return;
      const bright = 0.35 + z * 0.45;   // front-face brighter
      const r = 1.2 + z * 0.6;
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(80,130,180,${bright})`;
      ctx.fill();
    });

    ctx.restore();

    /* ── 4. Atmosphere outer glow (behind dots, wraps sphere edge) ── */
    const atmOut = ctx.createRadialGradient(cx, cy, R * 0.82, cx, cy, R * 1.22);
    atmOut.addColorStop(0,   'rgba(30,80,200,0)');
    atmOut.addColorStop(0.6, 'rgba(30,80,200,0.10)');
    atmOut.addColorStop(1,   'rgba(30,80,200,0)');
    ctx.beginPath(); ctx.arc(cx, cy, R * 1.22, 0, Math.PI * 2);
    ctx.fillStyle = atmOut; ctx.fill();

    /* ── 5. Rim/edge glow — brighter blue ring around sphere edge ── */
    const rimGrad = ctx.createRadialGradient(cx, cy, R * 0.88, cx, cy, R * 1.02);
    rimGrad.addColorStop(0,   'rgba(60,120,255,0)');
    rimGrad.addColorStop(0.7, 'rgba(60,120,255,0.22)');
    rimGrad.addColorStop(1,   'rgba(100,180,255,0.08)');
    ctx.beginPath(); ctx.arc(cx, cy, R * 1.02, 0, Math.PI * 2);
    ctx.fillStyle = rimGrad; ctx.fill();

    /* ── 6. Top-left specular highlight ── */
    const spec = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.35, 0, cx - R * 0.35, cy - R * 0.35, R * 0.55);
    spec.addColorStop(0,   'rgba(120,180,255,0.12)');
    spec.addColorStop(1,   'rgba(120,180,255,0)');
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.fillStyle = spec; ctx.fill();

    /* ── 7. City hotspot beacons ── */
    spots.forEach(({ lon, lat, threat, fallbackSev, haloColor }, idx) => {
      const { x, y, z } = project(lon, lat, R, cx, cy, rot);
      if (z < 0.05) return;

      const isHov  = hovIdx === idx;
      const isSel  = selData?.idx === idx;
      const depth  = 0.4 + z * 0.6;   // fade with depth

      /* ── outer bloom — large soft halo matching reference image ── */
      const bloomR = (isHov ? 26 : 18) * depth;
      const bloom  = ctx.createRadialGradient(x, y, 0, x, y, bloomR);
      bloom.addColorStop(0,   hexAlpha(haloColor, 0.30 * depth));
      bloom.addColorStop(0.4, hexAlpha(haloColor, 0.15 * depth));
      bloom.addColorStop(1,   hexAlpha(haloColor, 0));
      ctx.beginPath(); ctx.arc(x, y, bloomR, 0, Math.PI * 2);
      ctx.fillStyle = bloom; ctx.fill();

      /* ── mid glow ring ── */
      const midR  = (isHov ? 10 : 7) * depth;
      const midGl = ctx.createRadialGradient(x, y, 0, x, y, midR);
      midGl.addColorStop(0,   hexAlpha(haloColor, 0.70 * depth));
      midGl.addColorStop(0.6, hexAlpha(haloColor, 0.35 * depth));
      midGl.addColorStop(1,   hexAlpha(haloColor, 0));
      ctx.beginPath(); ctx.arc(x, y, midR, 0, Math.PI * 2);
      ctx.fillStyle = midGl; ctx.fill();

      /* ── selected pulse ring ── */
      if (isSel) {
        ctx.beginPath(); ctx.arc(x, y, midR * 1.8, 0, Math.PI * 2);
        ctx.strokeStyle = haloColor;
        ctx.lineWidth = 1.2;
        ctx.globalAlpha = 0.55 * depth;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      /* ── bright core dot ── */
      const coreR = (isHov ? 4 : 3) * depth;
      ctx.beginPath(); ctx.arc(x, y, coreR, 0, Math.PI * 2);
      ctx.fillStyle = haloColor;
      ctx.globalAlpha = depth;
      ctx.shadowBlur = 8;
      ctx.shadowColor = haloColor;
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.shadowBlur = 0;

      /* ── white hot centre ── */
      ctx.beginPath(); ctx.arc(x, y, coreR * 0.45, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255,255,255,0.95)';
      ctx.globalAlpha = depth;
      ctx.fill();
      ctx.globalAlpha = 1;
    });
  }

  /* hex colour → rgba string helper */
  function hexAlpha(hex, a) {
    const r = parseInt(hex.slice(1,3),16);
    const g = parseInt(hex.slice(3,5),16);
    const b = parseInt(hex.slice(5,7),16);
    return `rgba(${r},${g},${b},${a.toFixed(3)})`;
  }

  /* ── animation loop — single stable RAF, never torn down on mouse events ── */
  useEffect(() => {
    const canvas = canvasRef.current; if (!canvas) return;
    const loop = ts => {
      if (!dragging.current) {
        const dt = ts - lastTsRef.current;
        rotRef.current = (rotRef.current + dt * 0.018) % 360;
      }
      lastTsRef.current = ts;
      drawFrame(canvas, rotRef.current, hoveredRef.current, selectedRef.current);
      animRef.current = requestAnimationFrame(loop);
    };
    animRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animRef.current);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [threats]);

  /* ── mouse interaction ── */
  const getHitSpot = (e) => {
    const canvas = canvasRef.current; if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width  / rect.width;
    const scaleY = canvas.height / rect.height;
    const mx = (e.clientX - rect.left) * scaleX;
    const my = (e.clientY - rect.top)  * scaleY;
    const W = canvas.width, H = canvas.height;
    const cx = W / 2, cy = H / 2;
    const R  = Math.min(W, H) * 0.42;
    let best = null, bestD = 14;
    spots.forEach(({ lon, lat }, idx) => {
      const { x, y, z } = project(lon, lat, R, cx, cy, rotRef.current);
      if (z < 0.05) return;
      const d = Math.hypot(mx - x, my - y);
      if (d < bestD) { bestD = d; best = idx; }
    });
    return best;
  };

  const onMouseMove = (e) => {
    if (dragging.current) {
      const dx = e.clientX - lastX.current;
      rotRef.current = (rotRef.current + dx * 0.4) % 360;
      lastX.current  = e.clientX;
      selectedRef.current = null;
      setTooltip(null);
    } else {
      const hit = getHitSpot(e);
      hoveredRef.current = hit !== null ? hit : -1;
    }
  };
  const onMouseDown = (e) => { dragging.current = true; lastX.current = e.clientX; };
  const onMouseUp   = (e) => {
    if (!dragging.current) return;
    dragging.current = false;
    const hit = getHitSpot(e);
    if (hit !== null) {
      const canvas = canvasRef.current;
      const rect   = canvas.getBoundingClientRect();
      const selData = { idx: hit, x: e.clientX - rect.left, y: e.clientY - rect.top };
      selectedRef.current = selData;
      setTooltip(selData);
    }
  };
  const onMouseLeave = () => { dragging.current = false; hoveredRef.current = -1; };

  /* touch drag */
  const onTouchStart = (e) => { dragging.current = true; lastX.current = e.touches[0].clientX; };
  const onTouchMove  = (e) => {
    if (!dragging.current) return;
    const dx = e.touches[0].clientX - lastX.current;
    rotRef.current = (rotRef.current + dx * 0.4) % 360;
    lastX.current  = e.touches[0].clientX;
  };
  const onTouchEnd = () => { dragging.current = false; };

  const selSpot   = tooltip !== null ? spots[tooltip.idx] : null;
  const selThreat = selSpot?.threat;

  return (
    <div className="globe-wrapper">
      <div className="globe-canvas-wrap" style={{ position: 'relative' }}>
        <canvas
          ref={canvasRef} width={420} height={420}
          className="globe-canvas"
          style={{ cursor: hoveredRef.current !== -1 ? 'pointer' : dragging.current ? 'grabbing' : 'grab' }}
          onMouseMove={onMouseMove} onMouseDown={onMouseDown}
          onMouseUp={onMouseUp}   onMouseLeave={onMouseLeave}
          onTouchStart={onTouchStart} onTouchMove={onTouchMove} onTouchEnd={onTouchEnd}
        />
        <div className="globe-hint">Drag to rotate · Click dot for details</div>

        {/* Click tooltip */}
        {tooltip && selThreat && (
          <div className="globe-tooltip"
            style={{ left: Math.min(tooltip.x + 12, 200), top: Math.max(tooltip.y - 20, 4) }}>
            <button className="globe-tt-close" onClick={() => { selectedRef.current = null; setTooltip(null); }}>✕</button>
            <div className={`globe-tt-sev globe-tt-sev--${selThreat.severity?.toLowerCase()}`}>
              {selThreat.severity?.toUpperCase() || 'UNKNOWN'}
            </div>
            <p className="globe-tt-name">{selThreat.name || selThreat.cve_id || 'Unknown Threat'}</p>
            {selThreat.cve_id && <p className="globe-tt-cve">{selThreat.cve_id}</p>}
            <p className="globe-tt-loc"><i className="fas fa-map-marker-alt"></i> {selSpot.label}</p>
            {selThreat.cvss_score != null && (
              <p className="globe-tt-score">CVSS <strong>{selThreat.cvss_score.toFixed(1)}</strong></p>
            )}
            {selThreat.created_at && (
              <p className="globe-tt-date">
                <i className="fas fa-clock"></i> {new Date(selThreat.created_at).toLocaleDateString('en-GB', {day:'2-digit',month:'short',year:'numeric'})}
              </p>
            )}
            {selThreat.description && (
              <p className="globe-tt-desc">{selThreat.description.slice(0, 120)}{selThreat.description.length > 120 ? '…' : ''}</p>
            )}
          </div>
        )}
        {tooltip && !selThreat && (
          <div className="globe-tooltip"
            style={{ left: Math.min(tooltip.x + 12, 200), top: Math.max(tooltip.y - 20, 4) }}>
            <button className="globe-tt-close" onClick={() => { selectedRef.current = null; setTooltip(null); }}>✕</button>
            <div className="globe-tt-sev globe-tt-sev--low">LOW</div>
            <p className="globe-tt-name">No active threat</p>
            <p className="globe-tt-loc"><i className="fas fa-map-marker-alt"></i> {selSpot?.label}</p>
            <p className="globe-tt-desc">This region is currently clean.</p>
          </div>
        )}
      </div>

      {/* Severity legend + threat list */}
      <div className="globe-side">
        <div className="globe-sev-legend">
          <span className="gsl-item"><span className="gsl-dot gsl-red"></span>Critical / High</span>
          <span className="gsl-item"><span className="gsl-dot gsl-yellow"></span>Severe / Medium</span>
          <span className="gsl-item"><span className="gsl-dot gsl-green"></span>Low</span>
        </div>
        <div className="globe-threat-list">
          {threats.slice(0, 6).map((t, i) => {
            const sev = t.severity?.toLowerCase() || 'low';
            return (
              <div key={i} className={`globe-threat-row gtr--${sev}`}
                onClick={() => {
                  const selData = { idx: i % spots.length, x: 160, y: 80 + i * 22 };
                  selectedRef.current = selData;
                  setTooltip(selData);
                }}>
                <span className={`sev-dot sev-${sev}`}></span>
                <span className="globe-cve">{t.cve_id || t.name?.slice(0, 18) || 'CVE-???'}</span>
                <span className="globe-score">CVSS {t.cvss_score?.toFixed(1) ?? 'N/A'}</span>
                <span className={`globe-sev-tag sev-tag--${sev}`}>{sev}</span>
              </div>
            );
          })}
          {threats.length === 0 && (
            <div className="globe-empty">
              <i className="fas fa-satellite-dish"></i> Syncing threat feed…
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

