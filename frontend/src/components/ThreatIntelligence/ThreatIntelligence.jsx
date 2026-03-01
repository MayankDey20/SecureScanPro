import { useState, useEffect, useRef } from 'react';
import { threatsAPI } from '../../services/api';
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, PointElement, LineElement,
  Filler, Tooltip, Legend
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import './ThreatIntelligence.css';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend);

const sevClass = (s = '') => s.toLowerCase();

const fmtDateTime = (raw) => {
  if (!raw) return '—';
  try {
    const d = new Date(raw);
    return {
      date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
      time: d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }),
    };
  } catch { return { date: '—', time: '' }; }
};

/* ════════════════════════════════════════
   GLOBE — proper 3-D dot-matrix sphere
════════════════════════════════════════ */
const LAND_POLYS = [
  // North America
  [[49,-125],[49,-67],[25,-80],[20,-87],[16,-90],[8,-77],[9,-79],[8,-77],[20,-87],[25,-80],[49,-67],[49,-125]],
  // South America
  [[-5,-80],[-5,-35],[-55,-68],[-55,-68],[-35,-58],[-20,-40],[-5,-35],[-5,-80]],
  // Europe
  [[71,28],[71,25],[60,5],[51,2],[43,-9],[36,-6],[36,28],[50,30],[71,28]],
  // Africa
  [[37,10],[37,42],[12,44],[-35,18],[-35,18],[-22,14],[0,-18],[15,-17],[37,10]],
  // Asia
  [[71,28],[71,140],[23,120],[1,103],[12,44],[37,42],[71,28]],
  // Australia
  [[-15,130],[-15,145],[-38,145],[-38,114],[-22,114],[-15,130]],
];

function projectPoint(lat, lon, cx, cy, R, rotY) {
  const phi  = (lat * Math.PI) / 180;
  const lam  = ((lon + rotY) * Math.PI) / 180;
  const x3 = Math.cos(phi) * Math.sin(lam);
  const y3 = Math.sin(phi);
  const z3 = Math.cos(phi) * Math.cos(lam);
  return { sx: cx + R * x3, sy: cy - R * y3, z: z3 };
}

function isLand(lat, lon) {
  // simple dot-in-poly for each continent polygon
  for (const poly of LAND_POLYS) {
    let inside = false;
    for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
      const [yi, xi] = poly[i], [yj, xj] = poly[j];
      if ((yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) {
        inside = !inside;
      }
    }
    if (inside) return true;
  }
  return false;
}

const GlobeCanvas = ({ threats }) => {
  const canvasRef = useRef(null);
  const animRef   = useRef(null);
  const rotRef    = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Sync canvas pixel size to its CSS display size
    const syncSize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr  = window.devicePixelRatio || 1;
      const w    = Math.round(rect.width  * dpr);
      const h    = Math.round(rect.height * dpr);
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width  = w;
        canvas.height = h;
        ctx.scale(dpr, dpr);
      }
    };

    const ro = new ResizeObserver(() => syncSize());
    ro.observe(canvas);
    syncSize();

    const draw = () => {
      syncSize();
      const dpr = window.devicePixelRatio || 1;
      const W = canvas.width  / dpr;
      const H = canvas.height / dpr;
      const cx = W / 2, cy = H / 2;
      const R  = Math.min(W, H) * 0.42;
      const rot = rotRef.current;

      ctx.clearRect(0, 0, W, H);

      // atmosphere glow
      const atm = ctx.createRadialGradient(cx, cy, R * 0.85, cx, cy, R * 1.15);
      atm.addColorStop(0, 'rgba(59,130,246,0.18)');
      atm.addColorStop(1, 'rgba(59,130,246,0)');
      ctx.fillStyle = atm;
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.15, 0, Math.PI * 2); ctx.fill();

      // inner glow
      const inner = ctx.createRadialGradient(cx - R*0.3, cy - R*0.3, 0, cx, cy, R);
      inner.addColorStop(0, 'rgba(99,179,255,0.09)');
      inner.addColorStop(1, 'rgba(3,12,36,0.92)');
      ctx.fillStyle = inner;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();

      // dot matrix: ocean + land
      const step = 4.5;
      for (let lat = -85; lat <= 85; lat += step) {
        for (let lon = -180; lon <= 180; lon += step / Math.max(0.3, Math.cos((lat*Math.PI)/180))) {
          const { sx, sy, z } = projectPoint(lat, lon, cx, cy, R, rot);
          if (z < 0) continue;
          const land = isLand(lat, lon);
          const alpha = 0.35 + z * 0.5;
          if (land) {
            ctx.beginPath();
            ctx.arc(sx, sy, 1.4, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(56,189,248,${alpha})`;
            ctx.fill();
          } else {
            ctx.beginPath();
            ctx.arc(sx, sy, 0.7, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(30,58,100,${alpha * 0.6})`;
            ctx.fill();
          }
        }
      }

      // outline
      ctx.strokeStyle = 'rgba(56,189,248,0.30)';
      ctx.lineWidth = 0.8;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.stroke();

      // threat dots
      const colors = {
        critical: '#ef4444', high: '#f59e0b',
        medium: '#a855f7', low: '#10b981', info: '#60a5fa',
      };
      (threats || []).slice(0, 25).forEach((t, i) => {
        const lat2 = ((i * 41 + 13) % 150) - 75;
        const lon2 = ((i * 67 - 30) % 360) - 180;
        const { sx, sy, z: z2 } = projectPoint(lat2, lon2, cx, cy, R, rot);
        if (z2 < 0.1) return;
        const col = colors[t.severity?.toLowerCase()] || '#60a5fa';
        // pulse ring
        ctx.beginPath();
        ctx.arc(sx, sy, 6, 0, Math.PI * 2);
        ctx.strokeStyle = col.replace(')', ',0.25)').replace('rgb', 'rgba') || `${col}40`;
        ctx.lineWidth = 0.8;
        ctx.stroke();
        // dot
        ctx.beginPath();
        ctx.arc(sx, sy, 3.2, 0, Math.PI * 2);
        ctx.fillStyle = col;
        ctx.shadowColor = col;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      rotRef.current += 0.18;
      animRef.current = requestAnimationFrame(draw);
    };

    draw();
    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current);
      ro.disconnect();
    };
  }, [threats]);

  return (
    <canvas
      ref={canvasRef}
      style={{ width: '100%', height: '100%', display: 'block' }}
    />
  );
};

/* ════════════════════════════════════════
   Threat Volume chart data — uses real API data
════════════════════════════════════════ */
const buildChartData = (chartRows) => {
  // chartRows: [{date: "YYYY-MM-DD", count: N}] for last 30 days
  const labels = [];
  const counts = [];
  const days = chartRows.length;
  chartRows.forEach((row, i) => {
    const label =
      i === 0               ? '30 Days' :
      i === Math.round(days * 0.25) ? `${Math.round(days * 0.75)} days` :
      i === Math.round(days * 0.5)  ? `${Math.round(days * 0.5)} days` :
      i === Math.round(days * 0.75) ? `${Math.round(days * 0.25)} days` :
      i === days - 1        ? 'Today' : '';
    labels.push(label);
    counts.push(row.count);
  });
  return { labels, counts };
};

/* ════════════════════════════════════════
   Severity icon (skull/shield)
════════════════════════════════════════ */
const SevIcon = ({ sev }) => {
  const s = sev?.toLowerCase();
  if (s === 'critical') return (
    <div className="ti-sev-icon critical">
      <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
        <path d="M12 2C7.03 2 3 6.03 3 11c0 3.1 1.5 5.8 3.8 7.5V21h10.4v-2.5C19.5 16.8 21 14.1 21 11c0-4.97-4.03-9-9-9zm-1 14v-2h2v2h-2zm0-4V7h2v5h-2z"/>
      </svg>
    </div>
  );
  if (s === 'high') return (
    <div className="ti-sev-icon high">
      <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 14l-3-3 1.41-1.41L11 12.17l4.59-4.58L17 9l-6 6z"/>
      </svg>
    </div>
  );
  return (
    <div className="ti-sev-icon medium">
      <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
        <path d="M12 2L1 21h22L12 2zm1 14h-2v2h2v-2zm0-6h-2v4h2v-4z"/>
      </svg>
    </div>
  );
};

/* ════════════════════════════════════════
   MAIN COMPONENT
════════════════════════════════════════ */
const ThreatIntelligence = () => {
  const [threats, setThreats]         = useState([]);
  const [chartRows, setChartRows]     = useState([]);
  const [loading, setLoading]         = useState(true);
  const [syncing, setSyncing]         = useState(false);
  const [realtimeBadge, setRealtimeBadge] = useState(0); // count of new threats since page load
  const sseRef = useRef(null);

  useEffect(() => {
    loadAll();
    startSSE();
    return () => { if (sseRef.current) sseRef.current.close(); };
  }, []);

  const loadAll = async () => {
    try {
      setLoading(true);
      const [data, chart] = await Promise.all([
        threatsAPI.list({ skip: 0, limit: 100 }),
        threatsAPI.getLast30Days().catch(() => ({ data: [] })),
      ]);
      setThreats(data);
      setChartRows(chart.data || []);
    } catch (err) {
      console.error('Failed to load threats:', err);
    } finally {
      setLoading(false);
    }
  };

  const startSSE = () => {
    if (sseRef.current) sseRef.current.close();
    const es = new EventSource(threatsAPI.streamUrl());
    sseRef.current = es;

    es.addEventListener('threats', (e) => {
      try {
        const newItems = JSON.parse(e.data);
        if (newItems.length > 0) {
          setThreats(prev => {
            const existingIds = new Set(prev.map(t => t.id));
            const novel = newItems.filter(t => !existingIds.has(t.id));
            if (novel.length === 0) return prev;
            setRealtimeBadge(b => b + novel.length);
            return [...novel, ...prev];
          });
          // bump chart counts for today
          setChartRows(prev => {
            if (prev.length === 0) return prev;
            const updated = [...prev];
            updated[updated.length - 1] = {
              ...updated[updated.length - 1],
              count: updated[updated.length - 1].count + newItems.length,
            };
            return updated;
          });
        }
      } catch { /* ignore malformed */ }
    });

    es.onerror = () => {
      // SSE reconnects automatically; only close if page is unloading
    };
  };

  const handleSync = async () => {
    try {
      setSyncing(true);
      await threatsAPI.sync();
      setRealtimeBadge(0);
      await loadAll();
    } catch (err) {
      console.error('Sync failed:', err);
    } finally {
      setSyncing(false);
    }
  };

  const { labels, counts } = buildChartData(chartRows);
  const chartData = {
    labels,
    datasets: [{
      label: 'Threats',
      data: counts,
      borderColor: '#a855f7',
      backgroundColor: 'rgba(168,85,247,0.15)',
      fill: true,
      tension: 0.5,
      pointRadius: 0,
      borderWidth: 2,
    }],
  };
  const chartOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(8,16,40,0.95)',
        bodyColor: '#94a3b8',
        titleColor: '#cbd5e1',
        bodyFont: { size: 11 },
        titleFont: { size: 11 },
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(255,255,255,0.05)' },
        ticks: {
          color: '#475569',
          font: { size: 10 },
          maxRotation: 0,
          callback: (_, i) => labels[i] || '',
        },
      },
      y: {
        grid: { color: 'rgba(255,255,255,0.05)' },
        ticks: { color: '#475569', font: { size: 10 } },
        beginAtZero: true,
      },
    },
  };

  return (
    <section className="ti-section">
      {/* Page header */}
      <h1 className="ti-title">Threat Intelligence</h1>
      <p className="ti-subtitle">Real-time threat data from the last 30 days</p>

      {loading ? (
        <div className="ti-loading">Loading threat intelligence…</div>
      ) : (
        <div className="ti-layout">

          {/* ── LEFT ── */}
          <div className="ti-left">

            {/* Globe card */}
            <div className="ti-globe-card">
              <div className="ti-globe-topbar">
                <button
                  className="ti-sync-btn"
                  onClick={handleSync}
                  disabled={syncing}
                >
                  {syncing ? '↻ Syncing…' : '↻ Sync Threats'}
                </button>
                {realtimeBadge > 0 && (
                  <span className="ti-realtime-badge">
                    +{realtimeBadge} new
                  </span>
                )}
                <span className="ti-live-dot" title="Real-time SSE active">● LIVE</span>
              </div>
              <div className="ti-globe-wrap">
                <GlobeCanvas threats={threats} />
              </div>
            </div>

            {/* Threat Volume chart */}
            <div className="ti-chart-card">
              <div className="ti-chart-header">
                <span className="ti-chart-title">Threat Volume</span>
                <span className="ti-chart-badge">↗ last 30 days</span>
              </div>
              <div className="ti-chart-wrap">
                <Line data={chartData} options={chartOpts} />
              </div>
            </div>

          </div>

          {/* ── RIGHT: Recent Threats ── */}
          <div className="ti-right">
            <div className="ti-threats-card">
              <div className="ti-threats-head">
                <span className="ti-threats-title">Recent Threats</span>
                <button className="ti-refresh-icon" onClick={loadAll} title="Refresh">↺</button>
              </div>
              <div className="ti-threats-list">
                {threats.length === 0 && (
                  <div className="ti-empty">
                    No threats loaded.<br />Click ↻ Sync Threats.
                  </div>
                )}
                {threats.slice(0, 30).map((threat, i) => {
                  const sev = (threat.severity || 'info').toLowerCase();
                  const { date, time } = fmtDateTime(threat.created_at || threat.published_date || threat.published_at);
                  return (
                    <div key={threat.id || i} className={`ti-threat-item${i < realtimeBadge ? ' ti-threat-item--new' : ''}`}>
                      <SevIcon sev={threat.severity} />
                      <div className="ti-threat-body">
                        <span className="ti-threat-sev-label">Severity — {sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
                        <span className="ti-threat-name-text">{threat.title || threat.description || 'Unknown threat'}</span>
                      </div>
                      <div className="ti-threat-time-col">
                        <span className="ti-threat-date">{date}</span>
                        <span className="ti-threat-time">{time}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

        </div>
      )}
    </section>
  );
};

export default ThreatIntelligence;
