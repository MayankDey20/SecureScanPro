import { useState, useEffect } from 'react';
import { analyticsAPI } from '../../services/api';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import './Analytics.css';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

// Shared chart font config
const PIXEL_FONT = "'Press Start 2P', monospace";

// Shared tooltip style
const tooltipPlugin = {
  backgroundColor: 'rgba(8,16,40,0.95)',
  borderColor: 'rgba(59,130,246,0.35)',
  borderWidth: 1,
  titleColor: '#94a3b8',
  bodyColor: '#60a5fa',
  titleFont: { family: PIXEL_FONT, size: 9 },
  bodyFont:  { family: PIXEL_FONT, size: 9 },
  padding: 10,
  cornerRadius: 6,
};

// Fake fallback data when API has nothing
const FALLBACK_LABELS = ['Week 1','Week 2','Week 3','Week 4','Week 5','Week 6'];
const FALLBACK_SCORES = [72, 65, 78, 58, 83, 76];

const Analytics = () => {
  const [trends, setTrends] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadTrends();
  }, []);

  const loadTrends = async () => {
    try {
      setLoading(true);
      const data = await analyticsAPI.getTrends('30d');
      setTrends(data);
    } catch (error) {
      console.error('Failed to load trends:', error);
    } finally {
      setLoading(false);
    }
  };

  // ── derive chart data ────────────────────────────────
  const labels = trends?.labels || FALLBACK_LABELS;
  const scores = trends?.securityScores || FALLBACK_SCORES;
  // Shorten date labels: "2026-02-21" → "Feb 21"
  const shortLabels = labels.map(l => {
    try {
      const d = new Date(l + 'T00:00:00');
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch { return l; }
  });

  const vulnDist = trends?.vulnerabilityDistribution || {
    critical: 12, high: 28, medium: 45, low: 30, info: 18,
  };

  const topAssets = trends?.topAssets || [
    { name: 'api.example.com', count: 14 },
    { name: 'app.example.com', count: 9  },
    { name: 'cdn.example.com', count: 6  },
    { name: 'auth.example.com',count: 5  },
    { name: 'db.example.com',  count: 3  },
  ];

  // ── Line chart ──────────────────────────────────────
  const lineData = {
    labels: shortLabels,
    datasets: [
      {
        label: 'Security Score',
        data: scores,
        borderColor: '#3b82f6',
        borderWidth: 3,
        pointBackgroundColor: '#3b82f6',
        pointBorderColor: '#60a5fa',
        pointBorderWidth: 2,
        pointRadius: 5,
        pointHoverRadius: 8,
        tension: 0.45,
        fill: true,
        backgroundColor: (ctx) => {
          if (!ctx.chart.chartArea) return 'rgba(59,130,246,0.05)';
          const { top, bottom } = ctx.chart.chartArea;
          const gradient = ctx.chart.ctx.createLinearGradient(0, top, 0, bottom);
          gradient.addColorStop(0, 'rgba(59,130,246,0.30)');
          gradient.addColorStop(1, 'rgba(59,130,246,0.01)');
          return gradient;
        },
        shadowOffsetX: 0,
        shadowOffsetY: 4,
        shadowBlur: 12,
        shadowColor: 'rgba(59,130,246,0.60)',
      },
    ],
  };

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#475569',
          font: { family: PIXEL_FONT, size: 9 },
          boxWidth: 12,
        },
      },
      tooltip: tooltipPlugin,
    },
    scales: {
      x: {
        grid: { color: 'rgba(59,130,246,0.07)' },
        ticks: { color: '#334155', font: { family: PIXEL_FONT, size: 8 } },
      },
      y: {
        min: 0, max: 100,
        grid: { color: 'rgba(59,130,246,0.07)' },
        ticks: { color: '#334155', font: { family: PIXEL_FONT, size: 8 } },
      },
    },
  };

  // ── Doughnut chart ──────────────────────────────────
  const doughnutData = {
    labels: ['Critical','High','Medium','Low','Info'],
    datasets: [
      {
        data: [
          vulnDist.critical || 0,
          vulnDist.high     || 0,
          vulnDist.medium   || 0,
          vulnDist.low      || 0,
          vulnDist.info     || 0,
        ],
        backgroundColor: [
          'rgba(239,68,68,0.80)',
          'rgba(245,158,11,0.80)',
          'rgba(59,130,246,0.80)',
          'rgba(16,185,129,0.80)',
          'rgba(107,114,128,0.80)',
        ],
        borderColor: [
          'rgba(239,68,68,1)',
          'rgba(245,158,11,1)',
          'rgba(59,130,246,1)',
          'rgba(16,185,129,1)',
          'rgba(107,114,128,1)',
        ],
        borderWidth: 2,
        hoverOffset: 8,
        hoverBorderWidth: 3,
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '60%',
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#475569',
          font: { family: PIXEL_FONT, size: 8 },
          padding: 12,
          boxWidth: 10,
        },
      },
      tooltip: tooltipPlugin,
    },
  };

  // ── Bar chart ────────────────────────────────────────
  const barLabels = topAssets.map(a => a.name || a.target || a);
  const barCounts = topAssets.map(a => a.count || a.finding_count || a);

  const barData = {
    labels: barLabels,
    datasets: [
      {
        label: 'Findings',
        data: barCounts,
        backgroundColor: barCounts.map((_, i) => {
          const cols = [
            'rgba(239,68,68,0.75)',
            'rgba(245,158,11,0.75)',
            'rgba(59,130,246,0.75)',
            'rgba(99,102,241,0.75)',
            'rgba(16,185,129,0.75)',
          ];
          return cols[i % cols.length];
        }),
        borderColor: barCounts.map((_, i) => {
          const cols = ['#ef4444','#f59e0b','#3b82f6','#6366f1','#10b981'];
          return cols[i % cols.length];
        }),
        borderWidth: 2,
        borderRadius: 6,
        borderSkipped: false,
        hoverBorderWidth: 3,
      },
    ],
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y',
    plugins: {
      legend: { display: false },
      tooltip: tooltipPlugin,
    },
    scales: {
      x: {
        grid: { color: 'rgba(59,130,246,0.07)' },
        ticks: { color: '#334155', font: { family: PIXEL_FONT, size: 8 } },
      },
      y: {
        grid: { color: 'transparent' },
        ticks: { color: '#64748b', font: { family: PIXEL_FONT, size: 8 } },
      },
    },
  };

  if (loading) {
    return <div className="analytics-loading">Loading analytics...</div>;
  }

  // summary counts
  const totalVulns = Object.values(vulnDist).reduce((a, b) => a + b, 0);
  const avgScore = scores.length
    ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
    : 0;
  const latestScore = scores[scores.length - 1] ?? 0;

  return (
    <section className="analytics-section">
      <div className="analytics-header">
        <div>
          <h1 className="analytics-title">Security Analytics</h1>
          <p className="analytics-subtitle">Historical trends and vulnerability insights</p>
        </div>
      </div>

      {/* KPI row */}
      <div className="analytics-kpi-row">
        <div className="kpi-tile">
          <span className="kpi-value" style={{color:'#60a5fa'}}>{latestScore}</span>
          <span className="kpi-label">Current Score</span>
        </div>
        <div className="kpi-tile">
          <span className="kpi-value" style={{color:'#a78bfa'}}>{avgScore}</span>
          <span className="kpi-label">Avg Score</span>
        </div>
        <div className="kpi-tile">
          <span className="kpi-value" style={{color:'#f87171'}}>{vulnDist.critical || 0}</span>
          <span className="kpi-label">Critical</span>
        </div>
        <div className="kpi-tile">
          <span className="kpi-value" style={{color:'#fbbf24'}}>{vulnDist.high || 0}</span>
          <span className="kpi-label">High</span>
        </div>
        <div className="kpi-tile">
          <span className="kpi-value" style={{color:'#94a3b8'}}>{totalVulns}</span>
          <span className="kpi-label">Total Vulns</span>
        </div>
      </div>

      {/* charts grid */}
      <div className="analytics-grid">
        {/* Line chart */}
        <div className="chart-card chart-card--wide">
          <div className="chart-card-header">
            <span className="chart-card-title">Security Score Trends</span>
            <span className="chart-period">{trends?.period || '30d'}</span>
          </div>
          <div className="chart-body" style={{height:'220px'}}>
            <Line data={lineData} options={lineOptions} />
          </div>
        </div>

        {/* Doughnut */}
        <div className="chart-card">
          <div className="chart-card-header">
            <span className="chart-card-title">Vuln Distribution</span>
          </div>
          <div className="chart-body" style={{height:'220px'}}>
            <Doughnut data={doughnutData} options={doughnutOptions} />
          </div>
        </div>

        {/* Bar chart */}
        <div className="chart-card chart-card--wide">
          <div className="chart-card-header">
            <span className="chart-card-title">Top Affected Assets</span>
          </div>
          <div className="chart-body" style={{height:'220px'}}>
            <Bar data={barData} options={barOptions} />
          </div>
        </div>
      </div>
    </section>
  );
};

export default Analytics;

