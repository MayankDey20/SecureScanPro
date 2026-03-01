import { useState, useEffect } from 'react';
import { scanAPI } from '../../services/api';
import './Reports.css';

const scoreClass = (s) => {
  if (!s && s !== 0) return 'green';
  if (s >= 80) return 'green';
  if (s >= 60) return 'yellow';
  return 'red';
};

const Reports = () => {
  const [scans, setScans]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [search, setSearch]     = useState('');

  useEffect(() => { loadScans(); }, []);

  const loadScans = async () => {
    try {
      setLoading(true);
      const data = await scanAPI.list(0, 50);
      setScans(data.filter(s => s.status === 'completed'));
    } catch (err) {
      console.error('Failed to load scans:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (scanId, type) => {
    const url = `${import.meta.env.VITE_API_URL}/reports/${scanId}/${type}`;
    window.open(url, '_blank');
  };

  const visible = scans.filter(s => {
    if (!search) return true;
    const target = (s.target_url || s.target || '').toLowerCase();
    return target.includes(search.toLowerCase());
  });

  const fmtDate = (raw) => {
    try {
      return new Date(raw).toLocaleDateString('en-GB', {
        day: '2-digit', month: 'short', year: 'numeric'
      });
    } catch { return '—'; }
  };

  return (
    <section className="reports-section">
      <h1 className="rp-title">Security Reports</h1>
      <p className="rp-subtitle">Expert results from completed scans</p>

      <div className="rp-toolbar">
        <span className="rp-toolbar-brand">SecureScan&nbsp;Pro</span>
        <button className="rp-btn" onClick={loadScans} disabled={loading}>
          ↺ Refresh
        </button>
      </div>

      <div className="rp-filter-row">
        <select className="rp-select" defaultValue="">
          <option value="">☰ Filter</option>
          <option value="high">High Score</option>
          <option value="low">Low Score</option>
        </select>
        <select className="rp-select" defaultValue="">
          <option value="">Categories</option>
          <option value="web">Web</option>
          <option value="api">API</option>
          <option value="network">Network</option>
        </select>
        <input
          className="rp-search"
          type="text"
          placeholder="🔍  Search target…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      <div className="rp-card">
        {loading ? (
          <div className="rp-loading">⟳&nbsp;&nbsp;Loading reports…</div>
        ) : visible.length === 0 ? (
          <div className="rp-empty">
            No completed scans found.<br />
            Run a scan and return here once it finishes.
          </div>
        ) : (
          <table className="rp-table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Target</th>
                <th>Score</th>
                <th>Export</th>
              </tr>
            </thead>
            <tbody>
              {visible.map(scan => {
                const score = scan.security_score ?? null;
                const cls   = scoreClass(score);
                const pct   = score != null ? Math.min(100, score) : 0;
                return (
                  <tr key={scan.id}>
                    <td>{fmtDate(scan.created_at || scan.started_at)}</td>
                    <td className="rp-target">{scan.target_url || scan.target || '—'}</td>
                    <td>
                      <div className="score-bar-wrap">
                        <div className="score-bar-track">
                          <div
                            className={`score-bar-fill ${cls}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className={`score-num ${cls}`}>{score ?? 'N/A'}</span>
                      </div>
                    </td>
                    <td>
                      <div className="rp-dl-btns">
                        <button
                          className="rp-dl-btn"
                          title="Download JSON"
                          onClick={() => handleDownload(scan.id, 'json')}
                        >⬇</button>
                        <button
                          className="rp-dl-btn rp-dl-btn--alt"
                          title="Download CSV"
                          onClick={() => handleDownload(scan.id, 'csv')}
                        >CSV</button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
};

export default Reports;
