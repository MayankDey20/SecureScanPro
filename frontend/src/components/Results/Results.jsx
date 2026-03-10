import { useState, useEffect } from 'react';
import { scanAPI, aiAPI } from '../../services/api';
import { useRealtimeScan, useRealtimeScanList, isSupabaseEnabled } from '../../lib/supabase';
import { useAuth } from '../../contexts/AuthContext';
import './Results.css';

const sevClass = (s = '') => s.toLowerCase();

const fmtDate = (raw) => {
  if (!raw) return '—';
  try {
    return new Date(raw).toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
  } catch { return '—'; }
};

const Results = () => {
  const { user } = useAuth();
  const [scans, setScans]             = useState([]);
  const [selectedId, setSelectedId]   = useState(null);
  const [results, setResults]         = useState(null);
  const [loading, setLoading]         = useState(true);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [openRows, setOpenRows]       = useState({});
  const [aiResults, setAiResults]     = useState({});
  const [analyzingId, setAnalyzingId] = useState(null);

  // ── Supabase Realtime: live scan-list updates ──────────────────────────
  useRealtimeScanList(user?.id, {
    onInsert: (newScan) => setScans(prev => [newScan, ...prev]),
    onUpdate: (updated) => setScans(prev =>
      prev.map(s => s.id === updated.id ? { ...s, ...updated } : s)
    ),
  });

  // ── Supabase Realtime: live results for the selected scan ──────────────
  useRealtimeScan(selectedId, (updated) => {
    // Re-fetch full results when the selected scan row changes
    if (updated.status === 'completed' || updated.status === 'failed') {
      loadResults(updated.id);
    }
    setScans(prev => prev.map(s => s.id === updated.id ? { ...s, ...updated } : s));
  });

  useEffect(() => { loadScans(); }, []);

  useEffect(() => {
    if (selectedId) {
      setResults(null);
      setOpenRows({});
      loadResults(selectedId);
    }
  }, [selectedId]);

  const loadScans = async () => {
    try {
      setLoading(true);
      const data = await scanAPI.list(0, 50);
      setScans(data);
      if (data.length > 0) setSelectedId(data[0].id);
    } catch (err) {
      console.error('Failed to load scans:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadResults = async (id) => {
    try {
      setResultsLoading(true);
      const data = await scanAPI.getResults(id);
      setResults(data);
    } catch (err) {
      console.error('Failed to load results:', err);
    } finally {
      setResultsLoading(false);
    }
  };

  const toggleRow = (id) =>
    setOpenRows(prev => ({ ...prev, [id]: !prev[id] }));

  const handleAiAnalyze = async (finding) => {
    try {
      setAnalyzingId(finding.id);
      const analysis = await aiAPI.analyze(
        finding.title,
        finding.description || 'No description available.',
        finding.severity
      );
      setAiResults(prev => ({ ...prev, [finding.id]: analysis }));
    } catch (err) {
      console.error('AI analysis failed:', err);
    } finally {
      setAnalyzingId(null);
    }
  };

  const selectedScan = scans.find(s => s.id === selectedId);
  const score   = results?.securityScore ?? selectedScan?.security_score ?? null;
  const findings = results?.findings || [];
  const vulns   = results?.vulnerabilities || {};
  const criticalCount = vulns.critical ?? findings.filter(f => f.severity?.toLowerCase() === 'critical').length;

  const totalVulns = Object.values(vulns).reduce((a, n) => a + (Number(n) || 0), 0) || findings.length;

  if (loading) return <div className="rs-loading">Loading scan results…</div>;

  return (
    <section className="results-section">
      <h1 className="rs-title">Scan Results</h1>
      <p className="rs-subtitle">Detailed analysis of discovered vulnerabilities</p>

      <div className="rs-layout">

        {/* ── Sidebar ── */}
        <aside className="rs-sidebar">
          <div className="rs-sidebar-head">
            <span className="rs-sidebar-col-hdr">Recent Scans</span>
          </div>
          <div className="rs-sidebar-cols">
            <span className="rs-col-label">Status</span>
            <span className="rs-col-label">Date</span>
          </div>
          <div className="rs-scan-list">
            {scans.length === 0 && <div className="rs-empty">No scans yet.</div>}
            {scans.map(scan => (
              <div
                key={scan.id}
                className={`rs-scan-item ${selectedId === scan.id ? 'active' : ''}`}
                onClick={() => setSelectedId(scan.id)}
              >
                <div className="rs-scan-left">
                  <span className={`rs-dot ${scan.status || 'queued'}`} />
                  <span className="rs-scan-status-txt">Status</span>
                </div>
                <span className="rs-scan-date">{fmtDate(scan.created_at || scan.started_at)}</span>
              </div>
            ))}
          </div>
        </aside>

        {/* ── Main panel ── */}
        <div className="rs-main">

          {/* Stat tiles */}
          <div className="rs-stat-tiles">
            <div className="rs-stat-tile">
              <span className="rs-stat-num">{score ?? '—'}</span>
              <span className="rs-stat-lbl">Security Score</span>
            </div>
            <div className="rs-stat-tile critical">
              <span className="rs-stat-num">{criticalCount}</span>
              <span className="rs-stat-lbl">Critical Findings</span>
            </div>
            <div className="rs-stat-tile">
              <span className="rs-stat-num">{totalVulns}</span>
              <span className="rs-stat-lbl">Total Vulnerabilities</span>
            </div>
          </div>

          {/* Finding cards */}
          {resultsLoading && <div className="rs-loading">Loading findings…</div>}

          {!resultsLoading && findings.length === 0 && (
            <div className="rs-findings-empty">
              {selectedId ? 'No vulnerabilities found for this scan.' : 'Select a scan to view findings.'}
            </div>
          )}

          {findings.map(finding => {
            const sev = sevClass(finding.severity || 'info');
            const isOpen = !!openRows[finding.id];
            const ai = aiResults[finding.id];
            return (
              <div key={finding.id} className="rs-finding-card">
                {/* Card header row */}
                <div className="rs-fc-header" onClick={() => toggleRow(finding.id)}>
                  <div className="rs-fc-title-group">
                    <span className="rs-fc-title">
                      {finding.type ? `${finding.type} Description` : 'Security Description'}
                    </span>
                  </div>
                  <div className="rs-fc-right">
                    <span className={`rs-sev-badge ${sev}`}>{finding.severity}</span>
                    <span className="rs-chevron">{isOpen ? '∧' : '∨'}</span>
                  </div>
                </div>

                {/* Description always visible */}
                {finding.description && (
                  <p className="rs-fc-desc">{finding.description}</p>
                )}
                {finding.title && finding.title !== finding.description && (
                  <p className="rs-fc-subdesc">{finding.title}</p>
                )}

                {/* Remediation row */}
                <div className="rs-fc-actions">
                  <button
                    className="rs-remediation-btn"
                    onClick={() => toggleRow(finding.id)}
                  >
                    › Remediation Steps
                  </button>
                  <button
                    className="rs-remediation-btn"
                    disabled={analyzingId === finding.id}
                    onClick={e => { e.stopPropagation(); handleAiAnalyze(finding); }}
                  >
                    {analyzingId === finding.id ? '…' : '› AI Remediation'}
                  </button>
                </div>

                {/* Expanded details */}
                {isOpen && (
                  <div className="rs-fc-expanded">
                    {finding.location && (
                      <p className="rs-fc-loc">📍 <code>{finding.location}</code></p>
                    )}
                    {ai && (
                      <div className="rs-ai-block">
                        <p className="rs-ai-block-title">🤖 {ai.classification?.detected_type || 'AI Analysis'}</p>
                        {ai.risk_assessment?.predicted_impact && (
                          <p><strong>Impact:</strong> {ai.risk_assessment.predicted_impact}</p>
                        )}
                        {ai.remediation?.suggested_action && (
                          <p><strong>Remediation:</strong> {ai.remediation.suggested_action}</p>
                        )}
                        {ai.explanation && <p>{ai.explanation}</p>}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

        </div>
      </div>
    </section>
  );
};

export default Results;
