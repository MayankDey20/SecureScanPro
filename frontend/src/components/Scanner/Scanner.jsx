import { useState, useEffect, useRef, useCallback } from 'react';
import { scanAPI } from '../../services/api';
import { supabase } from '../../lib/supabase';
import { useAuth } from '../../contexts/AuthContext';
import './Scanner.css';

// Build a WebSocket URL from the current API base
const WS_BASE = (() => {
  const api = import.meta.env.VITE_API_URL || '/api/v1';
  if (api.startsWith('http')) {
    return api.replace(/^http/, 'ws');
  }
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}${api}`;
})();

const PHASES = [
  'Initializing',
  'Crawling',
  'Reconnaissance',
  'Port Scanning',
  'SSL Analysis',
  'Header Inspection',
  'Vulnerability Detection',
  'Deep Vulnerability Scan',
  'Finalizing Report',
];

const STEPPER_STEPS = [
  { icon: '⊙', label: 'Target' },
  { icon: '⊙', label: 'Depth' },
  { icon: '≡', label: 'Type' },
  { icon: '🚀', label: 'Launch' },
];

const SCAN_DEPTH_OPTIONS = [
  { value: 'shallow', label: 'Shallow', desc: 'Quick surface-level scan' },
  { value: 'medium',  label: 'Medium',  desc: 'Standard balanced scan — recommended' },
  { value: 'deep',    label: 'Deep',    desc: 'Comprehensive deep analysis' },
];

const SCAN_TYPE_OPTIONS = [
  { value: 'full',            label: 'Full Security Audit' },
  { value: 'vulnerabilities', label: 'Vulnerability Only' },
  { value: 'ssl',             label: 'SSL/TLS Check' },
  { value: 'headers',         label: 'Headers Only' },
  { value: 'recon',           label: 'Recon Only' },
];

const Toast = ({ toast, onDismiss }) => {
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(onDismiss, 5000);
    return () => clearTimeout(t);
  }, [toast, onDismiss]);

  if (!toast) return null;
  return (
    <div className={`scanner-toast scanner-toast--${toast.type}`}>
      <span className="scanner-toast__icon">
        {toast.type === 'success' ? '✓' : toast.type === 'error' ? '✕' : 'ℹ'}
      </span>
      <span className="scanner-toast__msg">{toast.message}</span>
      <button className="scanner-toast__close" onClick={onDismiss}>×</button>
    </div>
  );
};

const Scanner = () => {
  const { user } = useAuth();
  const [activeStep, setActiveStep] = useState(0);
  const [formData, setFormData] = useState({
    targetUrl: '',
    scanType: 'full',
    scanDepth: 'medium',
  });
  const [urlValid, setUrlValid]       = useState(null);   // null | true | false
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [activeScan, setActiveScan] = useState(null);
  const [scanResults, setScanResults] = useState(null);

  // Live system status metrics (simulated fluctuation)
  const [serverLoad, setServerLoad] = useState(35);
  const [networkSpeed, setNetworkSpeed] = useState(132);
  const [scanTimer, setScanTimer] = useState(0);

  const pollRef  = useRef(null);
  const wsRef    = useRef(null);
  const timerRef = useRef(null);

  const showToast    = (message, type = 'info') => setToast({ message, type });
  const dismissToast = useCallback(() => setToast(null), []);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  // Scan timer
  useEffect(() => {
    if (activeScan?.status === 'running' || activeScan?.status === 'queued') {
      timerRef.current = setInterval(() => setScanTimer(t => t + 1), 1000);
    } else {
      if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
      if (!activeScan) setScanTimer(0);
    }
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [activeScan?.status]);

  // Simulated server / network fluctuation
  useEffect(() => {
    const id = setInterval(() => {
      setServerLoad(v => Math.max(10, Math.min(95, v + ((Math.random() * 6 - 3) | 0))));
      setNetworkSpeed(v => Math.max(80, Math.min(250, v + ((Math.random() * 10 - 5) | 0))));
    }, 2500);
    return () => clearInterval(id);
  }, []);

  const fmtTimer = (s) => {
    const h   = (s / 3600 | 0).toString().padStart(2, '0');
    const m   = ((s % 3600) / 60 | 0).toString().padStart(2, '0');
    const sec = (s % 60).toString().padStart(2, '0');
    return `${h}:${m}:${sec}`;
  };

  const validateUrl = () => {
    try { new URL(formData.targetUrl); setUrlValid(true); }
    catch { setUrlValid(false); }
  };

  const fetchResults = useCallback(async (scanId) => {
    try {
      const data = await scanAPI.getResults(scanId);
      setScanResults(data);
    } catch { /* not ready yet */ }
  }, []);

  const startPolling = useCallback((scanId) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const status = await scanAPI.getStatus(scanId);
        const phaseIndex = Math.min(
          Math.floor((status.progress / 100) * PHASES.length),
          PHASES.length - 1
        );
        setActiveScan(prev => ({
          ...prev,
          status: status.status,
          progress: status.progress ?? prev?.progress ?? 0,
          phase: status.currentPhase || PHASES[phaseIndex],
        }));
        if (status.status === 'completed' || status.status === 'failed') {
          stopPolling();
          if (status.status === 'completed') {
            showToast('Scan completed successfully!', 'success');
            await fetchResults(scanId);
          } else {
            showToast('Scan failed. Check logs for details.', 'error');
          }
        }
      } catch { stopPolling(); }
    }, 3000);
  }, [stopPolling, fetchResults]);

  const startWebSocket = useCallback(async (scanId) => {
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }

    let token = '';
    try {
      const { data: { session } } = await supabase.auth.getSession();
      token = session?.access_token || '';
    } catch { /* skip */ }

    const url = `${WS_BASE}/scan/${scanId}/live${token ? `?token=${token}` : ''}`;
    let ws;
    try { ws = new WebSocket(url); } catch { startPolling(scanId); return; }

    wsRef.current = ws;
    let wsAlive   = false;
    const fallbackTimer = setTimeout(() => {
      if (!wsAlive) { ws.close(); startPolling(scanId); }
    }, 3000);

    ws.onopen = () => { wsAlive = true; clearTimeout(fallbackTimer); };

    ws.onmessage = async (event) => {
      try {
        const msg = JSON.parse(event.data);
        // Ignore pure control frames
        if (msg.type === 'keepalive' || msg.type === 'pong') return;

        // Accept both camelCase (legacy) and snake_case (new DB-poll shape)
        const progress  = msg.progress ?? 0;
        const status    = msg.status || msg.status;
        const phase     = msg.current_phase || msg.currentPhase || '';
        const phaseIndex = Math.min(
          Math.floor((progress / 100) * PHASES.length),
          PHASES.length - 1
        );

        if (status) {
          setActiveScan(prev => ({
            ...prev,
            status,
            progress,
            phase: phase || PHASES[phaseIndex],
          }));
        }
      } catch { /* malformed frame */ }
    };

    ws.onerror = () => { clearTimeout(fallbackTimer); if (!wsAlive) startPolling(scanId); };
    ws.onclose = () => { clearTimeout(fallbackTimer); wsRef.current = null; };
  }, [fetchResults, startPolling]);

  useEffect(() => () => {
    stopPolling();
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
  }, [stopPolling]);

  const handleSubmit = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    setLoading(true);
    setScanResults(null);
    setActiveScan(null);
    setScanTimer(0);

    try {
      const result = await scanAPI.start({
        target: formData.targetUrl,
        scan_type: [formData.scanType],
        scan_options: { scan_depth: formData.scanDepth },
        auth_config: null,
      });

      const newScan = {
        scan_id: result.scan_id,
        target: formData.targetUrl,
        status: 'queued',
        progress: 0,
        phase: PHASES[0],
      };
      setActiveScan(newScan);
      setActiveStep(3);
      showToast(`Scan queued for ${formData.targetUrl}`, 'success');
      // Always start polling — it reads DB state directly and is reliable
      startPolling(result.scan_id);
      // Also try WebSocket for lower-latency updates (falls back gracefully)
      startWebSocket(result.scan_id);
    } catch (error) {
      const detail = error.response?.data?.detail;
      let msg = 'Failed to start scan. Please try again.';
      if (typeof detail === 'string') {
        msg = detail;
      } else if (Array.isArray(detail) && detail.length > 0) {
        // FastAPI 422 returns an array of validation error objects
        msg = detail.map(e => e.msg || JSON.stringify(e)).join(' | ');
      } else if (detail && typeof detail === 'object') {
        msg = detail.msg || JSON.stringify(detail);
      }
      showToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  };

  const vulnCounts = scanResults?.vulnerabilities || {};
  const findings   = scanResults?.findings || [];
  const severityColor = {
    critical: '#ef4444', high: '#f59e0b',
    medium: '#3b82f6', low: '#10b981', info: '#6b7280'
  };

  const depthDesc  = SCAN_DEPTH_OPTIONS.find(d => d.value === formData.scanDepth)?.desc ?? '';
  const typeLabel  = SCAN_TYPE_OPTIONS.find(t => t.value === formData.scanType)?.label ?? '';

  return (
    <section className="sc-section">
      <Toast toast={toast} onDismiss={dismissToast} />

      <h1 className="sc-title">Advanced Security Scanner</h1>
      <p className="sc-subtitle">Configure and launch comprehensive security assessments</p>

      {/* ── Main configuration card ── */}
      <div className="sc-main-card">

        {/* Stepper */}
        <div className="sc-stepper">
          {STEPPER_STEPS.map((step, i) => (
            <div key={step.label} className="sc-step-group">
              <button
                type="button"
                className={`sc-step ${i === activeStep ? 'active' : i < activeStep ? 'done' : ''}`}
                onClick={() => setActiveStep(i)}
              >
                <span className="sc-step-icon">{step.icon}</span>
                <span className="sc-step-label">{step.label}</span>
              </button>
              {i < STEPPER_STEPS.length - 1 && <span className="sc-step-arrow">›</span>}
            </div>
          ))}
        </div>

        {/* Body — 2-column */}
        <div className="sc-body">

          {/* ── LEFT column ── */}
          <div className="sc-left">

            {/* Target URL */}
            <div className="sc-field-group">
              <label className="sc-label">Target URL</label>
              <div className="sc-input-wrap">
                <input
                  className={`sc-input${urlValid === false ? ' sc-input--err' : urlValid === true ? ' sc-input--ok' : ''}`}
                  type="text"
                  value={formData.targetUrl}
                  onChange={e => { setFormData({ ...formData, targetUrl: e.target.value }); setUrlValid(null); }}
                  onFocus={() => setActiveStep(0)}
                  placeholder="https://example.com"
                />
                <button type="button" className="sc-validate-btn" onClick={validateUrl}>
                  {urlValid === true ? '✓ Valid' : urlValid === false ? '✗ Invalid' : 'Validate'}
                </button>
              </div>
              {urlValid === false && <p className="sc-field-err">Enter a valid URL including https://</p>}
            </div>

            {/* Scan Depth */}
            <div className="sc-field-group">
              <label className="sc-label">Scan Depth</label>
              <div className="sc-option-row">
                {SCAN_DEPTH_OPTIONS.map(opt => (
                  <button
                    key={opt.value}
                    type="button"
                    className={`sc-option-pill${formData.scanDepth === opt.value ? ' active' : ''}`}
                    onClick={() => { setFormData({ ...formData, scanDepth: opt.value }); setActiveStep(1); }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <p className="sc-field-hint">{depthDesc}</p>
            </div>

          </div>

          {/* ── RIGHT column ── */}
          <div className="sc-right">

            {/* Scan Type */}
            <div className="sc-field-group">
              <label className="sc-label">Scan Type</label>
              <div className="sc-type-grid">
                {SCAN_TYPE_OPTIONS.map(opt => (
                  <button
                    key={opt.value}
                    type="button"
                    className={`sc-type-btn${formData.scanType === opt.value ? ' active' : ''}`}
                    onClick={() => { setFormData({ ...formData, scanType: opt.value }); setActiveStep(2); }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <p className="sc-field-hint">Selected: {typeLabel}</p>
            </div>

            {/* Launch CTA */}
            <button
              type="button"
              className="sc-launch-btn"
              onClick={handleSubmit}
              disabled={loading || activeScan?.status === 'running'}
            >
              {loading ? (
                <><span className="sc-spinner" /> Queuing Scan…</>
              ) : activeScan?.status === 'running' ? (
                <><span className="sc-spinner" /> Scan In Progress…</>
              ) : (
                <>&nbsp; Start Security Scan &nbsp;</>
              )}
            </button>

            {/* System Status */}
            <div className="sc-status-panel">
              <p className="sc-status-title">System Status</p>
              <div className="sc-status-metrics">
                <div className="sc-status-metric">
                  <span className="sc-status-val sc-sv-load">{serverLoad}%</span>
                  <span className="sc-status-lbl">Server Load</span>
                  <div className="sc-mini-bar">
                    <div
                      className="sc-mini-bar-fill"
                      style={{ width: `${serverLoad}%`, background: serverLoad > 75 ? '#ef4444' : serverLoad > 50 ? '#f59e0b' : '#3b82f6' }}
                    />
                  </div>
                </div>
                <div className="sc-status-sep" />
                <div className="sc-status-metric">
                  <span className="sc-status-val sc-sv-net">{networkSpeed} <small>Mbps</small></span>
                  <span className="sc-status-lbl">Network Speed</span>
                </div>
                <div className="sc-status-sep" />
                <div className="sc-status-metric">
                  <span className="sc-status-val sc-sv-time">{fmtTimer(scanTimer)}</span>
                  <span className="sc-status-lbl">Scan Time</span>
                </div>
              </div>
            </div>

          </div>
        </div>
      </div>

      {/* ── Live progress panel ── */}
      {activeScan && (
        <div className="sc-progress-card">
          <div className="sc-progress-header">
            <div>
              <p className="sc-progress-target">{activeScan.target}</p>
              <p className="sc-progress-id">ID: <code>{activeScan.scan_id}</code></p>
            </div>
            <span className={`status-pill status-pill--${activeScan.status}`}>
              {activeScan.status}
            </span>
          </div>

          <div className="sc-bar-wrap">
            <div className="sc-bar-fill" style={{ width: `${activeScan.progress}%` }} />
          </div>
          <div className="sc-progress-meta">
            <span className="sc-progress-phase">⚡ {activeScan.phase}</span>
            <span className="sc-progress-pct">{activeScan.progress}%</span>
          </div>

          <div className="sc-phase-stepper">
            {PHASES.map((p, i) => {
              const currentIdx = PHASES.indexOf(activeScan.phase);
              const done   = i < currentIdx;
              const active = i === currentIdx;
              return (
                <div key={p} className={`sc-phase-step${done ? ' done' : active ? ' active' : ''}`}>
                  <div className="sc-phase-dot">{done ? '✓' : i + 1}</div>
                  <span className="sc-phase-label">{p}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Results panel ── */}
      {scanResults && (
        <div className="sc-results-card">
          <div className="sc-results-header">
            <h3>Scan Results</h3>
            <div className="sc-score-badge">
              <span className="sc-score-val">{scanResults.securityScore ?? '—'}</span>
              <span className="sc-score-lbl">Security Score</span>
            </div>
          </div>

          <div className="sc-sev-grid">
            {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
              <div key={sev} className="sc-sev-tile" style={{ borderColor: severityColor[sev] }}>
                <span className="sc-sev-count">{vulnCounts[sev] ?? 0}</span>
                <span className="sc-sev-label">{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
              </div>
            ))}
          </div>

          {findings.length > 0 ? (
            <div className="sc-findings-wrap">
              <h4>Findings ({findings.length})</h4>
              <table className="sc-findings-tbl">
                <thead>
                  <tr>
                    <th>Severity</th><th>Title</th><th>Type</th><th>Location</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map(f => (
                    <tr key={f.id}>
                      <td>
                        <span className="sc-sev-badge" style={{ background: severityColor[f.severity] }}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="sc-finding-title">{f.title}</td>
                      <td className="sc-finding-type">{f.type || '—'}</td>
                      <td><code className="sc-finding-loc">{f.location || '—'}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="sc-no-findings">✅ No vulnerabilities detected.</p>
          )}
        </div>
      )}
    </section>
  );
};

export default Scanner;
