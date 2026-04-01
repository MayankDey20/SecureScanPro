import { useState, useEffect, useRef, useCallback } from 'react';
import { scanAPI, systemAPI } from '../../services/api';
import { getAccessToken } from '../../contexts/AuthContext';
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
  { value: 'full',            label: 'FULL AUDIT' },
  { value: 'vulnerabilities', label: 'VULN ONLY' },
  { value: 'ssl',             label: 'SSL/TLS' },
  { value: 'headers',         label: 'HEADERS' },
  { value: 'recon',           label: 'RECON' },
  { value: 'custom',          label: 'CUSTOM' },
];

// Phases that are NOT run for a given scan type
const SKIPPED_PHASES = {
  full:            [],
  vulnerabilities: ['Reconnaissance', 'Port Scanning', 'SSL Analysis', 'Header Inspection', 'Deep Vulnerability Scan'],
  ssl:             ['Crawling', 'Reconnaissance', 'Port Scanning', 'Header Inspection', 'Vulnerability Detection', 'Deep Vulnerability Scan'],
  headers:         ['Crawling', 'Reconnaissance', 'Port Scanning', 'SSL Analysis', 'Vulnerability Detection', 'Deep Vulnerability Scan'],
  recon:           ['Crawling', 'Port Scanning', 'SSL Analysis', 'Header Inspection', 'Vulnerability Detection', 'Deep Vulnerability Scan'],
  custom:          [],
};

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
  const [latency, setLatency] = useState(24);
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

  // Real-time server and network metrics
  useEffect(() => {
    const fetchMetrics = async () => {
      const startTime = performance.now();
      try {
        // Fetch real server load from backend
        const metrics = await systemAPI.getMetrics();
        const endTime = performance.now();
        
        // Calculate Latency (RTT)
        setLatency(Math.round(endTime - startTime));

        if (metrics && metrics.server_load !== undefined) {
          setServerLoad(metrics.server_load);
        }
      } catch (err) {
        console.warn('Failed to fetch system metrics:', err);
      }

      // Estimate real user network speed using browser's Network Information API
      if (navigator.connection && navigator.connection.downlink) {
        // downlink returns effective bandwidth estimate in megabits per second
        // We add a tiny bit of random jitter (±0.5 Mbps) to make it feel "live" 
        // since the browser's raw value is often heavily rounded/cached.
        const rawDownlink = navigator.connection.downlink;
        const jitter = (Math.random() - 0.5); 
        setNetworkSpeed(Math.max(1, (rawDownlink + jitter).toFixed(1)));
      } else {
        // Fallback or jitter for default
        const base = 132;
        const jitter = (Math.random() * 4 - 2);
        setNetworkSpeed(Math.round(base + jitter));
      }
    };

    fetchMetrics(); // Initial fetch
    const id = setInterval(fetchMetrics, 5000); // Poll every 5s

    // Optionally listen to connection change events
    const updateNetwork = () => {
      if (navigator.connection && navigator.connection.downlink) {
        setNetworkSpeed(Math.round(navigator.connection.downlink));
      }
    };
    if (navigator.connection) {
      navigator.connection.addEventListener('change', updateNetwork);
    }

    return () => {
      clearInterval(id);
      if (navigator.connection) {
        navigator.connection.removeEventListener('change', updateNetwork);
      }
    };
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
      token = getAccessToken() || '';
    } catch { /* skip */ }

    const url = `${WS_BASE}/scan/${scanId}/live${token ? `?token=${token}` : ''}`;
    let ws;
    try { ws = new WebSocket(url); } catch { startPolling(scanId); return; }

    wsRef.current = ws;
    let wsAlive   = false;
    const fallbackTimer = setTimeout(() => {
      if (!wsAlive) { ws.close(); startPolling(scanId); }
    }, 1500);

    ws.onopen = () => {
      wsAlive = true;
      clearTimeout(fallbackTimer);
      stopPolling(); // WS is live — stop redundant polling
    };

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
    ws.onclose = () => {
      clearTimeout(fallbackTimer);
      wsRef.current = null;
      // If scan hasn't finished yet, fall back to polling
      if (wsAlive) startPolling(scanId);
    };
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
    <main className="pt-16 min-h-screen relative cyber-grid">
      <Toast toast={toast} onDismiss={dismissToast} />
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-20 right-20 w-96 h-96 bg-primary/10 blur-[120px] rounded-full"></div>
        <div className="absolute bottom-40 left-20 w-80 h-80 bg-secondary/5 blur-[100px] rounded-full"></div>
      </div>
      <div className="max-w-6xl mx-auto px-8 py-12 relative z-10">
        <header className="mb-12 text-center">
          <h1 className="text-3xl md:text-4xl font-bold tracking-widest mb-6 bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent inline-block heading-glow" style={{ fontFamily: "'Press Start 2P', monospace", lineHeight: "1.4" }}>
            ADVANCED SECURITY SCANNER
          </h1>
          <div className="flex items-center justify-center gap-4 text-xs font-headline tracking-[0.3em] text-slate-500 uppercase">
            <span className="text-primary">System Integrity: 99.8%</span>
            <span className="w-1 h-1 rounded-full bg-outline-variant"></span>
            <span className="text-secondary">Threat Detection: {activeScan ? 'Active' : 'Standby'}</span>
          </div>
        </header>

        <section className="glass-panel p-8 md:p-12 rounded-xl shadow-2xl relative overflow-hidden transition-all duration-700">
          <div className="mb-10">
            <label className="block font-headline text-[10px] tracking-widest text-slate-400 uppercase mb-3 px-1">Target Endpoint / URL</label>
            <div className="relative flex items-stretch group">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none z-10">
                <span className="material-symbols-outlined text-primary-dim text-lg">language</span>
              </div>
              <input 
                className={`w-full bg-surface-container-lowest border rounded-l-lg py-5 pl-12 pr-4 text-primary focus:ring-1 focus:ring-primary focus:border-primary outline-none transition-all placeholder:text-slate-700 font-mono text-sm overflow-hidden relative ${urlValid === false ? 'border-red-500' : urlValid === true ? 'border-green-500' : 'border-white/10'}`} 
                placeholder="https://api.vortex-security.io/v1/internal" 
                type="text"
                value={formData.targetUrl}
                onChange={e => { setFormData({ ...formData, targetUrl: e.target.value }); setUrlValid(null); }}
              />
              <div className="scan-beam opacity-50"></div>
              <button 
                className="bg-surface-container-lowest px-8 rounded-r-lg border-y border-r border-white/10 text-secondary text-xs font-bold tracking-widest uppercase transition-all flex items-center gap-2 hover:text-white"
                onClick={validateUrl}
              >
                {urlValid === true ? 'VALID ✅' : urlValid === false ? 'INVALID ❌' : 'VALIDATE'} <span className="material-symbols-outlined text-sm">check_circle</span>
              </button>
            </div>
            {urlValid === false && <p className="text-red-500 text-xs mt-2 font-mono">Enter a valid URL or hostname</p>}
          </div>

          <div className="grid lg:grid-cols-3 gap-12 mb-12">
            <div className="lg:col-span-1">
              <label className="block font-headline text-[10px] tracking-widest text-slate-400 uppercase mb-4">Scan Intensity / Depth</label>
              <div className="flex gap-2">
                {SCAN_DEPTH_OPTIONS.map(opt => (
                  <button 
                    key={opt.value}
                    className={`flex-1 py-3 text-[10px] font-bold tracking-widest uppercase rounded transition-all border ${formData.scanDepth === opt.value ? 'bg-secondary text-on-secondary border-secondary shadow-[0_0_15px_rgba(195,244,0,0.3)]' : 'bg-surface-container-lowest border-white/5 text-slate-500 hover:border-white/20'}`}
                    onClick={() => { setFormData({ ...formData, scanDepth: opt.value }); setActiveStep(1); }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="lg:col-span-2">
              <label className="block font-headline text-[10px] tracking-widest text-slate-400 uppercase mb-4">Module Selection</label>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {SCAN_TYPE_OPTIONS.map(opt => {
                  const isActive = formData.scanType === opt.value;
                  const iconMap = {
                    full: 'troubleshoot',
                    vulnerabilities: 'security',
                    ssl: 'encrypted',
                    headers: 'view_list',
                    recon: 'radar',
                    custom: 'tune'
                  };
                  const colorMap = {
                    full: 'text-primary',
                    vulnerabilities: 'text-yellow-400',
                    ssl: 'text-blue-400',
                    headers: 'text-purple-400',
                    recon: 'text-teal-400',
                    custom: 'text-pink-400'
                  };
                  const borderActiveMap = {
                    full: 'border-primary/60 shadow-[0_0_20px_rgba(143,245,255,0.25)]',
                    vulnerabilities: 'border-yellow-400/60 shadow-[0_0_20px_rgba(250,204,21,0.25)]',
                    ssl: 'border-blue-400/60 shadow-[0_0_20px_rgba(96,165,250,0.25)]',
                    headers: 'border-purple-400/60 shadow-[0_0_20px_rgba(192,132,252,0.25)]',
                    recon: 'border-teal-400/60 shadow-[0_0_20px_rgba(45,212,191,0.25)]',
                    custom: 'border-pink-400/60 shadow-[0_0_20px_rgba(244,114,182,0.25)]'
                  };
                  const bgActiveMap = {
                    full: 'bg-primary/5',
                    vulnerabilities: 'bg-yellow-400/5',
                    ssl: 'bg-blue-400/5',
                    headers: 'bg-purple-400/5',
                    recon: 'bg-teal-400/5',
                    custom: 'bg-pink-400/5'
                  };

                  const activeColor = colorMap[opt.value] || 'text-primary';
                  const activeStyle = borderActiveMap[opt.value] || '';
                  const activeBg = bgActiveMap[opt.value] || '';

                  return (
                    <div 
                      key={opt.value}
                      className={`bg-surface-container-lowest border p-4 rounded transition-all cursor-pointer group flex flex-col justify-between ${isActive ? `${activeStyle} ${activeBg}` : 'border-white/5 hover:border-white/20 hover:bg-white/5'}`}
                      onClick={() => { setFormData({ ...formData, scanType: opt.value }); setActiveStep(2); }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className={`material-symbols-outlined text-xl transition-all duration-300 ${activeColor} ${isActive ? 'opacity-100' : 'opacity-40 group-hover:opacity-70'}`}>
                          {iconMap[opt.value] || 'settings_input_component'}
                        </span>
                        {isActive && <div className={`w-1.5 h-1.5 rounded-full animate-pulse ${activeColor.replace('text-', 'bg-')}`}></div>}
                      </div>
                      <div className="mt-1">
                        <div className={`text-[10px] font-bold tracking-widest uppercase transition-colors ${isActive ? activeColor : 'text-slate-400 group-hover:text-slate-200'}`}>
                          {opt.label}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="flex flex-col items-center">
            <button 
              className="relative group cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
              onClick={handleSubmit}
              disabled={loading || activeScan?.status === 'running' || activeScan?.status === 'queued'}
            >
              <div 
                className="absolute -inset-2 rounded-xl blur-xl opacity-30 group-hover:opacity-60 transition duration-500"
                style={{ backgroundColor: '#c3f400', backgroundImage: 'none' }}
              ></div>
              <div 
                className="relative flex items-center justify-center gap-4 px-12 py-6 rounded-xl text-[#002d2d] font-headline font-black text-xl tracking-[0.2em] transition-transform active:scale-95 shadow-[0_0_30px_rgba(195,244,0,0.4)] min-w-[360px]"
                style={{ backgroundColor: '#c3f400', backgroundImage: 'none' }}
              >
                {loading ? 'INITIALIZING...' : activeScan?.status === 'running' || activeScan?.status === 'queued' ? 'SCAN IN PROGRESS' : 'START SECURITY SCAN'}
                <span className="material-symbols-outlined text-3xl font-black">{loading || activeScan?.status === 'running' || activeScan?.status === 'queued' ? 'sync' : 'play_arrow'}</span>
              </div>
            </button>
            <p className="mt-6 text-[10px] text-slate-500 uppercase tracking-widest font-headline">Scanning restricted to authorized domains only</p>
          </div>
        </section>

        {activeScan && (
          <div className="glass-panel p-8 mt-8 rounded-xl shadow-2xl border border-primary/20">
            <div className="flex justify-between items-center mb-6">
              <div>
                <p className="text-secondary font-mono text-sm">{activeScan.target}</p>
                <p className="text-slate-500 text-xs font-mono mt-1">ID: {activeScan.scan_id}</p>
              </div>
              <div className="text-primary font-bold uppercase tracking-widest text-xs">
                {activeScan.status} - {activeScan.phase}
              </div>
            </div>
            
            <div className="h-2 w-full bg-surface-container-low rounded-full overflow-hidden mb-2 border border-white/5">
              <div className="h-full bg-gradient-to-r from-primary to-secondary transition-all duration-500" style={{ width: `${activeScan.progress}%` }}></div>
            </div>
            <div className="text-right text-xs text-primary font-mono">{activeScan.progress}%</div>
          </div>
        )}

        {scanResults && (
          <div className="glass-panel p-8 mt-8 rounded-xl shadow-2xl border border-secondary/20">
             <div className="flex justify-between items-center mb-6">
                <h3 className="text-secondary font-headline font-bold text-xl uppercase tracking-widest">Scan Complete</h3>
                <div className="text-center px-4 py-2 bg-surface-container-low border border-white/10 rounded">
                  <p className="text-xs text-slate-400 uppercase font-headline tracking-wider mb-1">Security Score</p>
                  <p className="text-2xl font-mono text-primary">{scanResults.securityScore ?? '—'}</p>
                </div>
             </div>
             
             {scanResults.findings && scanResults.findings.length > 0 ? (
                <div className="mt-6">
                  <h4 className="text-sm font-headline tracking-widest text-slate-400 mb-4 uppercase">Findings ({scanResults.findings.length})</h4>
                  <div className="space-y-4">
                    {scanResults.findings.map(f => (
                      <div key={f.id} className="bg-surface-container-lowest p-4 rounded border border-white/5 flex flex-col gap-2">
                        <div className="flex justify-between items-center">
                           <span className={`text-[10px] font-bold tracking-widest uppercase px-2 py-1 rounded ${
                             f.severity === 'critical' ? 'bg-red-500/20 text-red-500 border border-red-500/30' :
                             f.severity === 'high' ? 'bg-orange-500/20 text-orange-500 border border-orange-500/30' :
                             f.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-500 border border-yellow-500/30' :
                             f.severity === 'low' ? 'bg-green-500/20 text-green-500 border border-green-500/30' :
                             'bg-blue-500/20 text-blue-500 border border-blue-500/30'
                           }`}>{f.severity}</span>
                           <span className="text-xs text-slate-500 font-mono">{f.type || '—'}</span>
                        </div>
                        <p className="text-sm text-on-surface">{f.title}</p>
                        <p className="text-xs font-mono text-slate-400">{f.location || '—'}</p>
                      </div>
                    ))}
                  </div>
                </div>
             ) : (
                <div className="mt-6 p-6 text-center border border-secondary/20 rounded bg-secondary/5">
                   <p className="text-secondary font-mono">✅ No vulnerabilities detected.</p>
                </div>
             )}
          </div>
        )}

        <section className="globe-container mt-16 glass-panel-heavy border border-white/5">
          <div className="world-map-bg"></div>
          <div className="map-radar-sweep"></div>
          
          {/* Random animated threat nodes */}
          <div className="threat-node" style={{ top: '30%', left: '20%' }}></div>
          <div className="threat-node" style={{ top: '45%', left: '48%', animationDelay: '0.7s' }}></div>
          <div className="threat-node" style={{ top: '25%', left: '75%', animationDelay: '1.2s' }}></div>
          <div className="threat-node" style={{ top: '60%', left: '35%', animationDelay: '0.4s' }}></div>
          <div className="threat-node" style={{ top: '55%', left: '85%', animationDelay: '1.8s' }}></div>

          <div className="absolute bottom-6 left-6 z-20">
            <div className="threat-monitor-label">
              <div className="status-dot"></div>
              <span>GLOBAL THREAT MONITOR: NOMINAL</span>
            </div>
          </div>

          <div className="absolute top-6 right-6 font-mono text-[10px] text-primary/40 tracking-[0.2em] z-20">
            REALTIME_NETWORK_TOPOLOGY_SCAN
          </div>
        </section>

        <footer className="mt-12 grid md:grid-cols-3 gap-8 relative z-10">
          <div className="glass-panel p-6 rounded-lg flex items-center gap-6 border border-white/5">
            <div className="relative w-20 h-20 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90 text-surface-container-low">
                <circle cx="40" cy="40" fill="none" r="36" stroke="currentColor" strokeWidth="4"></circle>
                <circle className="text-primary transition-all duration-1000" cx="40" cy="40" fill="none" r="36" stroke="currentColor" strokeDasharray="226" strokeDashoffset={226 - (226 * serverLoad / 100)} strokeWidth="4"></circle>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-lg font-bold font-headline">{serverLoad}%</span>
              </div>
            </div>
            <div>
              <div className="text-[10px] font-headline tracking-widest text-slate-400 uppercase mb-1">Server Load</div>
              <div className="text-sm font-mono text-primary flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-primary animate-ping"></span>
                {serverLoad > 80 ? 'Heavy Load' : serverLoad > 50 ? 'Moderate' : 'Optimized'}
              </div>
            </div>
          </div>

          <div className="glass-panel p-6 rounded-lg border border-white/5">
            <div className="flex items-center justify-between mb-4">
              <div className="text-[10px] font-headline tracking-widest text-slate-400 uppercase">Network Speed</div>
              <div className="text-sm font-mono text-secondary transition-all">{networkSpeed} Mbps</div>
            </div>
            <div className="h-10 w-full overflow-hidden">
              <svg className="w-full h-full text-secondary opacity-50" preserveAspectRatio="none" viewBox="0 0 200 40">
                <path d={`M0 20 Q 25 ${40 - networkSpeed/15}, 50 20 T 100 20 T 150 20 T 200 20 T 250 20 T 300 20`} fill="none" stroke="currentColor" strokeWidth="2">
                  <animateTransform attributeName="transform" type="translate" from="0 0" to="-100 0" dur="2s" repeatCount="indefinite" />
                </path>
                <path d={`M0 25 Q 25 ${45 - networkSpeed/10}, 50 25 T 100 25 T 150 25 T 200 25 T 250 25 T 300 25`} fill="none" opacity="0.3" stroke="currentColor" strokeWidth="1">
                  <animateTransform attributeName="transform" type="translate" from="0 0" to="-100 0" dur="3s" repeatCount="indefinite" />
                </path>
              </svg>
            </div>
          </div>

          <div className="glass-panel p-6 rounded-lg flex items-center gap-6 border border-white/5">
            <div className="w-12 h-12 rounded border border-white/5 bg-white/5 flex items-center justify-center">
              <span className="material-symbols-outlined text-primary-dim text-2xl animate-pulse">hourglass_top</span>
            </div>
            <div>
              <div className="text-[10px] font-headline tracking-widest text-slate-400 uppercase mb-1">Elapsed Time</div>
              <div className="text-xl font-mono text-on-surface tracking-widest">{fmtTimer(scanTimer)}</div>
            </div>
          </div>
        </footer>

        <div className="mt-12 flex justify-between items-center px-4 opacity-30 border-t border-white/5 pt-8">
          <div className="font-mono text-[8px] text-slate-500 uppercase flex gap-8">
            <span className="flex items-center gap-1">
              <span className="w-1 h-1 rounded-full bg-green-500"></span>
              LATENCY: {latency}ms
            </span>
            <span>RX: 0.08ms</span>
            <span>PKT_LOSS: 0.000%</span>
          </div>
          <div className="flex gap-4">
            <div className="w-12 h-[1px] bg-primary/40"></div>
            <div className="w-2 h-2 rotate-45 border border-primary/40"></div>
            <div className="w-12 h-[1px] bg-primary/40"></div>
          </div>
          <div className="font-mono text-[8px] text-slate-500">
            UUID: 8F55-12E1-SENTINEL-X9
          </div>
        </div>
      </div>
    </main>
  );
};

export default Scanner;
