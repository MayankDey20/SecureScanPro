import re

with open('frontend/src/components/Scanner/Scanner.jsx', 'r') as f:
    content = f.read()

# Find the start of the return statement
match = re.search(r'(\s*return\s*\(\s*<section className="sc-section">)', content)
if not match:
    print("Could not find return statement")
    exit(1)

start_idx = match.start(1)

new_return = """
  return (
    <main className="pt-16 min-h-screen relative cyber-grid">
      <Toast toast={toast} onDismiss={dismissToast} />
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-20 right-20 w-96 h-96 bg-primary/10 blur-[120px] rounded-full"></div>
        <div class="absolute bottom-40 left-20 w-80 h-80 bg-secondary/5 blur-[100px] rounded-full"></div>
      </div>
      <div className="max-w-6xl mx-auto px-8 py-12 relative z-10">
        <header className="mb-12 text-center">
          <h1 className="font-headline text-5xl md:text-7xl font-bold tracking-tighter mb-4 bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent inline-block">
            ADVANCED SECURITY SCANNER
          </h1>
          <div className="flex items-center justify-center gap-4 text-xs font-headline tracking-[0.3em] text-slate-500 uppercase">
            <span className="text-primary">System Integrity: 99.8%</span>
            <span className="w-1 h-1 rounded-full bg-outline-variant"></span>
            <span className="text-secondary">Threat Detection: {activeScan ? 'Active' : 'Standby'}</span>
            <span className="w-1 h-1 rounded-full bg-outline-variant"></span>
            <span>Core Version 4.0.2-BETA</span>
          </div>
        </header>

        <section className="glass-panel p-8 md:p-12 rounded-xl shadow-2xl">
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
                className="bg-surface-container-high hover:bg-surface-bright px-8 rounded-r-lg border-y border-r border-white/10 text-secondary text-xs font-bold tracking-widest uppercase transition-all flex items-center gap-2 group-hover:shadow-[0_0_15px_rgba(195,244,0,0.15)]"
                onClick={validateUrl}
              >
                {urlValid === true ? 'Valid ✅' : urlValid === false ? 'Invalid ❌' : 'Validate'} <span className="material-symbols-outlined text-sm">task_alt</span>
              </button>
            </div>
          </div>

          <div className="grid lg:grid-cols-3 gap-12 mb-12">
            <div className="lg:col-span-1">
              <label className="block font-headline text-[10px] tracking-widest text-slate-400 uppercase mb-4">Scan Intensity / Depth</label>
              <div className="flex bg-surface-container-lowest p-1 rounded-lg border border-white/5">
                {SCAN_DEPTH_OPTIONS.map(opt => (
                  <button 
                    key={opt.value}
                    className={`flex-1 py-3 text-[10px] font-bold tracking-widest uppercase rounded transition-colors ${formData.scanDepth === opt.value ? 'bg-secondary text-on-secondary shadow-lg shadow-secondary/10' : 'text-slate-500 hover:text-slate-300'}`}
                    onClick={() => { setFormData({ ...formData, scanDepth: opt.value }); setActiveStep(1); }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <p className="mt-2 text-xs text-slate-500">{depthDesc}</p>
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
                    recon: 'radar'
                  };
                  return (
                    <div 
                      key={opt.value}
                      className={`bg-surface-container-lowest border p-4 rounded transition-all cursor-pointer group ${isActive ? 'border-primary bg-white/5' : 'border-white/5 hover:border-primary/40 hover:bg-white/5'}`}
                      onClick={() => { setFormData({ ...formData, scanType: opt.value }); setActiveStep(2); }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className={`material-symbols-outlined text-xl ${isActive ? 'text-primary' : 'text-slate-400'}`}>
                          {iconMap[opt.value] || 'settings_input_component'}
                        </span>
                        {isActive && <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>}
                      </div>
                      <div className={`text-[10px] font-bold tracking-tighter uppercase ${isActive ? 'text-primary' : 'text-on-surface'}`}>
                        {opt.label}
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
              <div className="absolute -inset-1 bg-gradient-to-r from-primary to-secondary rounded-full blur opacity-25 group-hover:opacity-75 transition duration-1000 group-hover:duration-200"></div>
              <div className="relative flex items-center gap-4 bg-gradient-to-r from-primary to-secondary px-12 py-6 rounded-full text-on-primary-fixed font-headline font-black text-xl tracking-[0.2em] transition-transform active:scale-95">
                {loading ? 'INITIALIZING...' : activeScan?.status === 'running' || activeScan?.status === 'queued' ? 'SCAN IN PROGRESS' : 'START SECURITY SCAN'}
                <span className="material-symbols-outlined text-3xl">{loading || activeScan?.status === 'running' || activeScan?.status === 'queued' ? 'sync' : 'play_arrow'}</span>
              </div>
            </button>
            <p className="mt-6 text-[10px] text-slate-500 uppercase tracking-widest font-headline">Scanning restricted to authorized domains only</p>
          </div>
        </section>

        {activeScan && (
          <div className="glass-panel p-8 mt-8 rounded-xl shadow-2xl">
            <div className="flex justify-between items-center mb-6">
              <div>
                <p className="text-secondary font-mono text-sm">{activeScan.target}</p>
                <p className="text-slate-500 text-xs font-mono mt-1">ID: {activeScan.scan_id}</p>
              </div>
              <div className="text-primary font-bold uppercase tracking-widest text-xs">
                {activeScan.status} - {activeScan.phase}
              </div>
            </div>
            
            <div className="h-2 w-full bg-surface-container-low rounded-full overflow-hidden mb-2">
              <div className="h-full bg-gradient-to-r from-primary to-secondary transition-all duration-500" style={{ width: `${activeScan.progress}%` }}></div>
            </div>
            <div className="text-right text-xs text-primary font-mono">{activeScan.progress}%</div>
          </div>
        )}

        <footer className="mt-12 grid md:grid-cols-3 gap-8">
          <div className="glass-panel p-6 rounded-lg flex items-center gap-6">
            <div className="relative w-20 h-20 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90">
                <circle cx="40" cy="40" fill="none" r="36" stroke="rgba(255,255,255,0.05)" strokeWidth="4"></circle>
                <circle className="text-primary" cx="40" cy="40" fill="none" r="36" stroke="currentColor" strokeDasharray="226" strokeDashoffset={226 - (226 * serverLoad / 100)} strokeWidth="4"></circle>
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

          <div className="glass-panel p-6 rounded-lg">
            <div className="flex items-center justify-between mb-4">
              <div className="text-[10px] font-headline tracking-widest text-slate-400 uppercase">Network Speed</div>
              <div className="text-sm font-mono text-secondary">{networkSpeed} Mbps</div>
            </div>
            <div className="h-10 w-full overflow-hidden">
              <svg className="w-full h-full text-secondary opacity-50" preserveAspectRatio="none" viewBox="0 0 200 40">
                <path d={`M0 20 Q 25 ${40 - networkSpeed/15}, 50 20 T 100 20 T 150 20 T 200 20`} fill="none" stroke="currentColor" strokeWidth="2"></path>
                <path d={`M0 25 Q 25 ${45 - networkSpeed/10}, 50 25 T 100 25 T 150 25 T 200 25`} fill="none" opacity="0.3" stroke="currentColor" strokeWidth="1"></path>
              </svg>
            </div>
          </div>

          <div className="glass-panel p-6 rounded-lg flex items-center gap-6">
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
            <span>TX: 0.12ms</span>
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
"""

with open('frontend/src/components/Scanner/Scanner.jsx', 'w') as f:
    f.write(content[:start_idx] + new_return)

print("Updated Scanner.jsx")
