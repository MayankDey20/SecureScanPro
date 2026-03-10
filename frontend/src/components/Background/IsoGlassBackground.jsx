import './IsoGlassBackground.css';

/* LED blink rows per rack unit */
const LED_ROWS = [
  { color: '#22c55e', count: 4 },
  { color: '#38bdf8', count: 6 },
  { color: '#22c55e', count: 4 },
  { color: '#f59e0b', count: 3 },
  { color: '#22c55e', count: 5 },
  { color: '#38bdf8', count: 4 },
  { color: '#22c55e', count: 6 },
  { color: '#ef4444', count: 2 },
  { color: '#22c55e', count: 4 },
  { color: '#38bdf8', count: 5 },
];

function RackUnit({ unit, index }) {
  const leds = LED_ROWS[index % LED_ROWS.length];
  return (
    <div className="db-rack-unit" style={{ '--unit-accent': leds.color }}>
      <div className="db-ru-bezel">
        <div className="db-ru-label">RU{String(index + 1).padStart(2,'0')}</div>
        <div className="db-ru-body">
          {unit === 'disk' && (
            <>
              <div className="db-disk-stack">
                {[0,1,2].map(d => <div key={d} className="db-disk" style={{ '--di': d }} />)}
              </div>
              <div className="db-disk-stack">
                {[0,1,2].map(d => <div key={d} className="db-disk" style={{ '--di': d }} />)}
              </div>
              <div className="db-disk-stack">
                {[0,1,2].map(d => <div key={d} className="db-disk" style={{ '--di': d }} />)}
              </div>
            </>
          )}
          {unit === 'blade' && (
            <div className="db-blade-row">
              {[0,1,2,3,4,5,6,7].map(b => <div key={b} className="db-blade" style={{ '--bi': b }} />)}
            </div>
          )}
          {unit === 'switch' && (
            <div className="db-switch-row">
              <div className="db-switch-ports">
                {Array.from({ length: 16 }).map((_,p) => (
                  <div key={p} className="db-port" style={{ '--pi': p }} />
                ))}
              </div>
              <div className="db-cable-trace" />
            </div>
          )}
          {unit === 'psu' && (
            <div className="db-psu-row">
              <div className="db-psu" />
              <div className="db-psu" />
              <div className="db-fan-grid">
                {[0,1,2,3,4,5].map(f => <div key={f} className="db-fan" />)}
              </div>
            </div>
          )}
        </div>
        <div className="db-ru-leds">
          {Array.from({ length: leds.count }).map((_,i) => (
            <div key={i} className="db-led" style={{ '--li': i, '--lc': leds.color }} />
          ))}
        </div>
      </div>
    </div>
  );
}

const RACK_UNITS = [
  'psu','disk','disk','blade','switch','disk','disk','blade','switch','psu',
];

export default function IsoGlassBackground() {
  return (
    <div className="iso-bg" aria-hidden="true">

      {/* ── Scene base gradient ── */}
      <div className="iso-scene-base" />

      {/* ── Floor reflection plane ── */}
      <div className="iso-floor" />

      {/* ══════════════════════════════
          SERVER RACK — CENTRE
      ══════════════════════════════ */}
      <div className="db-rack-wrap">
        {/* Back wall of rack */}
        <div className="db-rack-back" />

        {/* Left side panel — glass */}
        <div className="db-rack-glass db-rack-glass-l">
          <div className="db-glass-inner">
            <div className="db-glass-grid" />
            <div className="db-glass-binary">
              {['01001101','10110010','01101001','11010110',
                '10110100','01101101','11001011','00110101'].map((b,i) => (
                <span key={i} className="db-bin-line" style={{ '--bi': i }}>{b}</span>
              ))}
            </div>
            <div className="db-glass-edge-top" />
            <div className="db-glass-edge-bottom" />
          </div>
        </div>

        {/* Right side panel — glass */}
        <div className="db-rack-glass db-rack-glass-r">
          <div className="db-glass-inner">
            <div className="db-glass-grid" />
            <div className="db-glass-binary db-glass-binary-r">
              {['11010011','00110101','10100110','01011010',
                '10011101','01110010','11100101','00101011'].map((b,i) => (
                <span key={i} className="db-bin-line" style={{ '--bi': i }}>{b}</span>
              ))}
            </div>
            <div className="db-glass-edge-top" />
            <div className="db-glass-edge-bottom" />
          </div>
        </div>

        {/* Top glass lid */}
        <div className="db-rack-glass db-rack-glass-top">
          <div className="db-glass-inner">
            <div className="db-glass-grid" />
          </div>
        </div>

        {/* Rack units */}
        <div className="db-rack-body">
          <div className="db-rack-rail db-rail-l" />
          <div className="db-rack-rail db-rail-r" />
          <div className="db-rack-units">
            {RACK_UNITS.map((u, i) => <RackUnit key={i} unit={u} index={i} />)}
          </div>
        </div>

        {/* Floor shadow / base */}
        <div className="db-rack-base">
          <div className="db-base-leg db-base-leg-fl" />
          <div className="db-base-leg db-base-leg-fr" />
          <div className="db-base-leg db-base-leg-bl" />
          <div className="db-base-leg db-base-leg-br" />
        </div>

        {/* Cable management tray — bottom */}
        <div className="db-cable-tray">
          {[0,1,2,3,4,5,6,7].map(c => (
            <div key={c} className="db-cable" style={{ '--ci': c }} />
          ))}
        </div>
      </div>

      {/* ══════════════════════════════
          SECONDARY RACK — LEFT (partial)
      ══════════════════════════════ */}
      <div className="db-rack-wrap db-rack-secondary db-rack-left">
        <div className="db-rack-back" />
        <div className="db-rack-glass db-rack-glass-l"><div className="db-glass-inner"><div className="db-glass-grid" /></div></div>
        <div className="db-rack-glass db-rack-glass-r"><div className="db-glass-inner"><div className="db-glass-grid" /></div></div>
        <div className="db-rack-body">
          <div className="db-rack-rail db-rail-l" />
          <div className="db-rack-rail db-rail-r" />
          <div className="db-rack-units">
            {['disk','switch','disk','blade','psu'].map((u, i) => <RackUnit key={i} unit={u} index={i+2} />)}
          </div>
        </div>
      </div>

      {/* ══════════════════════════════
          SECONDARY RACK — RIGHT (partial)
      ══════════════════════════════ */}
      <div className="db-rack-wrap db-rack-secondary db-rack-right">
        <div className="db-rack-back" />
        <div className="db-rack-glass db-rack-glass-l"><div className="db-glass-inner"><div className="db-glass-grid" /></div></div>
        <div className="db-rack-glass db-rack-glass-r"><div className="db-glass-inner"><div className="db-glass-grid" /></div></div>
        <div className="db-rack-body">
          <div className="db-rack-rail db-rail-l" />
          <div className="db-rack-rail db-rail-r" />
          <div className="db-rack-units">
            {['blade','disk','switch','psu','disk'].map((u, i) => <RackUnit key={i} unit={u} index={i+5} />)}
          </div>
        </div>
      </div>

      {/* ══════════════════════════════
          AMBIENT / GLOW LAYERS
      ══════════════════════════════ */}
      <div className="iso-glow iso-glow-cyan" />
      <div className="iso-glow iso-glow-blue" />
      <div className="iso-glow iso-glow-green" />

      {/* Depth-of-field vignette */}
      <div className="iso-dof-overlay" />

      {/* Scan line overlay */}
      <div className="iso-scanlines" />
    </div>
  );
}
