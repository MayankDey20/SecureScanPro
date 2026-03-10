import { useEffect, useRef } from 'react';

const HEX_SIZE  = 38;   // radius of each hex tile
const GAP       = 3;    // gap between hexes
const STEP_X    = HEX_SIZE * Math.sqrt(3) + GAP;
const STEP_Y    = HEX_SIZE * 1.5 + GAP;

// Color palette — deep-space with electric-cyan / indigo / violet accents
const PALETTE = [
  'rgba(0,212,255,0.18)',   // electric cyan
  'rgba(99,102,241,0.20)',  // indigo
  'rgba(139,92,246,0.16)',  // violet
  'rgba(0,188,212,0.12)',   // teal
  'rgba(6,14,36,0.85)',     // near-black filler
  'rgba(6,14,36,0.85)',     // near-black filler (weighted more)
  'rgba(6,14,36,0.85)',     // near-black filler (weighted more)
];

function hexPath(cx, cy, r, ctx) {
  ctx.beginPath();
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 180) * (60 * i - 30);
    const x = cx + r * Math.cos(angle);
    const y = cy + r * Math.sin(angle);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  }
  ctx.closePath();
}

export default function HexBackground() {
  const canvasRef = useRef(null);
  const frameRef  = useRef(null);
  const hexesRef  = useRef([]);
  const timeRef   = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx    = canvas.getContext('2d');

    function buildHexes() {
      const W = canvas.width;
      const H = canvas.height;
      const hexes = [];
      let col = 0;
      for (let x = -HEX_SIZE; x < W + HEX_SIZE * 2; x += STEP_X, col++) {
        let row = 0;
        const offsetY = col % 2 === 0 ? 0 : STEP_Y / 2;
        for (let y = -HEX_SIZE + offsetY; y < H + HEX_SIZE * 2; y += STEP_Y, row++) {
          hexes.push({
            cx: x,
            cy: y,
            baseColor: PALETTE[Math.floor(Math.random() * PALETTE.length)],
            phase: Math.random() * Math.PI * 2,   // for pulse animation
            speed: 0.3 + Math.random() * 0.7,
            depth: 0.3 + Math.random() * 0.7,     // simulated 3-D depth (brightness)
          });
        }
      }
      hexesRef.current = hexes;
    }

    function resize() {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
      buildHexes();
    }

    function draw(ts) {
      timeRef.current = ts * 0.001;
      const W = canvas.width;
      const H = canvas.height;

      // Clear
      ctx.clearRect(0, 0, W, H);

      // Solid background
      ctx.fillStyle = '#06080f';
      ctx.fillRect(0, 0, W, H);

      // Draw hexes
      for (const h of hexesRef.current) {
        const pulse = 0.55 + 0.45 * Math.sin(timeRef.current * h.speed + h.phase);
        const alpha = h.depth * pulse;

        // Fill
        hexPath(h.cx, h.cy, HEX_SIZE - 1, ctx);
        ctx.fillStyle = h.baseColor.replace(/[\d.]+\)$/, `${(parseFloat(h.baseColor.match(/[\d.]+\)$/)[0]) * alpha).toFixed(3)})`);
        ctx.fill();

        // Edge highlight (simulates 3-D bevel)
        hexPath(h.cx, h.cy, HEX_SIZE - 1, ctx);
        const edgeAlpha = 0.08 + 0.12 * alpha;
        ctx.strokeStyle = `rgba(0,212,255,${edgeAlpha.toFixed(3)})`;
        ctx.lineWidth   = 0.8;
        ctx.stroke();
      }

      // Radial vignette so center glows slightly
      const vignette = ctx.createRadialGradient(W / 2, H / 2, 0, W / 2, H / 2, Math.max(W, H) * 0.72);
      vignette.addColorStop(0, 'rgba(0,30,60,0.0)');
      vignette.addColorStop(1, 'rgba(0,0,10,0.72)');
      ctx.fillStyle = vignette;
      ctx.fillRect(0, 0, W, H);

      frameRef.current = requestAnimationFrame(draw);
    }

    resize();
    window.addEventListener('resize', resize);
    frameRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(frameRef.current);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
        display: 'block',
      }}
    />
  );
}
