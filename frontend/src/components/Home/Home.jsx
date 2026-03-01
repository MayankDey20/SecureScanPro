import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { supabase } from '../../lib/supabase';
import NetworkBackground from '../Background/NetworkBackground';
import './Home.css';

/* ── comparison table data ── */
const COMPARISON = [
  { feature: 'AI-Powered Vulnerability Analysis',  us: true,  nessus: false, burp: false, owasp: false },
  { feature: 'Security Symptom Checker',           us: true,  nessus: false, burp: false, owasp: false },
  { feature: 'Real-Time Threat Intelligence Feed', us: true,  nessus: true,  burp: false, owasp: false },
  { feature: 'Historical Breach Correlation',      us: true,  nessus: false, burp: false, owasp: false },
  { feature: 'Scheduled Automated Scans',          us: true,  nessus: true,  burp: true,  owasp: false },
  { feature: 'Interactive Analytics Dashboard',    us: true,  nessus: true,  burp: false, owasp: false },
  { feature: 'PDF / Report Export',                us: true,  nessus: true,  burp: true,  owasp: true  },
  { feature: 'SSL / TLS Deep Inspection',          us: true,  nessus: true,  burp: true,  owasp: true  },
  { feature: 'IDOR & Auth-Flow Scanner',           us: true,  nessus: false, burp: true,  owasp: false },
  { feature: 'Network Recon (Shodan / AbuseIPDB)', us: true,  nessus: false, burp: false, owasp: false },
  { feature: 'Team Collaboration & RBAC',          us: true,  nessus: true,  burp: false, owasp: false },
  { feature: 'Open Source / Free Tier',            us: true,  nessus: false, burp: false, owasp: true  },
  { feature: 'No Agent Installation Required',     us: true,  nessus: false, burp: true,  owasp: true  },
  { feature: 'Biometric / PIN Login',              us: true,  nessus: false, burp: false, owasp: false },
];

const FEATURES = [
  {
    id: '01', icon: 'fa-brain', title: 'AI Threat Analysis',
    accent: '#a78bfa',
    tag: 'gemini-1.5-flash',
    desc: 'Gemini reasons over raw scan output to produce plain-English severity assessments, exploit likelihood scores and targeted fix recommendations — not just a list of CVEs.'
  },
  {
    id: '02', icon: 'fa-stethoscope', title: 'Symptom Checker',
    accent: '#34d399',
    tag: '13 attack patterns',
    desc: 'Type the weird behaviour you\'re seeing. Our engine cross-references 13 known attack patterns against real breach history — Equifax, SolarWinds, Heartbleed — and tells you what it looks like.'
  },
  {
    id: '03', icon: 'fa-shield-virus', title: 'Live Threat Intel',
    accent: '#f87171',
    tag: 'AbuseIPDB · Shodan · VT',
    desc: 'Real-time threat feed from four external providers, deduplicated and plotted on a rotating 3-D globe. Incoming attack IPs are tagged, scored and linked to CVEs automatically.'
  },
  {
    id: '04', icon: 'fa-terminal', title: 'Deep Network Recon',
    accent: '#38bdf8',
    tag: 'nuclei · nmap · crawl4ai',
    desc: 'Port sweep → service fingerprint → SSL/TLS grade → security header audit → authenticated crawler → nuclei template match. One target URL, fifty checks, one report.'
  },
  {
    id: '05', icon: 'fa-chart-line', title: 'Analytics & Trends',
    accent: '#fbbf24',
    tag: 'time-series · heatmaps',
    desc: 'Watch your security score move over time. Spot which assets are repeatedly targeted, which vulnerability classes keep coming back, and where your remediation is actually working.'
  },
  {
    id: '06', icon: 'fa-file-contract', title: 'Professional Reports',
    accent: '#818cf8',
    tag: 'PDF · CVSS · exec summary',
    desc: 'One-click export: executive summary up front, full technical evidence behind it. CVSS scores, affected endpoints, reproduction steps and a prioritised fix roadmap — all in one PDF.'
  },
  {
    id: '07', icon: 'fa-clock', title: 'Scheduled Scans',
    accent: '#fb923c',
    tag: 'cron · celery beat',
    desc: 'Define a cadence. Celery Beat fires your scan, emails you the delta from last time, and flags any regressions — so you catch newly introduced vulnerabilities before your users do.'
  },
  {
    id: '08', icon: 'fa-users-cog', title: 'Team & RBAC',
    accent: '#2dd4bf',
    tag: 'Admin · Analyst · Viewer',
    desc: 'Invite your team, lock down what each role can see and do, and get a full audit trail of every scan, export and setting change. Built for multi-tenant security operations.'
  },
];

const STATS = [
  { value: '13+',   label: 'Attack Pattern Types' },
  { value: '50+',   label: 'Scan Checks Per Target' },
  { value: '99.9%', label: 'Uptime SLA' },
  { value: '< 5s',  label: 'Avg. First Finding' },
];

const Check = () => <span className="hm-check"><i className="fas fa-check" /></span>;
const Cross = () => <span className="hm-cross"><i className="fas fa-times" /></span>;

const Home = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const dest = user ? '/dashboard' : '/register';
  const handleSignOut = async () => { await supabase.auth.signOut(); navigate('/'); };
  return (
  <div className="hm-root">
    <NetworkBackground />

    {/* ════ PUBLIC NAVBAR ════ */}
    <nav className="hm-nav">
      <div className="hm-nav-inner">
        <div className="hm-brand">
          <img src="/pixel-shield.svg" alt="logo" className="hm-brand-logo" />
          <span className="hm-brand-text">SecureScan<span className="hm-brand-pro">Pro</span></span>
        </div>
        <div className="hm-nav-links">
          <a href="#features" className="hm-nav-link">Features</a>
          <a href="#compare"  className="hm-nav-link">Compare</a>
          <a href="#about"    className="hm-nav-link">About</a>
          {user
            ? <button onClick={handleSignOut} className="hm-btn hm-btn-ghost"><i className="fas fa-sign-out-alt" /> Sign Out</button>
            : <Link to="/login" className="hm-btn hm-btn-ghost">Sign In</Link>
          }
          <Link to={dest} className="hm-btn hm-btn-primary">{user ? 'Go to Dashboard' : 'Get Started'}</Link>
        </div>
      </div>
    </nav>

    {/* ════ HERO ════ */}
    <section className="hm-hero">
      <div className="hm-hero-eyebrow">
        <span className="hm-pulse-dot" /> AI-Powered Security Platform
      </div>
      <h1 className="hm-hero-title">
        Scan. Diagnose.<br />
        <span className="hm-hero-gradient">Defend.</span>
      </h1>
      <p className="hm-hero-sub">
        SecureScanPro combines automated vulnerability scanning, real-time threat intelligence
        and an AI symptom checker into one unified security command centre — built for developers
        and security teams who move fast.
      </p>
      <div className="hm-hero-cta">
        <Link to={dest} className="hm-btn hm-btn-primary hm-btn-lg">
          <i className="fas fa-rocket" /> {user ? 'Go to Dashboard' : 'Start Free Scan'}
        </Link>
        {user
          ? <button onClick={handleSignOut} className="hm-btn hm-btn-ghost hm-btn-lg"><i className="fas fa-sign-out-alt" /> Sign Out</button>
          : <Link to="/login" className="hm-btn hm-btn-ghost hm-btn-lg"><i className="fas fa-sign-in-alt" /> Sign In</Link>
        }
      </div>
      {/* stats strip */}
      <div className="hm-stats">
        {STATS.map((s) => (
          <div key={s.label} className="hm-stat">
            <span className="hm-stat-value">{s.value}</span>
            <span className="hm-stat-label">{s.label}</span>
          </div>
        ))}
      </div>
    </section>

    {/* ════ FEATURES ════ */}
    <section className="hm-section" id="features">
      <div className="hm-section-inner">
        <div className="hm-feat-header">
          <div className="hm-feat-terminal-bar">
            <span className="hm-dot hm-dot-r" /><span className="hm-dot hm-dot-y" /><span className="hm-dot hm-dot-g" />
            <span className="hm-terminal-label">securescanpro --capabilities --list-all</span>
          </div>
          <h2 className="hm-feat-section-title">A full security stack.<br /><span className="hm-hero-gradient">One command centre.</span></h2>
          <p className="hm-feat-section-sub">From first scan to board-level report — every tool you need, none you don't.</p>
        </div>
        <div className="hm-features-grid">
          {FEATURES.map((f) => (
            <div key={f.title} className="hm-feat-card" style={{'--feat-accent': f.accent}}>
              <div className="hm-feat-top">
                <span className="hm-feat-id">{f.id}</span>
                <span className="hm-feat-tag"><i className="fas fa-tag" /> {f.tag}</span>
              </div>
              <div className="hm-feat-icon-row">
                <i className={`fas ${f.icon} hm-feat-icon`} />
                <h3 className="hm-feat-title">{f.title}</h3>
              </div>
              <p className="hm-feat-desc">{f.desc}</p>
              <div className="hm-feat-accent-bar" />
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* ════ COMPARISON TABLE ════ */}
    <section className="hm-section hm-section-dark" id="compare">
      <div className="hm-section-inner">
        <p className="hm-section-eyebrow">How we stack up</p>
        <h2 className="hm-section-title">SecureScanPro vs the competition</h2>
        <p className="hm-section-sub">
          Enterprise-grade capabilities without the enterprise price tag.
        </p>
        <div className="hm-table-wrap">
          <table className="hm-table">
            <thead>
              <tr>
                <th className="hm-th-feature">Feature</th>
                <th className="hm-th hm-th-us">SecureScanPro</th>
                <th className="hm-th">Nessus</th>
                <th className="hm-th">Burp Suite</th>
                <th className="hm-th">OWASP ZAP</th>
              </tr>
            </thead>
            <tbody>
              {COMPARISON.map((row, i) => (
                <tr key={i} className={i % 2 === 0 ? 'hm-tr-even' : ''}>
                  <td className="hm-td-feature">{row.feature}</td>
                  <td className="hm-td hm-td-us">{row.us     ? <Check /> : <Cross />}</td>
                  <td className="hm-td">{row.nessus  ? <Check /> : <Cross />}</td>
                  <td className="hm-td">{row.burp    ? <Check /> : <Cross />}</td>
                  <td className="hm-td">{row.owasp   ? <Check /> : <Cross />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>

    {/* ════ ABOUT ════ */}
    <section className="hm-section" id="about">
      <div className="hm-section-inner hm-about-grid">
        <div className="hm-about-text">
          <p className="hm-section-eyebrow">About us</p>
          <h2 className="hm-section-title hm-left">Built by security engineers,<br />for everyone.</h2>
          <p className="hm-about-body">
            SecureScanPro was born from the frustration of juggling five separate tools for a single
            security assessment — a port scanner here, a header checker there, a threat feed somewhere
            else. We unified them.
          </p>
          <p className="hm-about-body">
            Our mission is to make professional-grade security scanning accessible to solo developers,
            startups and enterprise teams alike. Every check we run — from SSL grading to AI-assisted
            diagnosis — is the same standard used by dedicated security consultants.
          </p>
          <div className="hm-about-pills">
            {['FastAPI', 'React', 'Gemini AI', 'Supabase', 'Celery', 'Nuclei'].map((t) => (
              <span key={t} className="hm-pill">{t}</span>
            ))}
          </div>
        </div>
        <div className="hm-about-cards">
          {[
            {
              stat: '< 5s',  label: 'First finding',
              sub: 'median time-to-first-vuln across all scan types',
              bar: 92, accent: '#38bdf8',
              status: 'LIVE', statusColor: '#22c55e',
              icon: 'fa-bolt',
            },
            {
              stat: '0 logs', label: 'Target data retained',
              sub: 'raw scan targets are never written to persistent storage',
              bar: 100, accent: '#a78bfa',
              status: 'VERIFIED', statusColor: '#a78bfa',
              icon: 'fa-lock',
            },
            {
              stat: '50+',   label: 'Checks per scan',
              sub: 'ports · headers · SSL · auth · IDOR · nuclei templates',
              bar: 78, accent: '#34d399',
              status: 'ASYNC', statusColor: '#34d399',
              icon: 'fa-layer-group',
            },
            {
              stat: '∞',     label: 'Extensible',
              sub: 'drop in custom nuclei templates or threat providers with zero code changes',
              bar: 60, accent: '#fbbf24',
              status: 'PLUGIN-READY', statusColor: '#fbbf24',
              icon: 'fa-plug',
            },
          ].map((c) => (
            <div key={c.label} className="hm-acard" style={{'--acard-accent': c.accent}}>
              <div className="hm-acard-top">
                <i className={`fas ${c.icon} hm-acard-icon`} />
                <span className="hm-acard-status" style={{color: c.statusColor, borderColor: c.statusColor}}>
                  <span className="hm-acard-dot" style={{background: c.statusColor}} />
                  {c.status}
                </span>
              </div>
              <div className="hm-acard-stat">{c.stat}</div>
              <div className="hm-acard-label">{c.label}</div>
              <p className="hm-acard-sub">{c.sub}</p>
              <div className="hm-acard-track">
                <div className="hm-acard-fill" style={{width: `${c.bar}%`}} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* ════ CTA BANNER ════ */}
    <section className="hm-cta-banner">
      <h2 className="hm-cta-title">Ready to secure your infrastructure?</h2>
      <p className="hm-cta-sub">Join thousands of teams running continuous security checks with SecureScanPro.</p>
      <div className="hm-hero-cta">
        <Link to={dest} className="hm-btn hm-btn-primary hm-btn-lg">
          <i className="fas fa-shield-alt" /> {user ? 'Go to Dashboard' : 'Create Free Account'}
        </Link>
        {user
          ? <button onClick={handleSignOut} className="hm-btn hm-btn-ghost hm-btn-lg"><i className="fas fa-sign-out-alt" /> Sign Out</button>
          : <Link to="/login" className="hm-btn hm-btn-ghost hm-btn-lg">Sign In</Link>
        }
      </div>
    </section>

    {/* ════ FOOTER ════ */}
    <footer className="hm-footer">
      <div className="hm-footer-inner">
        <div className="hm-brand">
          <img src="/pixel-shield.svg" alt="logo" className="hm-brand-logo" />
          <span className="hm-brand-text">SecureScan<span className="hm-brand-pro">Pro</span></span>
        </div>
        <p className="hm-footer-copy">© {new Date().getFullYear()} SecureScanPro. Built with <i className="fas fa-heart" style={{color:'#ef4444'}} /> for the security community.</p>
      </div>
    </footer>
  </div>
  );
};

export default Home;
