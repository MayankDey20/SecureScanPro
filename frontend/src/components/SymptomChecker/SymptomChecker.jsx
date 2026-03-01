import { useState } from 'react';
import { aiAPI } from '../../services/api';
import './SymptomChecker.css';

/* ─── severity colour helper ─── */
const sevColor = (s = '') => {
  switch (s.toLowerCase()) {
    case 'critical': return 'sc-sev-critical';
    case 'high':     return 'sc-sev-high';
    case 'medium':   return 'sc-sev-medium';
    default:         return 'sc-sev-low';
  }
};

/* ─── confidence bar label ─── */
const confLabel = (c) => {
  if (c >= 0.8) return 'High match';
  if (c >= 0.5) return 'Likely match';
  if (c >= 0.3) return 'Possible match';
  return 'Weak signal';
};

/* ════════════════════════════════════════
   DIAGNOSIS CARD
════════════════════════════════════════ */
const DiagnosisCard = ({ d, index }) => {
  const [expanded, setExpanded] = useState(index === 0);

  return (
    <div className={`sc-card ${sevColor(d.severity)}`}>
      {/* ── Card header ── */}
      <div className="sc-card-header" onClick={() => setExpanded(!expanded)}>
        <div className="sc-card-left">
          <span className={`sc-badge ${sevColor(d.severity)}`}>
            {d.severity?.toUpperCase()}
          </span>
          <div>
            <div className="sc-attack-name">{d.name}</div>
            <div className="sc-owasp">{d.owasp}</div>
          </div>
        </div>
        <div className="sc-card-right">
          <div className="sc-confidence-wrap">
            <span className="sc-conf-label">{confLabel(d.confidence)}</span>
            <div className="sc-conf-bar-bg">
              <div
                className={`sc-conf-bar ${sevColor(d.severity)}`}
                style={{ width: `${Math.round(d.confidence * 100)}%` }}
              />
            </div>
            <span className="sc-conf-pct">{Math.round(d.confidence * 100)}%</span>
          </div>
          <i className={`fas fa-chevron-${expanded ? 'up' : 'down'} sc-chevron`} />
        </div>
      </div>

      {/* ── Expandable body ── */}
      {expanded && (
        <div className="sc-card-body">
          {/* Match reason */}
          {d.match_reason && (
            <p className="sc-match-reason">
              <i className="fas fa-microscope" /> {d.match_reason}
            </p>
          )}

          {/* Historical attacks */}
          {d.historical_attacks?.length > 0 && (
            <div className="sc-section">
              <div className="sc-section-title">
                <i className="fas fa-history" /> Historical Attacks
              </div>
              <div className="sc-hist-grid">
                {d.historical_attacks.map((h, i) => (
                  <div key={i} className="sc-hist-card">
                    <div className="sc-hist-name">{h.name}</div>
                    <div className="sc-hist-detail">{h.detail}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          {d.remediation?.length > 0 && (
            <div className="sc-section">
              <div className="sc-section-title">
                <i className="fas fa-shield-alt" /> Remediation Steps
              </div>
              <ol className="sc-remediation-list">
                {d.remediation.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ol>
            </div>
          )}

          {/* CVEs + Compliance */}
          {(d.cve_examples?.length > 0 || d.compliance?.length > 0) && (
            <div className="sc-section sc-refs-row">
              {d.cve_examples?.length > 0 && (
                <div className="sc-chips-group">
                  <span className="sc-chips-label">CVEs</span>
                  {d.cve_examples.map((c, i) => (
                    <span key={i} className="sc-chip sc-chip-cve">{c}</span>
                  ))}
                </div>
              )}
              {d.compliance?.length > 0 && (
                <div className="sc-chips-group">
                  <span className="sc-chips-label">Compliance</span>
                  {d.compliance.map((c, i) => (
                    <span key={i} className="sc-chip sc-chip-compliance">{c}</span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

/* ════════════════════════════════════════
   MAIN PAGE
════════════════════════════════════════ */
const SymptomChecker = () => {
  const [symptoms, setSymptoms]     = useState('');
  const [context,  setContext]      = useState('');
  const [result,   setResult]       = useState(null);
  const [loading,  setLoading]      = useState(false);
  const [error,    setError]        = useState('');

  const examples = [
    'Users are getting logged out randomly and we see strange session tokens in the logs',
    'Database queries are running much slower than usual and we see unusual WHERE clauses',
    'CPU spikes to 100% every few minutes even when traffic is low',
    'We get 403 errors when accessing certain admin paths but non-admin users seem to reach them',
    'API responses sometimes include data from other users\' accounts',
  ];

  const handleDiagnose = async () => {
    if (!symptoms.trim()) { setError('Please describe your symptoms.'); return; }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const data = await aiAPI.diagnoseSymptoms(symptoms.trim(), context.trim());
      setResult(data);
    } catch (e) {
      setError(e?.response?.data?.detail || 'Diagnosis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleExample = (ex) => {
    setSymptoms(ex);
    setResult(null);
    setError('');
  };

  return (
    <section className="sc-section">
      {/* ── Page header ── */}
      <div className="sc-header">
        <div className="sc-header-icon">
          <i className="fas fa-stethoscope" />
        </div>
        <div>
          <h1 className="sc-title">Security Medical Checkup</h1>
          <p className="sc-subtitle">
            Describe your system's symptoms — unusual behaviour, errors, or anomalies — and
            our AI engine will match them to known attack patterns and historical breaches.
          </p>
        </div>
      </div>

      <div className="sc-layout">
        {/* ════ LEFT: Input panel ════ */}
        <div className="sc-input-panel">
          {/* Symptoms textarea */}
          <div className="sc-field">
            <label className="sc-label">
              <i className="fas fa-notes-medical" /> Describe Your Symptoms
            </label>
            <textarea
              className="sc-textarea"
              rows={6}
              placeholder="e.g. &#34;Users are seeing other users' data in API responses. We also noticed strange query strings in our access logs with single-quote characters...&#34;"
              value={symptoms}
              onChange={(e) => setSymptoms(e.target.value)}
              disabled={loading}
            />
          </div>

          {/* Context textarea */}
          <div className="sc-field">
            <label className="sc-label">
              <i className="fas fa-server" /> System Context{' '}
              <span className="sc-optional">(optional)</span>
            </label>
            <textarea
              className="sc-textarea sc-textarea-sm"
              rows={3}
              placeholder="e.g. Node.js API, PostgreSQL database, behind nginx reverse proxy, AWS ECS..."
              value={context}
              onChange={(e) => setContext(e.target.value)}
              disabled={loading}
            />
          </div>

          {/* Error */}
          {error && (
            <div className="sc-error">
              <i className="fas fa-exclamation-triangle" /> {error}
            </div>
          )}

          {/* Diagnose button */}
          <button
            className="sc-diagnose-btn"
            onClick={handleDiagnose}
            disabled={loading || !symptoms.trim()}
          >
            {loading ? (
              <>
                <span className="sc-spinner" />
                Analysing symptoms…
              </>
            ) : (
              <>
                <i className="fas fa-dna" /> Run Diagnosis
              </>
            )}
          </button>

          {/* Example symptoms */}
          <div className="sc-examples">
            <div className="sc-examples-title">
              <i className="fas fa-flask" /> Try an example
            </div>
            <div className="sc-example-list">
              {examples.map((ex, i) => (
                <button
                  key={i}
                  className="sc-example-btn"
                  onClick={() => handleExample(ex)}
                  disabled={loading}
                >
                  {ex.length > 68 ? ex.slice(0, 68) + '…' : ex}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* ════ RIGHT: Results panel ════ */}
        <div className="sc-results-panel">
          {/* Empty state */}
          {!result && !loading && (
            <div className="sc-empty">
              <i className="fas fa-heartbeat sc-empty-icon" />
              <div className="sc-empty-title">Ready for Diagnosis</div>
              <div className="sc-empty-sub">
                Describe the anomalies you're observing on the left and click{' '}
                <strong>Run Diagnosis</strong> to identify potential attack vectors.
              </div>
            </div>
          )}

          {/* Loading skeleton */}
          {loading && (
            <div className="sc-loading">
              <div className="sc-loading-pulse">
                <i className="fas fa-dna sc-dna-icon" />
                <span>Correlating with threat database…</span>
              </div>
              {[1, 2, 3].map((n) => (
                <div key={n} className="sc-skeleton" />
              ))}
            </div>
          )}

          {/* Results */}
          {result && !loading && (
            <>
              {/* Summary bar */}
              <div className="sc-summary-bar">
                <div className="sc-summary-left">
                  <span className="sc-summary-count">
                    {result.total_matches} potential{' '}
                    {result.total_matches === 1 ? 'match' : 'matches'}
                  </span>
                  <span className="sc-summary-snippet">
                    "{result.symptom_summary?.slice(0, 60)}
                    {result.symptom_summary?.length > 60 ? '…' : ''}"
                  </span>
                </div>
                <span className={`sc-ai-badge ${result.ai_powered ? 'sc-ai-on' : 'sc-ai-off'}`}>
                  <i className={`fas fa-${result.ai_powered ? 'robot' : 'calculator'}`} />
                  {result.ai_powered ? 'AI-Powered' : 'Heuristic'}
                </span>
              </div>

              {/* No matches */}
              {result.diagnoses?.length === 0 && (
                <div className="sc-no-match">
                  <i className="fas fa-check-circle" />
                  <div>No strong attack pattern matches found for the described symptoms.</div>
                </div>
              )}

              {/* Diagnosis cards */}
              <div className="sc-card-list">
                {result.diagnoses?.map((d, i) => (
                  <DiagnosisCard key={d.attack_id} d={d} index={i} />
                ))}
              </div>

              {/* Disclaimer */}
              <p className="sc-disclaimer">
                <i className="fas fa-info-circle" /> This diagnosis is based on symptom
                pattern matching and should be validated with a full security scan.
                Results do not constitute a definitive security assessment.
              </p>
            </>
          )}
        </div>
      </div>
    </section>
  );
};

export default SymptomChecker;
