import { useState, useEffect } from 'react';
import { scanAPI, aiAPI } from '../../services/api';
import './Results.css';

const Results = () => {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [analyzingId, setAnalyzingId] = useState(null);

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    if (selectedScan) {
      loadResults(selectedScan);
      setAiAnalysis(null); // Reset AI analysis when switching scans
    }
  }, [selectedScan]);

  const loadScans = async () => {
    try {
      setLoading(true);
      const data = await scanAPI.list(0, 50);
      setScans(data);
      if (data.length > 0 && !selectedScan) {
        setSelectedScan(data[0].id);
      }
    } catch (error) {
      console.error('Failed to load scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadResults = async (scanId) => {
    try {
      const data = await scanAPI.getResults(scanId);
      setResults(data);
    } catch (error) {
      console.error('Failed to load results:', error);
    }
  };
  
  const handleAiAnalyze = async (finding) => {
    try {
      setAnalyzingId(finding.id);
      setAiAnalysis(null);
      const analysis = await aiAPI.analyze(
        finding.title, 
        finding.description || "No specific description available.", 
        finding.severity
      );
      setAiAnalysis(analysis);
    } catch (error) {
      console.error("AI Analysis failed:", error);
      alert("Failed to perform AI analysis.");
    } finally {
      setAnalyzingId(null);
    }
  };

  const closeAiModal = () => {
    setAiAnalysis(null);
  }

  if (loading) {
    return <div className="loading">Loading results...</div>;
  }

  return (
    <section className="results-section">
      <div className="section-header">
        <h1 className="section-title">Scan Results</h1>
        <p className="section-subtitle">Detailed analysis of discovered vulnerabilities</p>
      </div>
      
      {/* AI Analysis Modal */}
      {aiAnalysis && (
        <div className="ai-modal-overlay">
          <div className="ai-modal">
            <div className="ai-modal-header">
              <h2>🤖 {aiAnalysis.classification?.detected_type || "AI Analysis"}</h2>
              <button className="close-btn" onClick={closeAiModal}>×</button>
            </div>
            <div className="ai-modal-content">
              <div className="ai-score-card">
                 <div className="score-ring" style={{"--score": aiAnalysis.risk_assessment?.calculated_risk_score}}>
                    <span>{aiAnalysis.risk_assessment?.calculated_risk_score}</span>
                    <small>Risk Score</small>
                 </div>
                 <div className="ai-summary">
                    <p><strong>Impact:</strong> {aiAnalysis.risk_assessment?.predicted_impact}</p>
                    <p><strong>Confidence:</strong> {(aiAnalysis.classification?.confidence_score * 100).toFixed(0)}%</p>
                 </div>
              </div>
              
              <div className="ai-section">
                <h3>💡 Remediation Strategy</h3>
                <p className="remediation-text">{aiAnalysis.remediation?.suggested_action}</p>
              </div>

              <div className="ai-section">
                <h3>🔍 Detailed Insights</h3>
                <p>{aiAnalysis.explanation}</p>
              </div>
              
              <div className="ai-footer">
                <small>Analysis by {aiAnalysis.ai_model} at {aiAnalysis.analysis_timestamp}</small>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="results-container">
        <div className="scans-sidebar">
          <h3>Recent Scans</h3>
          <div className="scans-list">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className={`scan-item ${selectedScan === scan.id ? 'active' : ''}`}
                onClick={() => setSelectedScan(scan.id)}
              >
                <div className="scan-url">{scan.target_url}</div>
                <div className="scan-meta">
                  <span className={`status-badge ${scan.status}`}>{scan.status}</span>
                  <span>Score: {scan.security_score || 'N/A'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="results-content">
          {results ? (
            <>
              <div className="result-summary">
                <h2>Security Score: {results.securityScore || 'N/A'}</h2>
                <div className="vuln-breakdown">
                  <div className="vuln-item critical">
                    <span className="vuln-count">{results.vulnerabilities?.critical || 0}</span>
                    <span className="vuln-label">Critical</span>
                  </div>
                  <div className="vuln-item high">
                    <span className="vuln-count">{results.vulnerabilities?.high || 0}</span>
                    <span className="vuln-label">High</span>
                  </div>
                  <div className="vuln-item medium">
                    <span className="vuln-count">{results.vulnerabilities?.medium || 0}</span>
                    <span className="vuln-label">Medium</span>
                  </div>
                  <div className="vuln-item low">
                    <span className="vuln-count">{results.vulnerabilities?.low || 0}</span>
                    <span className="vuln-label">Low</span>
                  </div>
                </div>
              </div>

              <div className="findings-list">
                <h3>Vulnerabilities Found</h3>
                {results.findings && results.findings.length > 0 ? (
                  <table className="findings-table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Title</th>
                        <th>Location</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.findings.map((finding) => (
                        <tr key={finding.id}>
                          <td>
                            <span className={`severity-badge ${finding.severity}`}>
                              {finding.severity}
                            </span>
                          </td>
                          <td>{finding.type}</td>
                          <td>{finding.title}</td>
                          <td><code>{finding.location}</code></td>
                          <td>
                            <button 
                                className="ai-analyze-btn" 
                                onClick={() => handleAiAnalyze(finding)}
                                disabled={analyzingId === finding.id}
                            >
                                {analyzingId === finding.id ? 'Analyzing...' : '⚡ AI Check'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p className="empty-message">No vulnerabilities found.</p>
                )}
              </div>
            </>
          ) : (
            <div className="empty-state">
              <p>Select a scan to view results</p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};

export default Results;

