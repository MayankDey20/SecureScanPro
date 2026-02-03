import { useState } from 'react';
import { scanAPI } from '../../services/api';
import './Scanner.css';

const Scanner = () => {
  const [scanMode, setScanMode] = useState('single');
  const [formData, setFormData] = useState({
    targetUrl: '',
    scanType: 'full',
    scanDepth: 'medium',
  });
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const result = await scanAPI.start({
        target: formData.targetUrl,
        scan_type: [formData.scanType],
        scan_options: {
          scan_depth: formData.scanDepth,
        },
      });
      setScanResult(result);
      alert('Scan started successfully!');
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="scanner-section">
      <div className="section-header">
        <h1 className="section-title">Advanced Security Scanner</h1>
        <p className="section-subtitle">Configure and launch comprehensive security assessments</p>
      </div>

      <div className="scanner-container">
        <div className="scanner-card">
          <div className="card-header">
            <h3>Scan Configuration</h3>
            <div className="scan-mode-toggle">
              <button
                className={`toggle-btn ${scanMode === 'single' ? 'active' : ''}`}
                onClick={() => setScanMode('single')}
              >
                Single URL
              </button>
              <button
                className={`toggle-btn ${scanMode === 'batch' ? 'active' : ''}`}
                onClick={() => setScanMode('batch')}
              >
                Batch Scan
              </button>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="scan-form">
            <div className="form-group">
              <label>Target URL</label>
              <input
                type="url"
                className="form-input"
                value={formData.targetUrl}
                onChange={(e) => setFormData({ ...formData, targetUrl: e.target.value })}
                placeholder="https://example.com"
                required
              />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Scan Depth</label>
                <select
                  className="form-select"
                  value={formData.scanDepth}
                  onChange={(e) => setFormData({ ...formData, scanDepth: e.target.value })}
                >
                  <option value="shallow">Shallow - Quick scan</option>
                  <option value="medium">Medium - Standard scan</option>
                  <option value="deep">Deep - Comprehensive scan</option>
                </select>
              </div>

              <div className="form-group">
                <label>Scan Type</label>
                <select
                  className="form-select"
                  value={formData.scanType}
                  onChange={(e) => setFormData({ ...formData, scanType: e.target.value })}
                >
                  <option value="full">Full Security Audit</option>
                  <option value="vulnerability">Vulnerability Only</option>
                  <option value="compliance">Compliance Check</option>
                </select>
              </div>
            </div>

            <button type="submit" className="btn-primary btn-lg" disabled={loading}>
              {loading ? 'Starting...' : 'Start Security Scan'}
            </button>
          </form>

          {scanResult && (
            <div className="scan-result">
              <p>Scan ID: {scanResult._id || scanResult.scanId}</p>
              <p>Status: {scanResult.status}</p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};

export default Scanner;

