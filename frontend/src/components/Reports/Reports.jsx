import { useState, useEffect } from 'react';
import { scanAPI } from '../../services/api';
import './Reports.css';

const Reports = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      setLoading(true);
      const data = await scanAPI.list(0, 20);
      // Filter for completed scans only
      setScans(data.filter(s => s.status === 'completed'));
    } catch (error) {
      console.error('Failed to load scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (scanId, type) => {
    // Direct link to the API endpoint
    const url = `${import.meta.env.VITE_API_URL}/reports/${scanId}/${type}`;
    window.open(url, '_blank');
  };

  return (
    <section className="reports-section">
      <div className="section-header">
        <h1 className="section-title">Security Reports</h1>
        <p className="section-subtitle">Export results from completed scans</p>
      </div>

      <div className="reports-content">
        <div className="glass-panel">
          <div className="panel-header">
            <h3>Available Reports</h3>
            <button className="btn-text" onClick={loadScans}><i className="fas fa-sync"></i> Refresh</button>
          </div>
          
          {loading ? (
             <div className="p-4 text-center">Loading completed scans...</div>
          ) : (
            <table className="modern-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Target</th>
                  <th>Score</th>
                  <th>Export</th>
                </tr>
              </thead>
              <tbody>
                {scans.length > 0 ? (
                  scans.map(scan => (
                    <tr key={scan.id}>
                      <td>{new Date(scan.created_at || scan.started_at).toLocaleDateString()}</td>
                      <td className="font-mono">{scan.target_url || scan.target}</td>
                      <td>
                        <span className={`badge ${
                          (scan.security_score || 0) >= 90 ? 'success' : 
                          (scan.security_score || 0) >= 70 ? 'warning' : 'danger'
                        }`}>
                          {scan.security_score || 'N/A'}
                        </span>
                      </td>
                      <td className="actions-cell">
                        <button 
                          className="btn-sm btn-secondary"
                          onClick={() => handleDownload(scan.id, 'json')}
                        >
                          <i className="fas fa-code"></i> JSON
                        </button>
                        <button 
                          style={{marginLeft: '8px'}}
                          className="btn-sm btn-primary"
                          onClick={() => handleDownload(scan.id, 'csv')}
                        >
                          <i className="fas fa-file-csv"></i> CSV
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4" className="text-center p-8 text-muted">
                      No completed scans found available for reporting.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </section>
  );
};

export default Reports;

