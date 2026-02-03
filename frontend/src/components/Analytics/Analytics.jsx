import { useState, useEffect } from 'react';
import { analyticsAPI } from '../../services/api';
import './Analytics.css';

const Analytics = () => {
  const [trends, setTrends] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadTrends();
  }, []);

  const loadTrends = async () => {
    try {
      setLoading(true);
      const data = await analyticsAPI.getTrends('30d');
      setTrends(data);
    } catch (error) {
      console.error('Failed to load trends:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading analytics...</div>;
  }

  return (
    <section className="analytics-section">
      <div className="section-header">
        <h1 className="section-title">Security Analytics</h1>
        <p className="section-subtitle">Historical trends and comparative analysis</p>
      </div>

      <div className="analytics-content">
        {trends ? (
          <div className="trends-card">
            <h3>Security Score Trends</h3>
            <div className="trends-chart">
              {/* Chart would be implemented with Chart.js */}
              <p>Chart visualization would go here</p>
              <p>Period: {trends.period}</p>
              <p>Scores: {trends.securityScores?.join(', ')}</p>
            </div>
          </div>
        ) : (
          <div className="empty-state">
            <p>No analytics data available</p>
          </div>
        )}
      </div>
    </section>
  );
};

export default Analytics;

