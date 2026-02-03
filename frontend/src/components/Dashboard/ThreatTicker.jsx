import React, { useState, useEffect } from 'react';
import './ThreatTicker.css';

const ThreatTicker = ({ threats }) => {
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    if (!threats || threats.length === 0) return;

    const interval = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % threats.length);
    }, 4000); // Rotate every 4 seconds

    return () => clearInterval(interval);
  }, [threats]);

  if (!threats || threats.length === 0) return null;

  const currentThreat = threats[currentIndex];

  return (
    <div className="threat-ticker-container">
      <div className="ticker-label">
        <span className="pulse-dot"></span> LIVE THREAT INTEL
      </div>
      <div className="ticker-content fade-in-up" key={currentIndex}>
        <span className="threat-id">{currentThreat.cve_id || 'CVE-PENDING'}</span>
        <span className="threat-severity" data-severity={(currentThreat.severity || 'low').toUpperCase()}>
          {currentThreat.severity || 'LOW'}
        </span>
        <span className="threat-title">
          {currentThreat.description?.substring(0, 100) || 'Threat description unavailable...'}...
        </span>
      </div>
    </div>
  );
};

export default ThreatTicker;
