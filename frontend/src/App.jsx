import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Navbar from './components/Navbar';
import Login from './components/Auth/Login';
import Register from './components/Auth/Register';
import Dashboard from './components/Dashboard/Dashboard';
import Scanner from './components/Scanner/Scanner';
import Results from './components/Results/Results';
import Analytics from './components/Analytics/Analytics';
import ThreatIntelligence from './components/ThreatIntelligence/ThreatIntelligence';
import Reports from './components/Reports/Reports';
import Settings from './components/Settings/Settings';
import Profile from './components/Profile/Profile';
import NetworkBackground from './components/Background/NetworkBackground';
import './App.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="app">
          <NetworkBackground />
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route
              path="/*"
              element={
                <ProtectedRoute>
                  <Navbar />
                  <main className="main-content">
                    <Routes>
                      <Route path="/" element={<Navigate to="/dashboard" replace />} />
                      <Route path="/dashboard" element={<Dashboard />} />
                      <Route path="/scanner" element={<Scanner />} />
                      <Route path="/results" element={<Results />} />
                      <Route path="/analytics" element={<Analytics />} />
                      <Route path="/threat-intel" element={<ThreatIntelligence />} />
                      <Route path="/reports" element={<Reports />} />
                      <Route path="/settings" element={<Settings />} />
                      <Route path="/profile" element={<Profile />} />
                    </Routes>
                  </main>
                </ProtectedRoute>
              }
            />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
