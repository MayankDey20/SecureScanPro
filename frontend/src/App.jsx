import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
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
import SymptomChecker from './components/SymptomChecker/SymptomChecker';
import Settings from './components/Settings/Settings';
import Profile from './components/Profile/Profile';
import NetworkBackground from './components/Background/NetworkBackground';
import Home from './components/Home/Home';
import './App.css';

function AuthRedirect({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (user) return <Navigate to="/dashboard" replace />;
  return children;
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="app">
          <NetworkBackground />
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<AuthRedirect><Login /></AuthRedirect>} />
            <Route path="/register" element={<AuthRedirect><Register /></AuthRedirect>} />
            <Route
              path="/*"
              element={
                <ProtectedRoute>
                  <Navbar />
                  <main className="main-content">
                    <Routes>
                      <Route path="/dashboard" element={<Dashboard />} />
                      <Route path="/scanner" element={<Scanner />} />
                      <Route path="/results" element={<Results />} />
                      <Route path="/analytics" element={<Analytics />} />
                      <Route path="/threat-intel" element={<ThreatIntelligence />} />
                      <Route path="/reports" element={<Reports />} />
                      <Route path="/symptom-checker" element={<SymptomChecker />} />
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
