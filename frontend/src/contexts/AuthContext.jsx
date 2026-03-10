/**
 * AuthContext — native JWT auth via SecureScan Pro backend API.
 * No Supabase dependency.
 */
import { createContext, useContext, useState, useEffect, useCallback } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

const AuthContext = createContext(null);

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
};

// ── Token helpers ──────────────────────────────────────────────────────────
const TOKEN_KEY = 'ssp_access_token';
const REFRESH_KEY = 'ssp_refresh_token';

export const getAccessToken = () => localStorage.getItem(TOKEN_KEY);
const setTokens = (access, refresh) => {
  localStorage.setItem(TOKEN_KEY, access);
  if (refresh) localStorage.setItem(REFRESH_KEY, refresh);
};
const clearTokens = () => {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
};

async function apiPost(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Request failed');
  return data;
}

async function apiGet(path, token) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Request failed');
  return data;
}

// ── Provider ───────────────────────────────────────────────────────────────
export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadUser = useCallback(async (token) => {
    if (!token) { setLoading(false); return; }
    try {
      const profile = await apiGet('/users/me', token);
      setUser(profile);
    } catch {
      clearTokens();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // On mount: restore session from localStorage
  useEffect(() => {
    const token = getAccessToken();
    loadUser(token);
  }, [loadUser]);

  const login = async (email, password) => {
    const data = await apiPost('/auth/login', { email, password });
    setTokens(data.access_token, data.refresh_token);
    setUser(data.user);
    return data;
  };

  const register = async (email, password, fullName) => {
    const data = await apiPost('/auth/register', { email, password, full_name: fullName });
    setTokens(data.access_token, data.refresh_token);
    setUser(data.user);
    return data;
  };

  const logout = () => {
    clearTokens();
    setUser(null);
  };

  const updateUser = async (userData) => {
    const token = getAccessToken();
    const res = await fetch(`${API_BASE}/users/me`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(userData),
    });
    const updated = await res.json();
    if (!res.ok) throw new Error(updated.detail || 'Update failed');
    setUser(updated);
    return updated;
  };

  // Fake session object so legacy code that reads session?.access_token still works
  const session = user ? { access_token: getAccessToken(), user } : null;

  return (
    <AuthContext.Provider value={{ user, session, loading, login, register, logout, updateUser, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  );
};
