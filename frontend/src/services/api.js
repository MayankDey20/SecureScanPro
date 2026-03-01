/**
 * API Client for SecureScan Pro with Supabase
 */
import axios from 'axios';
import { supabase } from '../lib/supabase';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

// Create axios instance
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use(
  async (config) => {
    // Get token from Supabase session
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.access_token) {
      config.headers.Authorization = `Bearer ${session.access_token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Token expired, Supabase will auto-refresh
      const { data: { session } } = await supabase.auth.getSession();
      if (session) {
        // Retry with new token
        error.config.headers.Authorization = `Bearer ${session.access_token}`;
        return apiClient.request(error.config);
      } else {
        // No session, redirect to login
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// API Methods
export const scanAPI = {
  start: async (config) => {
    const response = await apiClient.post('/scan/start', config);
    return response.data;
  },
  
  getStatus: async (scanId) => {
    const response = await apiClient.get(`/scan/${scanId}/status`);
    return response.data;
  },
  
  getResults: async (scanId) => {
    const response = await apiClient.get(`/scan/${scanId}/results`);
    return response.data;
  },
  
  startBatch: async (config) => {
    const response = await apiClient.post('/scan/batch', config);
    return response.data;
  },
  
  list: async (skip = 0, limit = 20) => {
    const response = await apiClient.get('/scan', { params: { skip, limit } });
    return response.data;
  },
  
  compare: async (scan1Id, scan2Id) => {
    const response = await apiClient.post('/scan/compare', { scan1: scan1Id, scan2: scan2Id });
    return response.data;
  },
};

export const threatsAPI = {
  list: async (params = {}) => {
    const response = await apiClient.get('/threats', { params });
    return response.data;
  },

  get: async (threatId) => {
    const response = await apiClient.get(`/threats/${threatId}`);
    return response.data;
  },

  sync: async () => {
    const response = await apiClient.post('/threats/sync');
    return response.data;
  },

  getStats: async () => {
    const response = await apiClient.get('/threats/stats/summary');
    return response.data;
  },

  getLast30Days: async () => {
    const response = await apiClient.get('/threats/last30days');
    return response.data;   // { data: [{date, count}] }
  },

  /** Returns an EventSource for real-time new-threat pushes */
  streamUrl: () => {
    const base = import.meta.env.VITE_API_URL || '/api/v1';
    return `${base}/threats/stream`;
  },
};

export const analyticsAPI = {
  getTrends: async (period = '30d') => {
    const response = await apiClient.get('/analytics/trends', { params: { period } });
    return response.data;
  },
};

export const reportsAPI = {
  generate: async (config) => {
    const response = await apiClient.post('/reports/generate', config);
    return response.data;
  },
  
  get: async (reportId) => {
    const response = await apiClient.get(`/reports/${reportId}`);
    return response.data;
  },
};

export const authAPI = {
  login: async (email, password) => {
    const response = await apiClient.post('/auth/login', { email, password });
    return response.data;
  },

  register: async (email, password, full_name) => {
    const response = await apiClient.post('/auth/register', { email, password, full_name });
    return response.data;
  },

  refreshToken: async (refresh_token) => {
    const response = await apiClient.post('/auth/refresh', { refresh_token });
    return response.data;
  },

  getMe: async () => {
    const response = await apiClient.get('/auth/me');
    return response.data;
  },

  // ── WebAuthn / Passkey (Fingerprint) ──
  webauthnRegisterBegin: async (userId) => {
    const response = await apiClient.post('/auth/webauthn/register/begin', { user_id: userId });
    return response.data;
  },
  webauthnRegisterFinish: async (payload) => {
    const response = await apiClient.post('/auth/webauthn/register/finish', payload);
    return response.data;
  },
  webauthnAuthBegin: async (userId) => {
    const response = await apiClient.post('/auth/webauthn/authenticate/begin', { user_id: userId });
    return response.data;
  },
  webauthnAuthFinish: async (payload) => {
    const response = await apiClient.post('/auth/webauthn/authenticate/finish', payload);
    return response.data;
  },
  listPasskeys: async (userId) => {
    const response = await apiClient.get(`/auth/webauthn/credentials/${userId}`);
    return response.data;
  },
  deletePasskey: async (userId, credentialId) => {
    await apiClient.delete(`/auth/webauthn/credentials/${userId}/${credentialId}`);
  },

  // ── PIN ──
  pinSetup: async (userId, pin) => {
    const response = await apiClient.post('/auth/pin/setup', { user_id: userId, pin });
    return response.data;
  },
  pinVerify: async (userId, pin) => {
    const response = await apiClient.post('/auth/pin/verify', { user_id: userId, pin });
    return response.data;
  },
  pinStatus: async (userId) => {
    const response = await apiClient.get(`/auth/pin/status/${userId}`);
    return response.data;
  },
  pinRemove: async (userId) => {
    const response = await apiClient.delete(`/auth/pin/remove/${userId}`);
    return response.data;
  },
  // Resolve user_id from email (used on login screen before a session exists)
  userIdByEmail: async (email) => {
    const response = await apiClient.get('/auth/user-id-by-email', { params: { email } });
    return response.data; // { user_id }
  },
  // Verify email+PIN without a session (login screen)
  pinLoginVerify: async (email, pin) => {
    const response = await apiClient.post('/auth/pin/login', { email, pin });
    return response.data; // { success, user_id, email }
  },
};

export const usersAPI = {
  getProfile: async () => {
    const response = await apiClient.get('/users/me');
    return response.data;
  },
  
  updateProfile: async (data) => {
    const response = await apiClient.put('/users/me', data);
    return response.data;
  },
  
  changePassword: async (current_password, new_password) => {
    const response = await apiClient.post('/users/me/password', {
      current_password,
      new_password,
    });
    return response.data;
  },
  
  getSettings: async () => {
    const response = await apiClient.get('/users/me/settings');
    return response.data;
  },
  
  updateSettings: async (settings) => {
    const response = await apiClient.put('/users/me/settings', settings);
    return response.data;
  },
};

export const aiAPI = {
  analyze: async (title, description, severity) => {
    const response = await apiClient.post('/ai/analyze', { title, description, severity });
    return response.data;
  },
  diagnoseSymptoms: async (symptoms, context = '') => {
    const response = await apiClient.post('/symptom-checker/diagnose', { symptoms, context });
    return response.data;
  },
};

export const integrationsAPI = {
  list: async () => {
    const response = await apiClient.get('/notifications/integrations');
    return response.data;
  },
  create: async (type, name, config) => {
    const response = await apiClient.post('/notifications/integrations', { type, name, config });
    return response.data;
  },
  delete: async (id) => {
    await apiClient.delete(`/notifications/integrations/${id}`);
  },
  test: async (id) => {
    const response = await apiClient.post(`/notifications/integrations/${id}/test`);
    return response.data;
  },
};

export default apiClient;

