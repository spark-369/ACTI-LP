import api from './client';

// Strip the "/api/v1" suffix so root-level endpoints (/healthz) resolve.
// e.g. http://localhost:8080/api/v1 → http://localhost:8080
const API_ORIGIN = (import.meta.env.VITE_API_URL || 'http://localhost:8080/api/v1').replace(
  /\/api\/v1\/?$/,
  ''
);

export const authApi = {
  login: (email, password) => api.post('/auth/login/json', { email, password }),
  me: () => api.get('/auth/me'),
};

export const alertsApi = {
  list: (params = {}) => api.get('/alerts', { params }),
  get: (id) => api.get(`/alerts/${id}`),
  acknowledge: (id) => api.post(`/alerts/${id}/acknowledge`),
  close: (id) => api.post(`/alerts/${id}/close`),
};

export const parseApi = {
  parse: (rawLog, source = 'dashboard', asyncMode = false) =>
    api.post('/parse', { raw_log: rawLog, source, async_mode: asyncMode }),
  batch: (logs, source = 'batch') => api.post('/parse/batch', { logs, source }),
  context: (q, limit = 5) => api.get('/parse/context', { params: { q, limit } }),
};

export const dashboardApi = {
  stats: (days = 7) => api.get('/dashboard/stats', { params: { days } }),
};

export const usersApi = {
  list: () => api.get('/users'),
  create: (payload) => api.post('/users', payload),
  deactivate: (id) => api.delete(`/users/${id}`),
};

export const auditApi = {
  list: (params = {}) => api.get('/audit', { params }),
};

export const systemApi = {
  // /healthz is mounted on the app root, NOT under /api/v1 (see app/main.py).
  // Calling it through `api` (baseURL = .../api/v1) requested
  // /api/v1/healthz, which 404s — the sidebar therefore always rendered
  // "Degraded". Override baseURL for this one call.
  health: () => api.get('/healthz', { baseURL: API_ORIGIN }),
};
