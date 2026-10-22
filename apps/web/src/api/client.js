/** Axios client with JWT interceptor + refresh rotation. */
import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080/api/v1';

const TOKEN_KEY = 'actilp.access';
const REFRESH_KEY = 'actilp.refresh';
const USER_KEY = 'actilp.user';

export const tokenStore = {
  getAccess: () => localStorage.getItem(TOKEN_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  getUser: () => {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
    } catch {
      return null;
    }
  },
  set: ({ access_token, refresh_token, role }) => {
    localStorage.setItem(TOKEN_KEY, access_token);
    if (refresh_token) localStorage.setItem(REFRESH_KEY, refresh_token);
    localStorage.setItem(USER_KEY, JSON.stringify({ role }));
  },
  clear: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
  },
};

export const api = axios.create({
  baseURL: API_URL,
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = tokenStore.getAccess();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

let refreshing = null;

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config || {};
    const status = error.response?.status;

    if (status === 401 && !original._retry && tokenStore.getRefresh()) {
      original._retry = true;
      try {
        refreshing =
          refreshing ||
          axios.post(`${API_URL}/auth/refresh`, {
            refresh_token: tokenStore.getRefresh(),
          });
        const { data } = await refreshing;
        refreshing = null;
        tokenStore.set(data);
        original.headers.Authorization = `Bearer ${data.access_token}`;
        return api(original);
      } catch (refreshError) {
        refreshing = null;
        tokenStore.clear();
        window.dispatchEvent(new Event('actilp:logout'));
        return Promise.reject(refreshError);
      }
    }
    return Promise.reject(error);
  }
);

/**
 * Turn any axios/FastAPI error into a single renderable string.
 *
 * FastAPI returns several shapes for `detail`:
 *   - 422 validation: [{type, loc, msg, input, ctx}, ...]   ← array of objects
 *   - 401/403/404:    "Incorrect email or password"         ← string
 * Rendering a non-string here crashes React, so always return a string.
 */
export function apiErrorMessage(err) {
  const detail = err?.response?.data?.detail ?? err?.response?.data?.message;

  if (typeof detail === 'string' && detail.trim()) return detail;

  if (Array.isArray(detail)) {
    const messages = detail.map((d) => {
      if (typeof d === 'string') return d;
      if (d && typeof d === 'object') {
        // ["body", "email"] → "body.email"
        const loc = Array.isArray(d.loc) ? d.loc.filter((p) => p !== 'body').join('.') : '';
        const msg = d.msg || d.message || JSON.stringify(d);
        return loc ? `${loc}: ${msg}` : msg;
      }
      return String(d);
    });
    if (messages.length) return messages.join('; ');
  }

  if (detail && typeof detail === 'object') {
    try {
      return JSON.stringify(detail);
    } catch {
      return 'Request failed';
    }
  }

  const status = err?.response?.status;
  if (status === 422) return 'Validation error (422) — check the request body';
  if (status === 401) return 'Invalid credentials';
  if (status === 403) return 'Not allowed';
  if (status === 500) return 'Server error (500)';

  return err?.message || 'Unexpected error';
}

export default api;
