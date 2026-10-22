import { create } from 'zustand';
import api, { apiErrorMessage, tokenStore } from '../api/client';

const stored = tokenStore.getUser();

export const useAuthStore = create((set) => ({
  user: stored,
  token: tokenStore.getAccess(),
  loading: false,
  error: null,

  login: async (email, password) => {
    set({ loading: true, error: null });
    try {
      const { data } = await api.post('/auth/login/json', { email, password });
      tokenStore.set(data);

      // Validate the new token immediately; if /auth/me fails the session is
      // unusable, so drop it instead of leaving a poisoned token in storage.
      let me;
      try {
        me = await api.get('/auth/me');
      } catch (meErr) {
        tokenStore.clear();
        throw meErr;
      }

      const user = { ...me.data, role: data.role };
      localStorage.setItem('actilp.user', JSON.stringify(user));
      set({ token: data.access_token, user, loading: false });
      return user;
    } catch (err) {
      tokenStore.clear();
      set({ loading: false, token: null, user: null, error: apiErrorMessage(err) });
      throw err;
    }
  },

  logout: () => {
    tokenStore.clear();
    set({ user: null, token: null, error: null });
  },

  hasRole: (...roles) => {
    const current = tokenStore.getUser();
    return !!current && roles.includes(current.role);
  },
}));
