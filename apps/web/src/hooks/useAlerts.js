import { useCallback, useEffect, useState } from 'react';
import api, { apiErrorMessage } from '../api/client';

export function useAlerts(params = {}) {
  const [data, setData] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const key = JSON.stringify(params);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/alerts', { params });
      setData(res.data.items || []);
      setTotal(res.data.total || 0);
      setError(null);
    } catch (e) {
      setError(apiErrorMessage(e));
    } finally {
      setLoading(false);
    }
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const acknowledge = useCallback(
    async (id) => {
      await api.post(`/alerts/${id}/acknowledge`);
      await fetchAlerts();
    },
    [fetchAlerts]
  );

  const close = useCallback(
    async (id) => {
      await api.post(`/alerts/${id}/close`);
      await fetchAlerts();
    },
    [fetchAlerts]
  );

  return { data, total, loading, error, refresh: fetchAlerts, acknowledge, close };
}
