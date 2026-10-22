import { useCallback, useState } from 'react';
import { parseApi } from '../api';
import { apiErrorMessage } from '../api/client';

export function useParse() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const parse = useCallback(async (rawLog, { source = 'dashboard', asyncMode = false } = {}) => {
    setLoading(true);
    setError(null);
    try {
      const res = await parseApi.parse(rawLog, source, asyncMode);
      setResult(res.data);
      return res.data;
    } catch (e) {
      setError(apiErrorMessage(e));
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
  }, []);

  return { result, loading, error, parse, reset };
}
