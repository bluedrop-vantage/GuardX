import { useEffect, useState } from "react";

/** Minimal data-fetching hook. Doesn't need react-query for M4 first pass. */
export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
): { data: T | null; error: unknown; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetcher()
      .then((v) => { if (!cancelled) setData(v); })
      .catch((e) => { if (!cancelled) setError(e); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, ...deps]);

  return { data, error, loading, refresh: () => setTick((t) => t + 1) };
}
