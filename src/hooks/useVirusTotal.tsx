import { useCallback, useState } from "react";
import { scanWithVirusTotal, type VirusTotalResult } from "@/api/virustotal.functions";

export function useVirusTotal() {
  const [result, setResult] = useState<VirusTotalResult | null>(null);
  const [loading, setLoading] = useState(false);

  const scan = useCallback(async (url: string) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await scanWithVirusTotal(url);
      setResult(res);
      return res;
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      const r: VirusTotalResult = { ok: false, error };
      setResult(r);
      return r;
    } finally {
      setLoading(false);
    }
  }, []);

  return { scan, result, loading } as const;
}
