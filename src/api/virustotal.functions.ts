export interface VirusTotalStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
}

export interface VirusTotalResult {
  ok: boolean;
  error?: string;
  stats?: VirusTotalStats;
  reputation?: number;
  totalEngines?: number;
  permalink?: string;
  scanDate?: string;
}

type VTSubmitResponse = { data?: { id?: string } };
type VTAnalysisAttributes = { status?: string; stats?: Record<string, number>; date?: number };
type VTAnalysisResponse = {
  data?: { attributes?: VTAnalysisAttributes };
};
type VTURLResponse = { data?: { attributes?: { reputation?: number } } };

async function vtFetch(path: string, init?: RequestInit, apiKey?: string) {
  const url = `https://www.virustotal.com/api/v3${path}`;
  const headers: Record<string, string> = { accept: "application/json" };
  if (apiKey) headers["x-apikey"] = apiKey;
  if (init?.headers) Object.assign(headers, init.headers as Record<string, string>);

  return fetch(url, { ...init, headers });
}

export async function scanWithVirusTotal(urlToScan: string): Promise<VirusTotalResult> {
  const apiKey = import.meta.env.VITE_VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { ok: false, error: "VirusTotal API key is not configured." };
  }

  try {
    // 1. Submit URL for analysis
    const submitRes = await vtFetch(
      "/urls",
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `url=${encodeURIComponent(urlToScan)}`,
      },
      apiKey,
    );

    if (!submitRes.ok) {
      const text = await submitRes.text();
      return { ok: false, error: `Submit failed (${submitRes.status}): ${text.slice(0, 200)}` };
    }

    const submitJson = (await submitRes.json()) as VTSubmitResponse;
    const analysisId = submitJson.data?.id;
    if (!analysisId) return { ok: false, error: "No analysis ID returned from VirusTotal." };

    // 2. Poll the analysis (up to ~15s)
    let attributes: VTAnalysisAttributes | undefined = undefined;
    for (let i = 0; i < 6; i++) {
      await new Promise((r) => setTimeout(r, i === 0 ? 1500 : 2500));
      const aRes = await vtFetch(`/analyses/${analysisId}`, { method: "GET" }, apiKey);
      if (!aRes.ok) continue;
      const aJson = (await aRes.json()) as VTAnalysisResponse;
      attributes = aJson.data?.attributes;
      if (attributes?.status === "completed") break;
    }

    if (!attributes) return { ok: false, error: "VirusTotal analysis timed out." };

    const statsRecord = attributes.stats ?? {};
    const totalEngines = Object.values(statsRecord).reduce<number>(
      (s, n) => s + (typeof n === "number" ? n : 0),
      0,
    );

    // 3. Optional: pull reputation from URL object
    let reputation: number | undefined;
    try {
      const urlId = btoa(urlToScan).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
      const uRes = await vtFetch(`/urls/${urlId}`, { method: "GET" }, apiKey);
      if (uRes.ok) {
        const uJson = (await uRes.json()) as VTURLResponse;
        reputation = uJson.data?.attributes?.reputation;
      }
    } catch {
      /* ignore */
    }

    const stats: VirusTotalStats = {
      malicious: statsRecord.malicious ?? 0,
      suspicious: statsRecord.suspicious ?? 0,
      harmless: statsRecord.harmless ?? 0,
      undetected: statsRecord.undetected ?? 0,
      timeout: statsRecord.timeout ?? 0,
    };

    return {
      ok: true,
      stats,
      reputation,
      totalEngines,
      scanDate: attributes.date ? new Date(attributes.date * 1000).toISOString() : undefined,
      permalink: `https://www.virustotal.com/gui/url/${btoa(urlToScan).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")}`,
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Unknown error" };
  }
}
