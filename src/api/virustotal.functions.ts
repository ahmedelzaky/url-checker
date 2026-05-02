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

export async function scanWithVirusTotal(urlToScan: string): Promise<VirusTotalResult> {
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ urlToScan }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      return { ok: false, error: errorData.error || `Server error: ${response.status}` };
    }

    return await response.json();
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Unknown error" };
  }
}
