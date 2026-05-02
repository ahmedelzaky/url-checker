import type { VercelRequest, VercelResponse } from "@vercel/node";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Only allow POST requests
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { urlToScan } = req.body;
  if (!urlToScan) {
    return res.status(400).json({ error: "URL to scan is required" });
  }

  const apiKey = process.env.VITE_VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: "VirusTotal API key is not configured on the server." });
  }

  const vtFetch = async (path: string, init?: RequestInit) => {
    const url = `https://www.virustotal.com/api/v3${path}`;
    const headers: Record<string, string> = {
      accept: "application/json",
      "x-apikey": apiKey,
    };
    if (init?.headers) Object.assign(headers, init.headers as Record<string, string>);
    return fetch(url, { ...init, headers });
  };

  try {
    // 1. Submit URL for analysis
    const submitRes = await vtFetch("/urls", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(urlToScan)}`,
    });

    if (!submitRes.ok) {
      const text = await submitRes.text();
      return res.status(submitRes.status).json({ error: `Submit failed: ${text.slice(0, 200)}` });
    }

    const submitJson = await submitRes.json();
    const analysisId = submitJson.data?.id;
    if (!analysisId) {
      return res.status(500).json({ error: "No analysis ID returned from VirusTotal." });
    }

    // 2. Poll the analysis (limited to fit Vercel timeout)
    let attributes: any = undefined;
    // Vercel free has a 10s timeout, so we poll fewer times or with shorter delays
    for (let i = 0; i < 3; i++) {
      await new Promise((r) => setTimeout(r, i === 0 ? 1000 : 2000));
      const aRes = await vtFetch(`/analyses/${analysisId}`, { method: "GET" });
      if (!aRes.ok) continue;
      const aJson = await aRes.json();
      attributes = aJson.data?.attributes;
      if (attributes?.status === "completed") break;
    }

    if (!attributes || attributes.status !== "completed") {
      // If still not completed, we'll return what we have or a "processing" state
      // but for simplicity, let's try to get the existing URL object if it exists
    }

    const statsRecord = attributes?.stats ?? {};

    // 3. Pull reputation from URL object
    let reputation: number | undefined;
    try {
      const urlId = Buffer.from(urlToScan)
        .toString("base64")
        .replace(/=+$/, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
      const uRes = await vtFetch(`/urls/${urlId}`, { method: "GET" });
      if (uRes.ok) {
        const uJson = await uRes.json();
        reputation = uJson.data?.attributes?.reputation;
        // If we didn't get stats from analysis yet, use them from the URL object
        if (!attributes) {
          attributes = uJson.data?.attributes;
        }
      }
    } catch {
      /* ignore */
    }

    const stats = {
      malicious: statsRecord.malicious ?? 0,
      suspicious: statsRecord.suspicious ?? 0,
      harmless: statsRecord.harmless ?? 0,
      undetected: statsRecord.undetected ?? 0,
      timeout: statsRecord.timeout ?? 0,
    };

    return res.status(200).json({
      ok: true,
      stats,
      reputation,
      totalEngines: Object.values(stats).reduce((a: number, b: number) => a + b, 0),
      scanDate: attributes?.date
        ? new Date(attributes.date * 1000).toISOString()
        : new Date().toISOString(),
      permalink: `https://www.virustotal.com/gui/url/${Buffer.from(urlToScan).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")}`,
    });
  } catch (err) {
    return res.status(500).json({ error: err instanceof Error ? err.message : "Unknown error" });
  }
}
