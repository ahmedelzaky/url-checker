import { useState, useMemo } from "react";
import { checkUrl, type CheckResult, type Severity } from "@/lib/urlChecker";
import { useVirusTotal } from "@/hooks/useVirusTotal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Search,
  Loader2,
  ExternalLink,
} from "lucide-react";

const severityStyles: Record<Severity, string> = {
  high: "border-destructive/40 bg-destructive/5 text-destructive",
  medium: "border-amber-500/40 bg-amber-500/5 text-amber-600 dark:text-amber-400",
  low: "border-muted-foreground/30 bg-muted/40 text-muted-foreground",
};

function ratingMeta(rating: CheckResult["rating"]) {
  switch (rating) {
    case "Safe":
      return {
        Icon: ShieldCheck,
        color: "text-emerald-500",
        ring: "ring-emerald-500/30",
        bar: "bg-emerald-500",
      };
    case "Likely Safe":
      return { Icon: Shield, color: "text-sky-500", ring: "ring-sky-500/30", bar: "bg-sky-500" };
    case "Suspicious":
      return {
        Icon: ShieldAlert,
        color: "text-amber-500",
        ring: "ring-amber-500/30",
        bar: "bg-amber-500",
      };
    case "Dangerous":
      return {
        Icon: ShieldX,
        color: "text-destructive",
        ring: "ring-destructive/30",
        bar: "bg-destructive",
      };
  }
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "ok" | "warn" | "bad" | "muted";
}) {
  const toneClass =
    tone === "bad"
      ? "text-destructive border-destructive/40 bg-destructive/5"
      : tone === "warn"
        ? "text-amber-600 dark:text-amber-400 border-amber-500/40 bg-amber-500/5"
        : tone === "ok"
          ? "text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/5"
          : "text-muted-foreground border-border bg-muted/40";
  return (
    <div className={`rounded-lg border p-3 text-center ${toneClass}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="mt-1 text-xs uppercase tracking-wide opacity-80">{label}</div>
    </div>
  );
}

export function UrlChecker() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<CheckResult | null>(null);
  const { scan: scanVt, result: vt, loading: vtLoading } = useVirusTotal();

  const onCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    const r = checkUrl(input);
    setResult(r);
    // clear previous VT result
    if (!r.parsed) return;
    await scanVt(r.parsed.full);
  };

  const meta = useMemo(() => (result ? ratingMeta(result.rating) : null), [result]);

  return (
    <div className="mx-auto w-full max-w-3xl px-4 py-12 sm:py-20">
      <div className="text-center">
        <div className="mx-auto mb-5 inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary ring-1 ring-primary/20">
          <Shield className="h-7 w-7" />
        </div>
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">Is this URL safe?</h1>
        <p className="mt-3 text-base text-muted-foreground">
          Paste any link and we'll score it for common phishing and malware red flags.
        </p>
      </div>

      <Card className="mt-8 p-4 sm:p-5">
        <form onSubmit={onCheck} className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="https://example.com/login"
              className="h-12 pl-9 text-base"
              autoFocus
              maxLength={2000}
            />
          </div>
          <Button type="submit" size="lg" className="h-12 px-6">
            Check URL
          </Button>
        </form>
      </Card>

      {result && meta && (
        <div className="mt-8 space-y-6">
          <Card className={`p-6 ring-1 ${meta.ring}`}>
            <div className="flex flex-col items-start gap-6 sm:flex-row sm:items-center">
              <div
                className={`flex h-20 w-20 shrink-0 items-center justify-center rounded-full bg-background ring-4 ${meta.ring}`}
              >
                <meta.Icon className={`h-10 w-10 ${meta.color}`} />
              </div>
              <div className="flex-1">
                <div className="flex items-baseline gap-3">
                  <span className={`text-5xl font-bold ${meta.color}`}>{result.score}</span>
                  <span className="text-lg text-muted-foreground">/ 100</span>
                </div>
                <p className={`mt-1 text-xl font-semibold ${meta.color}`}>{result.rating}</p>
                {result.parsed && (
                  <p className="mt-2 break-all font-mono text-xs text-muted-foreground">
                    {result.parsed.full}
                  </p>
                )}
                <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-muted">
                  <div
                    className={`h-full ${meta.bar} transition-all duration-700`}
                    style={{ width: `${result.score}%` }}
                  />
                </div>
              </div>
            </div>
          </Card>

          {(vtLoading || vt) && (
            <Card className="p-5">
              <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold">
                <Shield className="h-5 w-5 text-primary" />
                VirusTotal scan
              </h2>
              {vtLoading && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Submitting URL to VirusTotal and waiting for analysis…
                </div>
              )}
              {!vtLoading && vt && !vt.ok && <p className="text-sm text-destructive">{vt.error}</p>}
              {!vtLoading && vt && vt.ok && vt.stats && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                    <Stat
                      label="Malicious"
                      value={vt.stats.malicious}
                      tone={vt.stats.malicious > 0 ? "bad" : "ok"}
                    />
                    <Stat
                      label="Suspicious"
                      value={vt.stats.suspicious}
                      tone={vt.stats.suspicious > 0 ? "warn" : "ok"}
                    />
                    <Stat label="Harmless" value={vt.stats.harmless} tone="ok" />
                    <Stat label="Undetected" value={vt.stats.undetected} tone="muted" />
                    <Stat label="Timeout" value={vt.stats.timeout} tone="muted" />
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {vt.stats.malicious + vt.stats.suspicious === 0
                      ? `No engines flagged this URL out of ${vt.totalEngines} checked.`
                      : `${vt.stats.malicious + vt.stats.suspicious} of ${vt.totalEngines} engines flagged this URL.`}
                    {typeof vt.reputation === "number" &&
                      ` Community reputation: ${vt.reputation}.`}
                  </p>
                  {vt.permalink && (
                    <a
                      href={vt.permalink}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline"
                    >
                      View full report on VirusTotal <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  )}
                </div>
              )}
            </Card>
          )}

          {result.issues.length > 0 && (
            <Card className="p-5">
              <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold">
                <AlertTriangle className="h-5 w-5 text-amber-500" />
                Issues found ({result.issues.length})
              </h2>
              <ul className="space-y-3">
                {result.issues.map((issue) => (
                  <li
                    key={issue.id}
                    className={`rounded-lg border p-4 ${severityStyles[issue.severity]}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="font-medium text-foreground">{issue.title}</p>
                        <p className="mt-1 text-sm text-muted-foreground">{issue.description}</p>
                      </div>
                      <span className="shrink-0 rounded-full border border-current/20 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide">
                        {issue.severity}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {result.passed.length > 0 && (
            <Card className="p-5">
              <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold">
                <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                Passed checks ({result.passed.length})
              </h2>
              <ul className="grid gap-2 sm:grid-cols-2">
                {result.passed.map((p) => (
                  <li key={p.id} className="flex items-center gap-2 text-sm text-muted-foreground">
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                    {p.title}
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <p className="text-center text-xs text-muted-foreground">
            This is a heuristic check based on URL structure only. It can't guarantee a site is safe
            or malicious — always use your judgment.
          </p>
        </div>
      )}
    </div>
  );
}
