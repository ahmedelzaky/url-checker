import { createFileRoute } from "@tanstack/react-router";
import { UrlChecker } from "@/components/UrlChecker";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "URL Safety Checker — Detect Suspicious Links" },
      {
        name: "description",
        content:
          "Paste any URL to instantly score it for phishing and malware red flags like missing HTTPS, suspicious subdomains, and brand impersonation.",
      },
    ],
  }),
  component: Index,
});

function Index() {
  return (
    <main className="min-h-screen bg-background">
      <UrlChecker />
    </main>
  );
}
