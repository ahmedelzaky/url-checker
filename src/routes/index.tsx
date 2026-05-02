import { createFileRoute } from "@tanstack/react-router";
import { UrlChecker } from "@/components/UrlChecker";

export const Route = createFileRoute("/")({
  component: Index,
});

function Index() {
  return (
    <main className="min-h-screen bg-background">
      <UrlChecker />
    </main>
  );
}
