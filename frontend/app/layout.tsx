import type { Metadata } from "next";
import { Nav } from "@/components/nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "Nexus // Threat surface analyzer",
  description:
    "Multi-agent threat-surface analysis for AI deployments — terminal-grade interface.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Nav />
        <main className="max-w-[1320px] mx-auto px-ds-6 py-ds-6 pb-ds-9">
          {children}
        </main>
        <footer className="max-w-[1320px] mx-auto px-ds-6 py-ds-5 mt-ds-9 border-t border-border flex items-center justify-between text-[10.5px] uppercase tracking-[0.1em] text-fg-faint flex-wrap gap-ds-3">
          <span>{"nexus // threat surface analyzer v0.7.1"}</span>
          <span>jetbrains mono · dark-only · 0 radius</span>
        </footer>
      </body>
    </html>
  );
}
