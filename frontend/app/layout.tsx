import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Nexus // Multi-agent threat-surface analyzer",
  description:
    "Describe an AI architecture in plain language. Five specialized agents research, synthesize, criticize, and ship a structured ThreatReport in under sixty seconds.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
