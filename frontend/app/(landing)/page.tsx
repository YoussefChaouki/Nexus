import { AmbientBackground } from "@/components/landing/ambient-background";
import { LandingNav } from "@/components/landing/landing-nav";
import { LandingStatusBar } from "@/components/landing/status-bar";
import { LandingHero } from "@/components/landing/hero";
import { WhatItDoes } from "@/components/landing/what-it-does";
import { AgentsConstellation } from "@/components/landing/agents-constellation";
import { LiveFeedSample } from "@/components/landing/live-feed-sample";
import { Numbers } from "@/components/landing/numbers";
import { BuiltOn } from "@/components/landing/built-on";
import { CtaStrip } from "@/components/landing/cta-strip";
import { LandingFooter } from "@/components/landing/landing-footer";

// Marketing-shaped landing for nexus.
// The actual product UI lives at /analyze (prompt input), /runs/[id]
// (live SSE), /reports/[id] (report viewer) and /history.
export default function LandingPage() {
  return (
    <>
      <AmbientBackground />
      <div className="relative z-10 max-w-[1320px] mx-auto min-h-screen border-l border-r border-border">
        <LandingNav />
        <LandingStatusBar />
        <LandingHero />
        <WhatItDoes />
        <AgentsConstellation />
        <LiveFeedSample />
        <Numbers />
        <BuiltOn />
        <CtaStrip />
        <LandingFooter />
      </div>
    </>
  );
}
