"use client";

import { useEffect, useRef } from "react";

// Top-of-page Bloomberg-style telemetry strip. The clock ticks every
// minute via setInterval rather than React state so the rest of the
// landing stays static and free of re-renders.
export function LandingStatusBar() {
  const clockRef = useRef<HTMLSpanElement | null>(null);

  useEffect(() => {
    const fmt = (d: Date) => {
      const pad = (n: number) => n.toString().padStart(2, "0");
      const y = d.getUTCFullYear();
      const mo = pad(d.getUTCMonth() + 1);
      const da = pad(d.getUTCDate());
      const h = pad(d.getUTCHours());
      const mi = pad(d.getUTCMinutes());
      return `${y}-${mo}-${da} · ${h}:${mi} UTC`;
    };
    const update = () => {
      if (clockRef.current) clockRef.current.textContent = fmt(new Date());
    };
    update();
    const id = window.setInterval(update, 30_000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className="flex items-center gap-ds-4 px-ds-6 py-[9px] border-b border-border bg-bg-deep text-[10.5px] text-fg-faint uppercase tracking-[0.08em] flex-wrap">
      <Item>
        <span className="w-[6px] h-[6px] bg-accent animate-pulse-soft" />
        <strong className="text-fg-muted font-medium">SYSTEM READY</strong>
      </Item>
      <Sep />
      <Item>
        MODEL <strong className="text-fg-muted font-medium ml-[6px]">claude-opus-4-7</strong>
      </Item>
      <Sep />
      <Item>
        REGION <strong className="text-fg-muted font-medium ml-[6px]">eu-west-3</strong>
      </Item>
      <Sep />
      <Item>
        UPTIME <strong className="text-fg-muted font-medium ml-[6px]">99.94%</strong>
      </Item>
      <Sep />
      <Item>
        AGENTS <strong className="text-fg-muted font-medium ml-[6px]">5 / idle</strong>
      </Item>
      <span ref={clockRef} className="ml-auto tabular">
        — · — UTC
      </span>
    </div>
  );
}

function Item({ children }: { children: React.ReactNode }) {
  return <span className="inline-flex items-center gap-[6px]">{children}</span>;
}

function Sep() {
  return (
    <span className="text-fg-faint opacity-40" aria-hidden>
      │
    </span>
  );
}
