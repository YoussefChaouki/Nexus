"use client";

import Link from "next/link";
import { NexusGlyph } from "@/components/brand/glyph";

const SECTIONS = [
  { href: "#what", label: "what" },
  { href: "#agents", label: "agents" },
  { href: "#live", label: "live" },
  { href: "#metrics", label: "metrics" },
  { href: "#stack", label: "stack" },
] as const;

export function LandingNav() {
  return (
    <nav className="sticky top-0 z-50 bg-bg/85 backdrop-blur-md border-b border-border">
      <div className="px-ds-6 py-ds-3 flex items-center gap-ds-6 flex-wrap">
        <Link
          href="#top"
          className="flex items-center gap-ds-3 text-[12px] uppercase tracking-[0.08em] font-semibold"
        >
          <NexusGlyph variant="compact" size={22} />
          <span className="w-[6px] h-[6px] bg-accent animate-pulse-soft" aria-hidden />
          <span className="text-accent">nexus</span>
          <span className="text-fg-faint ml-1 font-normal">{"// v0.7.1"}</span>
        </Link>
        <div className="flex gap-1 ml-auto flex-wrap">
          {SECTIONS.map((s) => (
            <a
              key={s.href}
              href={s.href}
              className="px-[11px] py-[5px] border border-transparent text-fg-muted text-[10.5px] uppercase tracking-[0.1em] transition-colors duration-100 hover:text-fg hover:border-border hover:bg-bg-elev"
            >
              {s.label}
            </a>
          ))}
          <Link
            href="/analyze"
            className="px-[11px] py-[5px] border border-accent text-accent text-[10.5px] uppercase tracking-[0.12em] font-semibold bg-accent/[0.06] transition-colors duration-100 hover:bg-accent hover:text-bg"
          >
            ▶ run analysis
          </Link>
        </div>
      </div>
    </nav>
  );
}
