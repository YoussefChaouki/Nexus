"use client";

import { useState } from "react";
import { cn } from "@/lib/cn";

interface SurfaceListProps {
  vectors: string[];
}

// The persisted summary doesn't keep per-surface detail — we render the
// top attack vectors as ranked, collapsible rows. When the backend gains
// a full-report endpoint, this component can be swapped to render the
// real ThreatSurface[] (description / evidence / mitigations).
export function SurfaceList({ vectors }: SurfaceListProps) {
  const [open, setOpen] = useState<number | null>(0);
  if (vectors.length === 0) {
    return (
      <div className="border border-border bg-bg-card px-ds-5 py-ds-5 text-fg-faint text-[12px] uppercase tracking-[0.1em]">
        no attack vectors recorded
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-[10px]">
      {vectors.map((vec, i) => {
        const isOpen = open === i;
        return (
          <article key={`${i}-${vec}`} className="border border-border bg-bg-card">
            <button
              type="button"
              onClick={() => setOpen(isOpen ? null : i)}
              className="w-full flex items-center gap-ds-4 px-ds-5 py-ds-4 flex-wrap text-left hover:bg-white/[0.01]"
            >
              <span className="text-[11px] text-fg-faint tracking-[0.1em] tabular font-medium min-w-[40px]">
                V/{(i + 1).toString().padStart(2, "0")}
              </span>
              <span className="flex-1 text-fg text-[14px] font-medium min-w-[200px]">
                {vec}
              </span>
              <span
                className={cn(
                  "text-fg-faint text-[14px] transition-transform duration-200",
                  isOpen && "rotate-90",
                )}
                aria-hidden
              >
                ▸
              </span>
            </button>
            {isOpen && (
              <div className="px-ds-5 pl-[76px] pb-ds-5 pt-0 border-t border-border">
                <Section label="─ vector">
                  <code className="text-accent text-[13px] break-all">{vec}</code>
                </Section>
                <Section label="─ note">
                  <p className="text-fg-muted text-[13px] leading-[1.7] m-0">
                    Surface detail (description, full evidence list, mitigations)
                    is captured in the live ThreatReport but not persisted into
                    episodic memory by design — episodic stores only a{" "}
                    <em className="not-italic text-accent">ThreatReportSummary</em>.
                    Open the Langfuse trace below for the full agent transcript
                    and original evidence URLs.
                  </p>
                </Section>
              </div>
            )}
          </article>
        );
      })}
    </div>
  );
}

function Section({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mt-ds-5">
      <div className="text-[10.5px] uppercase tracking-[0.14em] text-fg-faint mb-ds-2">
        {label}
      </div>
      {children}
    </div>
  );
}
