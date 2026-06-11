"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { useAnalyzeStream } from "@/lib/use-analyze-stream";
import { Pill } from "@/components/ui/pill";
import { StatusBar, StatusItem, StatusSep } from "@/components/ui/status-bar";
import { EventRow } from "./event-row";
import { PipelineRail } from "./pipeline-rail";
import { StatsSidebar } from "./stats-sidebar";
import { formatElapsed } from "@/lib/format";

interface Props {
  sessionId: string;
  target: string;
}

export function LiveFeed({ sessionId, target }: Props) {
  const state = useAnalyzeStream(target, sessionId);
  const router = useRouter();
  const feedRef = useRef<HTMLDivElement | null>(null);
  const elapsedRef = useRef<HTMLSpanElement | null>(null);
  const lastStartedRef = useRef<number>(Date.now());

  // Live elapsed clock — bypasses React rerenders to avoid burning a
  // setState per animation frame.
  useEffect(() => {
    if (state.startedAt) lastStartedRef.current = state.startedAt;
    const id = window.setInterval(() => {
      if (!elapsedRef.current) return;
      elapsedRef.current.textContent = formatElapsed(
        Date.now() - lastStartedRef.current,
      );
    }, 50);
    return () => window.clearInterval(id);
  }, [state.startedAt]);

  // Autoscroll the feed as events stream in.
  useEffect(() => {
    if (!feedRef.current) return;
    feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [state.events.length]);

  // Navigate to the report viewer when complete.
  useEffect(() => {
    if (state.status === "completed" && state.reportId) {
      const t = window.setTimeout(() => {
        router.push(`/reports/${state.reportId}`);
      }, 1200);
      return () => window.clearTimeout(t);
    }
  }, [state.status, state.reportId, router]);

  const pillTone =
    state.status === "completed"
      ? "complete"
      : state.status === "error"
        ? "live"
        : state.status === "connecting"
          ? "warn"
          : "live";
  const pillLabel = state.status === "connecting" ? "Connecting" : state.status;

  return (
    <>
      <StatusBar>
        <Pill tone={pillTone} pulse={state.status === "streaming"}>
          {pillLabel}
        </Pill>
        <StatusSep />
        <span className="inline-flex items-baseline gap-ds-2">
          <span className="uppercase tracking-[0.1em] text-fg-faint">Elapsed</span>
          <span ref={elapsedRef} className="text-fg font-medium tabular">
            00:00.00
          </span>
        </span>
        <StatusSep />
        <StatusItem label="Iter">
          <span className="tabular">{state.iteration}/3</span>
        </StatusItem>
        <StatusSep />
        <StatusItem label="Active">
          {state.activeAgent ?? "—"}
        </StatusItem>
        <span className="ml-auto">
          <StatusItem label="Events">
            <span className="tabular">{state.events.length}</span>
          </StatusItem>
        </span>
      </StatusBar>

      <PipelineRail state={state} />

      <div className="mt-ds-4 grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-ds-4">
        <section className="border border-border bg-bg-card min-h-[600px] flex flex-col">
          <header className="flex items-center justify-between gap-ds-2 px-ds-5 py-ds-3 border-b border-border text-[11px] uppercase tracking-[0.1em] text-fg-muted flex-wrap">
            <span className="text-fg flex items-center gap-ds-2">
              <span className="w-2 h-2 bg-sev-critical animate-pulse-soft" />
              Agent timeline · live
            </span>
            <span className="text-fg-faint text-[10.5px]">
              session {sessionId.slice(0, 8)}
            </span>
          </header>
          <div className="px-ds-5 py-ds-3 border-b border-border bg-bg-deep text-[12.5px] text-fg-muted">
            <span className="text-fg-faint tracking-[0.1em] text-[10.5px] mr-ds-2">
              TARGET
            </span>
            {target}
          </div>
          <div
            ref={feedRef}
            className="flex-1 py-ds-4 overflow-y-auto max-h-[600px]"
          >
            {state.events.length === 0 && (
              <div className="px-ds-5 py-ds-5 text-fg-faint text-[12px] uppercase tracking-[0.1em]">
                waiting for first event…
              </div>
            )}
            {state.events.map((ev, i) => (
              <EventRow
                key={`${ev.timestamp}-${i}`}
                event={ev}
                startedAt={state.startedAt ?? Date.now()}
                isLast={i === state.events.length - 1}
              />
            ))}
            {state.status === "error" && (
              <div className="px-ds-5 py-ds-4 text-sev-critical text-[12.5px]">
                stream failed{state.error ? ` — ${state.error}` : ""}
              </div>
            )}
          </div>
        </section>

        <StatsSidebar state={state} />
      </div>
    </>
  );
}
