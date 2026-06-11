"use client";

import { cn } from "@/lib/cn";
import type { StreamState } from "@/lib/use-analyze-stream";
import { isKnownAgent } from "@/lib/schemas";

const AGENT_COLOR: Record<string, string> = {
  planner: "text-agent-planner",
  researcher: "text-agent-researcher",
  analyst: "text-agent-analyst",
  critic: "text-agent-critic",
  writer: "text-agent-writer",
};

const AGENT_BG: Record<string, string> = {
  planner: "bg-agent-planner",
  researcher: "bg-agent-researcher",
  analyst: "bg-agent-analyst",
  critic: "bg-agent-critic",
  writer: "bg-agent-writer",
};

interface Props {
  state: StreamState;
  maxIterations?: number;
}

export function StatsSidebar({ state, maxIterations = 3 }: Props) {
  const active = state.activeAgent && isKnownAgent(state.activeAgent)
    ? state.activeAgent
    : null;

  return (
    <aside className="border border-border bg-bg-card h-fit sticky top-[80px]">
      <header className="px-ds-4 py-ds-3 border-b border-border text-[11px] uppercase tracking-[0.1em] text-fg-muted">
        Live metrics
      </header>

      <div className="px-ds-4 py-ds-4 border-b border-border">
        <div className="text-[10.5px] uppercase tracking-[0.1em] text-fg-faint mb-ds-2">
          Active agent
        </div>
        {active ? (
          <div
            className={cn(
              "text-[16px] font-semibold uppercase tracking-[0.08em] flex items-center gap-ds-3",
              AGENT_COLOR[active],
            )}
          >
            <span
              className={cn(
                "w-2 h-2 animate-pulse-soft",
                AGENT_BG[active],
              )}
            />
            {active}
          </div>
        ) : (
          <div className="text-fg-muted text-[14px]">
            {state.status === "completed" ? "—" : "connecting…"}
          </div>
        )}
      </div>

      <Row
        label="Iteration"
        value={
          <>
            {state.iteration}
            <span className="text-fg-faint text-[12px]">/{maxIterations}</span>
          </>
        }
      />
      <Row label="Plan tasks" value={state.planCount} />
      <Row label="Findings" value={state.findingsCount} />
      <Row label="Surfaces" value={state.surfacesCount} />
      <Row
        label="Critic score"
        value={
          state.criticScore !== null ? state.criticScore.toFixed(2) : "—"
        }
        accent={state.criticScore !== null}
      />
      <Row label="Events" value={state.events.length} />

      <div className="px-ds-4 py-ds-3 border-t border-border flex items-baseline justify-between">
        <span className="text-[10.5px] uppercase tracking-[0.08em] text-fg-faint">
          Status
        </span>
        <span
          className={cn(
            "text-[11px] uppercase tracking-[0.1em] font-medium",
            state.status === "completed" && "text-agent-writer",
            state.status === "error" && "text-sev-critical",
            state.status === "streaming" && "text-accent",
            state.status === "connecting" && "text-fg-muted",
          )}
        >
          {state.status}
        </span>
      </div>
    </aside>
  );
}

function Row({
  label,
  value,
  accent,
}: {
  label: string;
  value: React.ReactNode;
  accent?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between px-ds-4 py-ds-3 border-b border-border">
      <span className="text-[10.5px] uppercase tracking-[0.08em] text-fg-faint">
        {label}
      </span>
      <span
        className={cn(
          "text-[15px] tabular font-medium",
          accent ? "text-accent" : "text-fg",
        )}
      >
        {value}
      </span>
    </div>
  );
}
