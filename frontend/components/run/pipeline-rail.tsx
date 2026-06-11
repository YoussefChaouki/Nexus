"use client";

import { cn } from "@/lib/cn";
import type { StreamState } from "@/lib/use-analyze-stream";
import { isKnownAgent, type AgentName } from "@/lib/schemas";

const ORDER: AgentName[] = ["planner", "researcher", "analyst", "critic", "writer"];

const SHORT: Record<AgentName, string> = {
  planner: "PLN",
  researcher: "RES",
  analyst: "ANL",
  critic: "CRT",
  writer: "WRT",
};

const TEXT: Record<AgentName, string> = {
  planner: "text-agent-planner",
  researcher: "text-agent-researcher",
  analyst: "text-agent-analyst",
  critic: "text-agent-critic",
  writer: "text-agent-writer",
};

const DOT: Record<AgentName, string> = {
  planner: "bg-agent-planner",
  researcher: "bg-agent-researcher",
  analyst: "bg-agent-analyst",
  critic: "bg-agent-critic",
  writer: "bg-agent-writer",
};

type NodePhase = "done" | "active" | "pending" | "error";

interface RailModel {
  phases: Record<AgentName, NodePhase>;
  /** Index of the currently active node, -1 when none (completed). */
  activeIdx: number;
  /** True while the critic has sent the flow back to the researcher. */
  looping: boolean;
}

/**
 * Derive node phases from the stream. `activeAgent` is the *last
 * completed* node, so the active one is its successor — unless the last
 * critic verdict was re_research, in which case flow loops back to the
 * researcher and the analysis pass restarts.
 */
function deriveRail(state: StreamState): RailModel {
  const phases = Object.fromEntries(
    ORDER.map((a) => [a, "pending" as NodePhase]),
  ) as Record<AgentName, NodePhase>;

  if (state.status === "completed") {
    for (const a of ORDER) phases[a] = "done";
    return { phases, activeIdx: -1, looping: false };
  }

  const last = state.activeAgent && isKnownAgent(state.activeAgent)
    ? state.activeAgent
    : null;
  const lastIdx = last ? ORDER.indexOf(last) : -1;

  const lastCritic = [...state.events]
    .reverse()
    .find((e) => e.agent === "critic" && e.event_type === "node_completed");
  const looping =
    last === "critic" &&
    lastCritic?.payload["critic_recommendation"] === "re_research";

  let activeIdx: number;
  if (looping) {
    // Critic kicked the flow back: planner stays done, the analysis
    // trio re-arms for the next pass.
    phases.planner = "done";
    activeIdx = ORDER.indexOf("researcher");
  } else {
    ORDER.slice(0, lastIdx + 1).forEach((a) => {
      phases[a] = "done";
    });
    activeIdx = Math.min(lastIdx + 1, ORDER.length - 1);
  }

  const activeAgent = ORDER[activeIdx];
  if (activeAgent) phases[activeAgent] = state.status === "error" ? "error" : "active";
  return { phases, activeIdx, looping };
}

export function PipelineRail({ state }: { state: StreamState }) {
  const { phases, activeIdx, looping } = deriveRail(state);
  const pass = Math.max(1, state.iteration + (looping ? 1 : 0));
  const showLoop = looping || state.iteration > 1;

  return (
    <section
      aria-label="Pipeline progress"
      className="mt-ds-4 border border-border bg-bg-card px-ds-5 pt-ds-4 pb-ds-3 overflow-x-auto"
    >
      <div className="flex items-center min-w-[560px]">
        {ORDER.map((agent, i) => (
          <div key={agent} className={cn("flex items-center", i < ORDER.length - 1 && "flex-1")}>
            <RailNode agent={agent} phase={phases[agent]} />
            {i < ORDER.length - 1 && (
              <Connector
                flowing={state.status === "streaming" && i === activeIdx - 1}
                done={phases[ORDER[i + 1] as AgentName] === "done" || i + 1 < activeIdx}
              />
            )}
          </div>
        ))}
      </div>

      {/* Feedback loop indicator: critic → researcher. */}
      <div
        className={cn(
          "mt-ds-2 flex items-center gap-ds-2 text-[10px] uppercase tracking-[0.12em]",
          "transition-opacity duration-300",
          showLoop ? "opacity-100" : "opacity-0",
        )}
        aria-hidden={!showLoop}
      >
        <span className="text-agent-critic">↺</span>
        <span className="flex-1 h-px bg-gradient-to-r from-agent-critic/50 via-border-emph to-agent-researcher/50" />
        <span className="text-fg-muted">
          re-research · pass <span className="tabular text-fg">{pass}</span>
          <span className="text-fg-faint">/3</span>
        </span>
      </div>
    </section>
  );
}

function RailNode({ agent, phase }: { agent: AgentName; phase: NodePhase }) {
  return (
    <div
      className={cn(
        "flex items-center gap-ds-2 px-[10px] py-[6px] border shrink-0",
        "text-[10.5px] uppercase tracking-[0.12em] font-semibold transition-colors duration-300",
        phase === "done" && cn(TEXT[agent], "border-border-emph bg-bg-deep"),
        phase === "active" && cn(TEXT[agent], "border-current bg-current/[0.07]"),
        phase === "pending" && "text-fg-faint border-border",
        phase === "error" && "text-sev-critical border-sev-critical bg-sev-critical/[0.07]",
      )}
      aria-label={`${agent}: ${phase}`}
    >
      {phase === "done" ? (
        <span aria-hidden className="text-[9px] leading-none">✓</span>
      ) : (
        <span
          aria-hidden
          className={cn(
            "w-[6px] h-[6px] shrink-0",
            phase === "active" && cn(DOT[agent], "animate-pulse-soft"),
            phase === "pending" && "bg-fg-faint/40",
            phase === "error" && "bg-sev-critical animate-pulse-soft",
          )}
        />
      )}
      <span className="hidden sm:inline">{agent}</span>
      <span className="sm:hidden">{SHORT[agent]}</span>
    </div>
  );
}

function Connector({ flowing, done }: { flowing: boolean; done: boolean }) {
  return (
    <span
      aria-hidden
      className={cn(
        "flex-1 h-px mx-ds-2 min-w-[16px]",
        done && "bg-border-emph",
        !done && !flowing && "bg-border",
        flowing &&
          "h-[2px] animate-rail-flow bg-[repeating-linear-gradient(90deg,var(--accent)_0_6px,transparent_6px_16px)] opacity-70",
      )}
    />
  );
}
