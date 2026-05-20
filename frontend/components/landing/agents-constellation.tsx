import { Section } from "./section-shell";
import { cn } from "@/lib/cn";

interface Agent {
  idx: string;
  name: string;
  role: string;
  desc: string;
  color: string;       // text token class
  bgColor: string;     // bg token class (for the pipe blip)
  io: { l: string; v: string }[];
}

const AGENTS: Agent[] = [
  {
    idx: "01",
    name: "Planner",
    role: "Decomposition",
    desc: "Breaks any target description into 4–6 ResearchTasks across distinct FocusAreas.",
    color: "text-agent-planner",
    bgColor: "bg-agent-planner",
    io: [
      { l: "IN", v: "target_description" },
      { l: "OUT", v: "ResearchTask[ ]" },
      { l: "MEM", v: "episodic · cos >0.85" },
    ],
  },
  {
    idx: "02",
    name: "Researcher",
    role: "Evidence gathering",
    desc: "Queries arXiv, NVD, and MITRE ATLAS MCP servers in parallel. Dedupes & scores.",
    color: "text-agent-researcher",
    bgColor: "bg-agent-researcher",
    io: [
      { l: "IN", v: "ResearchTask[ ]" },
      { l: "OUT", v: "FindingResult[ ]" },
      { l: "MCP", v: "arxiv · nvd · atlas" },
    ],
  },
  {
    idx: "03",
    name: "Analyst",
    role: "Synthesis",
    desc: "Groups findings by focus area, augments with semantic patterns, emits ThreatSurfaces.",
    color: "text-agent-analyst",
    bgColor: "bg-agent-analyst",
    io: [
      { l: "IN", v: "FindingResult[ ]" },
      { l: "OUT", v: "ThreatSurface[ ]" },
      { l: "MEM", v: "semantic patterns" },
    ],
  },
  {
    idx: "04",
    name: "Critic",
    role: "Validation",
    desc: "Scores coverage against OWASP LLM Top 10 + ATLAS tactics. Triggers re-research or approves.",
    color: "text-agent-critic",
    bgColor: "bg-agent-critic",
    io: [
      { l: "IN", v: "ThreatSurface[ ]" },
      { l: "OUT", v: "CriticReport" },
      { l: "MAX", v: "3 iterations" },
    ],
  },
  {
    idx: "05",
    name: "Writer",
    role: "Assembly",
    desc: "Composes the final ThreatReport, validates Pydantic schema, persists to episodic memory.",
    color: "text-agent-writer",
    bgColor: "bg-agent-writer",
    io: [
      { l: "IN", v: "all state" },
      { l: "OUT", v: "ThreatReport" },
      { l: "PERS", v: "pgvector · langfuse" },
    ],
  },
];

const BLIP_DELAYS = ["0s", "0.9s", "1.8s", "2.7s", "3.6s"] as const;

export function AgentsConstellation() {
  return (
    <Section
      id="agents"
      num="02"
      title="Five agents, one report"
      meta="langgraph state machine · feedback loop"
    >
      <div className="border border-border bg-bg-card">
        {/* Terminal-bar style header */}
        <header className="flex items-center gap-ds-3 px-ds-4 py-[10px] border-b border-border bg-bg-deep text-[10.5px] uppercase tracking-[0.12em] text-fg-muted">
          <span className="inline-flex gap-[5px] mr-1">
            <span className="w-2 h-2 bg-sev-critical/70" />
            <span className="w-2 h-2 bg-sev-high/70" />
            <span className="w-2 h-2 bg-sev-low/70" />
          </span>
          <span className="text-fg font-medium">agents · /v1/pipeline</span>
          <span className="ml-auto text-fg-faint">redis · pgvector · langfuse</span>
        </header>

        {/* 5 agent cells */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 border-b border-border">
          {AGENTS.map((a, i) => (
            <div
              key={a.name}
              className={cn(
                "p-ds-5 border-border relative overflow-hidden transition-colors duration-200 hover:bg-bg-elev",
                i < AGENTS.length - 1 && "lg:border-r",
                i % 2 === 0 && i !== AGENTS.length - 1 && "sm:border-r lg:border-r",
                "border-b sm:border-b lg:border-b-0",
              )}
            >
              <div className="text-[10.5px] text-fg-faint tracking-[0.16em] mb-[14px]">
                {a.idx}
              </div>
              <div
                className={cn(
                  "text-[16px] font-semibold uppercase tracking-[0.08em] flex items-center gap-ds-2 mb-[10px]",
                  a.color,
                )}
              >
                <span className={cn("w-2 h-2", a.bgColor)} aria-hidden />
                {a.name}
              </div>
              <div className="text-[10.5px] uppercase tracking-[0.12em] text-fg-faint mb-ds-4">
                {a.role}
              </div>
              <p className="text-[12.5px] text-fg-muted leading-[1.7] m-0 mb-ds-4">
                {a.desc}
              </p>
              <div className="flex flex-col gap-[6px] text-[11px] text-fg-faint border-t border-dashed border-border pt-[14px] tracking-[0.04em]">
                {a.io.map((row) => (
                  <span key={row.l} className="flex gap-ds-2">
                    <span className="text-fg-faint min-w-[28px]">{row.l}</span>
                    <span className="text-fg-muted">{row.v}</span>
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Animated pipeline — one blip per agent, staggered */}
        <div
          className="grid grid-cols-5 h-[36px] bg-bg-deep"
          aria-hidden
        >
          {AGENTS.map((a, i) => (
            <div
              key={i}
              className={cn(
                "relative overflow-hidden",
                i < 4 && "border-r border-border",
              )}
            >
              {/* Faint horizontal pulse trail */}
              <span
                className="absolute top-1/2 -translate-y-1/2 -left-[10%] w-[120%] h-px opacity-40 animate-pipeflow bg-[linear-gradient(to_right,transparent,rgba(94,212,193,0.8),transparent)]"
                style={{ animationDelay: BLIP_DELAYS[i] }}
              />
              {/* Crisp blip in agent color */}
              <span
                className={cn(
                  "absolute top-1/2 -translate-y-1/2 w-2 h-2 animate-blip",
                  a.bgColor,
                )}
                style={{ animationDelay: BLIP_DELAYS[i] }}
              />
            </div>
          ))}
        </div>

        <div className="flex items-center gap-ds-4 px-ds-4 py-ds-3 bg-bg-deep text-[10.5px] uppercase tracking-[0.12em] text-fg-faint flex-wrap">
          <span>
            STATE · <strong className="text-fg font-medium">AgentState (TypedDict)</strong>
          </span>
          <span aria-hidden className="opacity-40">│</span>
          <span>
            CHECKPOINT · <strong className="text-fg font-medium">RedisSaver</strong>
          </span>
          <span aria-hidden className="opacity-40">│</span>
          <span>
            OBSERVABILITY · <strong className="text-fg font-medium">Langfuse</strong>
          </span>
          <span className="ml-auto text-fg-muted">↗ adr-002 · 5-agent + feedback</span>
        </div>
      </div>
    </Section>
  );
}
