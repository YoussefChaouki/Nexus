import { Section } from "./section-shell";
import { cn } from "@/lib/cn";

interface Event {
  time: string;
  agent: "planner" | "researcher" | "analyst" | "critic" | "writer";
  body: React.ReactNode;
  live?: boolean;
}

const AGENT_COLOR: Record<Event["agent"], string> = {
  planner: "text-agent-planner",
  researcher: "text-agent-researcher",
  analyst: "text-agent-analyst",
  critic: "text-agent-critic",
  writer: "text-agent-writer",
};

const EVENTS: Event[] = [
  { time: "00:00.041", agent: "planner", body: <>decomposing target into candidate surfaces</> },
  { time: "00:00.892", agent: "planner", body: <>identified <Num n={4} /> candidate surfaces</> },
  { time: "00:01.203", agent: "researcher", body: <>querying arxiv <Ref>"adversarial RAG poisoning"</Ref></> },
  { time: "00:02.118", agent: "researcher", body: <>retrieved <Num n={12} /> papers · <Num n={3} /> high-relevance</> },
  { time: "00:02.604", agent: "researcher", body: <>added <Ref>CVE-2024-31819</Ref> to context</> },
  { time: "00:03.401", agent: "analyst", body: <>scoring <Ref>prompt-injection-via-tool-output</Ref></> },
  {
    time: "00:04.890",
    agent: "analyst",
    body: <>severity=<span className="text-sev-critical font-semibold">CRITICAL</span> · confidence=<Num n={0.82} /></>,
  },
  { time: "00:06.112", agent: "critic", body: <>flagging bias: over-indexing on recent papers</> },
  { time: "00:07.305", agent: "critic", body: <>requesting iteration <Num n={2} /></> },
  { time: "00:08.001", agent: "writer", body: <>drafting surface <Num n="1/4" /></> },
  { time: "00:08.612", agent: "writer", body: <>composing mitigations for surface <Num n="2/4" /></>, live: true },
];

export function LiveFeedSample() {
  return (
    <Section
      id="live"
      num="03"
      title="Live, with receipts"
      meta="sse stream · sample run"
    >
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-ds-5">
        {/* Feed */}
        <div className="border border-border bg-bg-card">
          <header className="flex items-center gap-[10px] px-ds-4 py-[10px] border-b border-border bg-bg-deep text-[10.5px] uppercase tracking-[0.12em] text-fg-muted">
            <span className="w-2 h-2 bg-sev-critical animate-pulse-soft" />
            <span>Agent timeline · live</span>
            <span className="ml-auto text-fg-faint">tail -f /var/log/nexus/run-7f3a.log</span>
          </header>
          <div className="px-ds-4 py-ds-3 border-b border-border bg-bg-deep text-[12.5px] text-fg">
            <span className="text-fg-faint text-[10px] tracking-[0.14em] mr-[6px]">TARGET /</span>
            RAG pipeline with arxiv tool access, retrieves papers and synthesizes summaries
          </div>
          <div className="py-ds-3">
            {EVENTS.map((e, i) => (
              <div
                key={i}
                className={cn(
                  "grid grid-cols-[80px_100px_1fr] gap-[14px] px-ds-4 py-[6px] items-baseline text-[12px]",
                  e.live && "bg-agent-writer/[0.04] border-l-2 border-agent-writer pl-[14px]",
                )}
              >
                <span className="text-fg-faint text-[10.5px] tabular">{e.time}</span>
                <span
                  className={cn(
                    "text-[9.5px] uppercase tracking-[0.12em] font-semibold border border-current text-center px-[7px] py-[2px]",
                    AGENT_COLOR[e.agent],
                  )}
                >
                  {e.agent}
                </span>
                <span className="text-fg">
                  <span className="text-fg-faint mr-[6px]">▸</span>
                  {e.body}
                  {e.live && (
                    <span className="text-agent-writer ml-ds-2 animate-blink">▊</span>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Stats */}
        <aside className="border border-border bg-bg-card h-fit">
          <header className="px-ds-4 py-[10px] border-b border-border bg-bg-deep text-[10.5px] uppercase tracking-[0.12em] text-fg-muted">
            Live metrics
          </header>
          <StatRow l="Iteration" v={<>2<span className="text-fg-faint text-[12px]">/3</span></>} />
          <StatRow l="Tokens in" v="4,832" />
          <StatRow l="Tokens out" v="1,205" />
          <StatRow l="Cost" v="$0.043" accent />
          <StatRow l="Surfaces" v="4" />
          <StatRow l="ETA" v="~6s" />
          <div className="px-ds-4 py-ds-3 border-t border-border bg-bg-deep">
            <div className="text-[10px] uppercase tracking-[0.12em] text-fg-faint mb-ds-2">Progress</div>
            <div className="h-[2px] bg-border relative">
              <div className="absolute inset-y-0 left-0 bg-accent w-[68%]" />
            </div>
            <div className="flex justify-between mt-ds-2 text-[10px] text-fg-faint tracking-[0.08em]">
              <span>68%</span>
              <span>writer · 2/4</span>
            </div>
          </div>
        </aside>
      </div>
    </Section>
  );
}

function StatRow({
  l,
  v,
  accent,
}: {
  l: string;
  v: React.ReactNode;
  accent?: boolean;
}) {
  return (
    <div className="px-ds-4 py-[12px] border-b border-border flex justify-between items-baseline last:border-b-0">
      <span className="text-[10px] uppercase tracking-[0.12em] text-fg-faint">{l}</span>
      <span
        className={cn(
          "text-[16px] tabular font-medium",
          accent ? "text-accent" : "text-fg",
        )}
      >
        {v}
      </span>
    </div>
  );
}

function Num({ n }: { n: number | string }) {
  return <span className="text-fg font-medium tabular">{n}</span>;
}

function Ref({ children }: { children: React.ReactNode }) {
  return <span className="text-agent-researcher border-b border-dotted border-current">{children}</span>;
}
