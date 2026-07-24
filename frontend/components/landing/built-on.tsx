import { Section } from "./section-shell";
import { MonoTag } from "@/components/ui/mono-tag";

interface Chip {
  k: string;
  v: string;
}

const ORCHESTRATION: Chip[] = [
  { k: "python", v: "3.11+" },
  { k: "fastapi", v: "async" },
  { k: "langgraph", v: "state-machine" },
  { k: "redis", v: "checkpointer" },
  { k: "pydantic", v: "strict" },
];

const MEMORY_TOOLS: Chip[] = [
  { k: "pgvector", v: "1536-dim" },
  { k: "mcp", v: "4 servers" },
  { k: "langfuse", v: "traces" },
  { k: "openai", v: "gpt-4o" },
  { k: "anthropic", v: "fallback" },
];

export function BuiltOn() {
  return (
    <Section id="stack" num="05" title="Built on" meta="honest stack · no magic">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-ds-5">
        <Card title="─ orchestration">
          <p className="m-0 text-fg-muted text-[13px] leading-[1.7]">
            A <MonoTag>StateGraph</MonoTag> in{" "}
            <strong className="text-fg font-medium">LangGraph</strong>, checkpointed in{" "}
            <strong className="text-fg font-medium">Redis</strong>, with a conditional edge
            from Critic that loops back into Researcher until coverage clears the threshold or{" "}
            <MonoTag>max_iterations</MonoTag> is hit.
          </p>
          <ChipRow chips={ORCHESTRATION} />
        </Card>

        <Card title="─ memory & tools">
          <p className="m-0 text-fg-muted text-[13px] leading-[1.7]">
            Three memory layers: working in Redis, episodic and semantic in{" "}
            <strong className="text-fg font-medium">pgvector</strong>. Three{" "}
            <strong className="text-fg font-medium">MCP</strong> servers expose arXiv, NVD, and
            MITRE ATLAS over stdio.
          </p>
          <ChipRow chips={MEMORY_TOOLS} />
        </Card>
      </div>
    </Section>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-border bg-bg-card p-ds-6">
      <div className="text-[10.5px] uppercase tracking-[0.14em] text-fg-faint mb-[14px]">
        {title}
      </div>
      {children}
    </div>
  );
}

function ChipRow({ chips }: { chips: Chip[] }) {
  return (
    <div className="flex flex-wrap gap-ds-2 mt-ds-5">
      {chips.map((c) => (
        <span
          key={c.k}
          className="px-[10px] py-[5px] border border-border text-[10.5px] text-fg-muted tracking-[0.06em] bg-bg-deep"
        >
          <strong className="text-fg font-medium mr-[5px]">{c.k}</strong>
          {c.v}
        </span>
      ))}
    </div>
  );
}
