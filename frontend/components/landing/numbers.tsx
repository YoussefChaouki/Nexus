import { Section } from "./section-shell";
import { cn } from "@/lib/cn";

interface Metric {
  label: string;
  value: string;
  unit?: string;
  desc: string;
  tone?: "default" | "accent" | "crit";
}

const METRICS: Metric[] = [
  {
    label: "P50 latency",
    value: "47",
    unit: "s",
    tone: "accent",
    desc: "One iteration, 3–4 ResearchTasks. Target P50 < 60s · P95 < 180s.",
  },
  {
    label: "OWASP coverage",
    value: "82",
    unit: "%",
    desc: "Of LLM Top 10 categories surfaced across 5 reference architectures. Target ≥ 70%.",
  },
  {
    label: "Δ vs single-prompt",
    value: "+38",
    unit: "%",
    tone: "accent",
    desc: "Additional surfaces found by the multi-agent loop vs. a one-shot prompt baseline.",
  },
  {
    label: "Avg cost / report",
    value: "$0.07",
    desc: "Across the eval harness · ~8.2K tokens · 2 iterations median.",
  },
];

interface OwaspCell {
  id: string;
  name: string;
  state?: "hit" | "crit";
}

const OWASP: OwaspCell[] = [
  { id: "LLM01", name: "prompt injection", state: "crit" },
  { id: "LLM02", name: "insecure output", state: "hit" },
  { id: "LLM03", name: "training poison", state: "hit" },
  { id: "LLM04", name: "model dos", state: "hit" },
  { id: "LLM05", name: "supply chain", state: "hit" },
  { id: "LLM06", name: "sensitive info", state: "hit" },
  { id: "LLM07", name: "insecure plugin", state: "hit" },
  { id: "LLM08", name: "excessive agency", state: "hit" },
  { id: "LLM09", name: "overreliance" },
  { id: "LLM10", name: "model theft" },
];

export function Numbers() {
  return (
    <Section
      id="metrics"
      num="04"
      title="Numbers that matter"
      meta="eval harness · 5 architectures"
    >
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 border-t border-l border-border">
        {METRICS.map((m) => (
          <div
            key={m.label}
            className="p-ds-6 border-r border-b border-border bg-bg-card flex flex-col gap-ds-2"
          >
            <span className="text-[10px] uppercase tracking-[0.16em] text-fg-faint">
              {m.label}
            </span>
            <span
              className={cn(
                "text-[44px] font-medium leading-none tracking-[-0.02em] tabular",
                m.tone === "accent" && "text-accent",
                m.tone === "crit" && "text-sev-critical",
                !m.tone && "text-fg",
              )}
            >
              {m.value}
              {m.unit && <span className="text-[22px] text-fg-muted ml-1">{m.unit}</span>}
            </span>
            <span className="text-[11.5px] text-fg-muted leading-[1.55] mt-ds-2">
              {m.desc}
            </span>
          </div>
        ))}
      </div>

      <div className="h-ds-6" />

      <div className="border border-border bg-bg-card p-ds-6">
        <h3 className="m-0 mb-[6px] text-[14px] font-medium text-fg flex items-baseline gap-[14px]">
          OWASP LLM Top 10 · 2025
          <span className="text-accent text-[20px] font-semibold">8</span>
          <span className="text-fg-faint text-[13px]">/ 10 covered</span>
        </h3>
        <div className="text-[11.5px] text-fg-muted mb-ds-5 tracking-[0.04em]">
          Sample run · RAG pipeline with arxiv tool access · iter 2
        </div>
        <div className="grid grid-cols-5 lg:grid-cols-10 gap-[4px]">
          {OWASP.map((c) => (
            <div
              key={c.id}
              className={cn(
                "aspect-[1.2] border flex flex-col justify-between p-[7px] text-[10px] transition-colors duration-200",
                c.state === "crit" && "bg-sev-critical/[0.07] border-sev-critical/50 text-sev-critical",
                c.state === "hit" && "bg-accent/[0.07] border-accent/50 text-accent",
                !c.state && "border-border text-fg-faint",
              )}
            >
              <span className="font-semibold tracking-[0.04em]">{c.id}</span>
              <span
                className={cn(
                  "text-[8.5px] tracking-[0.04em] leading-[1.2]",
                  c.state ? "text-fg-muted" : "text-fg-faint",
                )}
              >
                {c.name}
              </span>
            </div>
          ))}
        </div>
      </div>
    </Section>
  );
}
