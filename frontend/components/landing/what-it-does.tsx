import { Section } from "./section-shell";

export function WhatItDoes() {
  return (
    <Section
      id="what"
      num="01"
      title="What it does"
      meta="describe · orchestrate · ship"
    >
      <div className="grid grid-cols-1 md:grid-cols-3 border-t border-l border-border">
        <Cell
          n="01"
          step="DESCRIBE"
          title="You sketch the system in plain English"
          body="A textarea. No forms. No checklists. The same way you'd describe your stack to a colleague: framework, data store, model, who can touch what."
          glyph={
            <>
              <span className="text-accent">▸</span> FastAPI · pgvector · RAG · GPT-4 ·
              <br />
              &nbsp;&nbsp;Streamlit · AWS ECS · no auth ·
              <br />
              &nbsp;&nbsp;enterprise docs via user upload
            </>
          }
        />
        <Cell
          n="02"
          step="ORCHESTRATE"
          title="Five agents work the surface in parallel"
          body="Planner decomposes. Researcher queries arXiv, NVD, and MITRE ATLAS in parallel. Analyst synthesizes. Critic re-runs the loop if coverage is thin. Writer assembles."
          glyph={
            <>
              <span className="text-agent-planner">planner</span> →{" "}
              <span className="text-agent-researcher">researcher</span> →{" "}
              <span className="text-agent-analyst">analyst</span>
              <br />
              <span className="opacity-0">planner</span>
              <span className="text-fg-faint">↓</span>
              <br />
              &nbsp;&nbsp;<span className="text-agent-writer">writer</span> ←{" "}
              <span className="text-agent-critic">critic</span>
            </>
          }
        />
        <Cell
          n="03"
          step="SHIP"
          title="A structured ThreatReport, with receipts"
          body="JSON output. Severity-ranked surfaces. Attack vectors mapped to ATLAS techniques and OWASP categories. Every claim cited with a CVE or paper. Critic's gaps included."
          glyph={
            <>
              surfaces: <span className="text-accent">4</span> · iter:{" "}
              <span className="text-accent">2</span>
              <br />
              critical: <span className="text-sev-critical">1</span> · high:{" "}
              <span className="text-sev-high">2</span>
              <br />
              coverage: <span className="text-accent">8/10</span> OWASP LLM
            </>
          }
        />
      </div>
    </Section>
  );
}

function Cell({
  n,
  step,
  title,
  body,
  glyph,
}: {
  n: string;
  step: string;
  title: string;
  body: string;
  glyph: React.ReactNode;
}) {
  return (
    <div className="p-ds-6 border-r border-b border-border bg-bg-card flex flex-col gap-ds-4">
      <div className="flex items-baseline gap-[10px] text-[10.5px] uppercase tracking-[0.16em] text-fg-faint">
        <span className="text-accent font-semibold text-[18px] tracking-normal">{n}</span>
        {step}
      </div>
      <h3 className="m-0 text-[18px] font-medium text-fg leading-[1.35] tracking-[-0.005em]">
        {title}
      </h3>
      <p className="m-0 text-[13px] text-fg-muted leading-[1.7]">{body}</p>
      <div className="mt-[6px] p-ds-4 border border-border bg-bg-deep text-[11.5px] leading-[1.7] text-fg-muted font-mono">
        {glyph}
      </div>
    </div>
  );
}
