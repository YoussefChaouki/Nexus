import { Launcher } from "@/components/home/launcher";
import { Pill } from "@/components/ui/pill";
import { StatusBar, StatusItem, StatusSep } from "@/components/ui/status-bar";

export default function HomePage() {
  return (
    <>
      <StatusBar>
        <Pill tone="ready">System ready</Pill>
        <StatusSep />
        <StatusItem label="Model">gpt-4o</StatusItem>
        <StatusSep />
        <StatusItem label="Budget">~12s · 8K tok</StatusItem>
        <StatusSep />
        <StatusItem label="Iter">max 3</StatusItem>
        <span className="ml-auto">
          <StatusItem label="Agents">5 / idle</StatusItem>
        </span>
      </StatusBar>

      <header className="mt-ds-7 pb-ds-5">
        <div className="text-[10.5px] uppercase tracking-[0.12em] text-fg-faint mb-ds-3">
          stack <span className="text-fg-muted ml-ds-2">langgraph · pgvector · langfuse</span>
        </div>
        <h1 className="text-display text-fg m-0">
          Threat surface mapped<span className="text-accent font-light animate-blink">_</span>
        </h1>
        <p className="text-fg-muted text-[14.5px] leading-[1.7] max-w-[720px] mt-ds-3">
          Multi-agent threat-surface analyzer for AI deployments. Describe the
          target system below — the Planner decomposes it into focus areas, the
          Researcher pulls evidence from arxiv / NVD / ATLAS, the Analyst scores
          surfaces, the Critic challenges the result, and the Writer ships the
          final report. Hairlines and monospace all the way down.
        </p>
      </header>

      <Launcher />
    </>
  );
}
