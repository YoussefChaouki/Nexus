"use client";

import { cn } from "@/lib/cn";

const EXAMPLES = [
  "RAG pipeline with arxiv tool access, retrieves papers and synthesizes summaries for downstream LLM consumption.",
  "OAuth flow in a multi-tenant SaaS with shared LLM-powered support chatbot exposed to anonymous users.",
  "MCP server exposing a code-execution tool to an autonomous agent that ingests untrusted GitHub issue content.",
  "LLM-powered code-review bot that proposes patches and auto-merges on the main branch when CI passes.",
] as const;

export function ExampleChips({ onPick }: { onPick: (text: string) => void }) {
  return (
    <div className="flex items-center gap-ds-2 flex-wrap mt-ds-5">
      <span className="text-[11px] text-fg-faint uppercase tracking-[0.1em] mr-ds-2">
        ─ examples
      </span>
      {EXAMPLES.map((ex) => (
        <button
          key={ex.slice(0, 20)}
          type="button"
          onClick={() => onPick(ex)}
          className={cn(
            "px-ds-3 py-[6px] border border-border text-fg-muted text-[12px]",
            "transition-colors duration-100",
            "hover:text-fg hover:border-border-emph hover:bg-bg-elev",
            "text-left max-w-[420px] truncate",
          )}
          title={ex}
        >
          {ex.split(",")[0]}
        </button>
      ))}
    </div>
  );
}
