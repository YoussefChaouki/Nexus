"use client";

import * as React from "react";
import { cn } from "@/lib/cn";
import { estimateTokens } from "@/lib/format";
import { TerminalCard } from "./terminal-card";

interface PromptTextareaProps {
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  title?: string;
  endpoint?: string;
  footRight?: React.ReactNode;
  className?: string;
  minHeight?: number;
}

export function PromptTextarea({
  value,
  onChange,
  placeholder = "Describe target system, attack surface, or asset to analyze...",
  title = "Initiate threat-surface analysis",
  endpoint = "POST /v1/analyze/stream",
  footRight,
  className,
  minHeight = 200,
}: PromptTextareaProps) {
  const chars = value.length;
  const tokens = estimateTokens(chars);

  return (
    <TerminalCard className={cn("flex flex-col", className)}>
      <header className="flex items-center justify-between px-ds-4 py-[10px] border-b border-border text-[10.5px] uppercase tracking-[0.12em] text-fg-muted">
        <span className="text-fg flex items-center gap-ds-2 before:content-['▎'] before:text-accent">
          {title}
        </span>
        <span>{endpoint}</span>
      </header>
      <div className="flex gap-ds-3 px-ds-5 py-ds-4 items-start">
        <span
          aria-hidden
          className="text-accent text-[15px] font-medium leading-[1.7] pt-px shrink-0"
        >
          ▸
        </span>
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          spellCheck={false}
          style={{ minHeight }}
          className={cn(
            "flex-1 bg-transparent border-0 text-fg font-mono",
            "text-[13.5px] leading-[1.7] resize-y outline-none p-0",
            "placeholder:text-fg-faint",
            "[caret-color:var(--accent)]",
          )}
        />
      </div>
      <footer className="flex items-center justify-between px-ds-4 py-[8px] border-t border-border text-[10.5px] uppercase tracking-[0.1em] text-fg-faint">
        <span>
          {chars} chars · ~{tokens} tokens
        </span>
        <span>{footRight}</span>
      </footer>
    </TerminalCard>
  );
}
