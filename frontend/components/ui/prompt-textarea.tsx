"use client";

import * as React from "react";
import { cn } from "@/lib/cn";
import { estimateTokens } from "@/lib/format";
import { TerminalCard } from "./terminal-card";

interface PromptTextareaProps {
  value: string;
  onChange: (next: string) => void;
  /** Fired on Cmd/Ctrl+Enter — terminal users never reach for the mouse. */
  onSubmit?: () => void;
  placeholder?: string;
  title?: string;
  endpoint?: string;
  footRight?: React.ReactNode;
  className?: string;
  minHeight?: number;
  /** Character budget rendered as a fill meter in the footer. */
  maxLength?: number;
}

export function PromptTextarea({
  value,
  onChange,
  onSubmit,
  placeholder = "Describe target system, attack surface, or asset to analyze...",
  title = "Initiate threat-surface analysis",
  endpoint = "POST /v1/analyze/stream",
  footRight,
  className,
  minHeight = 200,
  maxLength,
}: PromptTextareaProps) {
  const chars = value.length;
  const tokens = estimateTokens(chars);
  const budget = maxLength ? Math.min(1, chars / maxLength) : null;
  const overBudget = maxLength !== undefined && chars > maxLength;

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (onSubmit && e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      onSubmit();
    }
  }

  return (
    <TerminalCard
      className={cn(
        "flex flex-col transition-colors duration-150",
        "focus-within:border-accent/60",
        className,
      )}
    >
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
          onKeyDown={handleKeyDown}
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
      <footer className="flex items-center justify-between gap-ds-4 px-ds-4 py-[8px] border-t border-border text-[10.5px] uppercase tracking-[0.1em] text-fg-faint">
        <span className="inline-flex items-center gap-ds-3 whitespace-nowrap">
          <span className={cn("tabular", overBudget && "text-sev-critical")}>
            {chars}
            {maxLength ? `/${maxLength}` : ""} chars · ~{tokens} tokens
          </span>
          {budget !== null && (
            <span
              aria-hidden
              className="hidden sm:block h-[3px] w-[64px] bg-bg-deep overflow-hidden"
            >
              <span
                className={cn(
                  "block h-full transition-[width] duration-200",
                  overBudget ? "bg-sev-critical" : budget > 0.85 ? "bg-sev-high" : "bg-accent/70",
                )}
                style={{ width: `${(budget * 100).toFixed(1)}%` }}
              />
            </span>
          )}
          {onSubmit && (
            <kbd className="hidden md:inline border border-border px-[6px] py-px text-[9.5px] tracking-[0.08em] text-fg-faint normal-case">
              ⌘↵ run
            </kbd>
          )}
        </span>
        <span>{footRight}</span>
      </footer>
    </TerminalCard>
  );
}
