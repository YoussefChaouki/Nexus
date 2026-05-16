import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/cn";

const pillVariants = cva(
  [
    "inline-flex items-center gap-ds-2",
    "px-[10px] py-[5px] pl-[9px]",
    "border bg-bg-deep",
    "font-mono uppercase tracking-[0.12em] text-[10.5px] font-medium",
  ],
  {
    variants: {
      tone: {
        ready: "text-accent border-accent/50",
        live: "text-sev-critical border-sev-critical/50",
        complete: "text-agent-writer border-agent-writer/50",
        warn: "text-sev-high border-sev-high/50",
        idle: "text-fg-muted border-border-emph",
      },
    },
    defaultVariants: { tone: "idle" },
  },
);

const dotColor: Record<NonNullable<VariantProps<typeof pillVariants>["tone"]>, string> = {
  ready: "bg-accent",
  live: "bg-sev-critical",
  complete: "bg-agent-writer",
  warn: "bg-sev-high",
  idle: "bg-fg-faint",
};

export interface PillProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof pillVariants> {
  pulse?: boolean;
}

export function Pill({ className, tone, pulse, children, ...props }: PillProps) {
  const t = tone ?? "idle";
  return (
    <span className={cn(pillVariants({ tone: t }), className)} {...props}>
      <span
        className={cn(
          "w-[6px] h-[6px] shrink-0",
          dotColor[t],
          pulse && "animate-pulse-soft",
        )}
      />
      {children}
    </span>
  );
}
