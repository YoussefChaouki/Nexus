import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/cn";
import type { Severity } from "@/lib/schemas";
import type { AgentName } from "@/lib/schemas";

const badgeVariants = cva(
  [
    "inline-flex items-center gap-ds-2",
    "px-[9px] py-[4px]",
    "font-mono uppercase tracking-[0.12em] font-semibold text-[10.5px] leading-[1.4]",
    "border",
  ],
  {
    variants: {
      tone: {
        "sev-critical": "text-sev-critical bg-sev-critical/[0.07] border-current",
        "sev-high": "text-sev-high bg-sev-high/[0.07] border-current",
        "sev-medium": "text-sev-medium bg-sev-medium/[0.07] border-current",
        "sev-low": "text-sev-low bg-sev-low/[0.07] border-current",
        "agent-planner": "text-agent-planner bg-agent-planner/[0.06] border-current",
        "agent-researcher": "text-agent-researcher bg-agent-researcher/[0.06] border-current",
        "agent-analyst": "text-agent-analyst bg-agent-analyst/[0.06] border-current",
        "agent-critic": "text-agent-critic bg-agent-critic/[0.06] border-current",
        "agent-writer": "text-agent-writer bg-agent-writer/[0.06] border-current",
        neutral: "text-fg-muted bg-bg-deep border-border",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, children, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ tone }), className)} {...props}>
      {children}
    </span>
  );
}

export function SeverityBadge({
  severity,
  count,
  className,
}: {
  severity: Severity;
  count?: number;
  className?: string;
}) {
  const tone = `sev-${severity}` as const;
  return (
    <Badge tone={tone} className={className}>
      {count !== undefined ? (
        <span className="text-[11px] tabular">{count}</span>
      ) : (
        <span className="text-[7px] leading-none">●</span>
      )}
      {severity}
    </Badge>
  );
}

export function AgentBadge({
  agent,
  className,
}: {
  agent: AgentName;
  className?: string;
}) {
  const tone = `agent-${agent}` as const;
  return (
    <Badge tone={tone} className={className}>
      <span className="text-[7px] leading-none">●</span>
      {agent}
    </Badge>
  );
}
