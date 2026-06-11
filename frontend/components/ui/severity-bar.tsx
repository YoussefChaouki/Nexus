import { cn } from "@/lib/cn";
import type { Severity } from "@/lib/schemas";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

const SEGMENT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

const LEGEND_TEXT: Record<Severity, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
};

interface SeverityBarProps {
  breakdown: Record<string, number>;
  /** mini = 4px strip for table rows; default = 10px bar with legend. */
  size?: "default" | "mini";
  className?: string;
}

/**
 * Proportional severity spectrum — one stacked bar, critical→low.
 * Replaces rows of count badges with a shape the eye can compare
 * across reports at a glance.
 */
export function SeverityBar({ breakdown, size = "default", className }: SeverityBarProps) {
  const counts = ORDER.map((sev) => ({ sev, n: breakdown[sev] ?? 0 }));
  const total = counts.reduce((acc, { n }) => acc + n, 0);
  const mini = size === "mini";

  if (total === 0) {
    return (
      <div
        className={cn(
          "bg-bg-deep border border-border",
          mini ? "h-[4px] w-[96px]" : "h-[10px] w-full",
          className,
        )}
        role="img"
        aria-label="No surfaces recorded"
        title="no surfaces"
      />
    );
  }

  const label = counts
    .filter(({ n }) => n > 0)
    .map(({ sev, n }) => `${n} ${sev}`)
    .join(", ");

  return (
    <div className={cn(mini ? "w-[96px]" : "w-full", className)}>
      <div
        role="img"
        aria-label={`Severity distribution: ${label}`}
        title={label}
        className={cn(
          "flex w-full overflow-hidden",
          "origin-left animate-bar-grow",
          mini ? "h-[4px] gap-px" : "h-[10px] gap-[2px]",
        )}
      >
        {counts.map(({ sev, n }) =>
          n > 0 ? (
            <span
              key={sev}
              className={cn(SEGMENT[sev], "h-full")}
              style={{ flexGrow: n, flexBasis: 0 }}
            />
          ) : null,
        )}
      </div>
      {!mini && (
        <div className="mt-ds-2 flex gap-ds-4 flex-wrap text-[10.5px] uppercase tracking-[0.1em]">
          {counts.map(({ sev, n }) => (
            <span
              key={sev}
              className={cn(n > 0 ? LEGEND_TEXT[sev] : "text-fg-faint")}
            >
              <span className="tabular font-semibold">{n}</span> {sev}
            </span>
          ))}
          <span className="ml-auto text-fg-faint">
            <span className="tabular text-fg-muted font-medium">{total}</span> total
          </span>
        </div>
      )}
    </div>
  );
}
