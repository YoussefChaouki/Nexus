import { cn } from "@/lib/cn";
import { SeverityBadge } from "@/components/ui/badge";
import type { Severity } from "@/lib/schemas";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function SeverityRow({
  breakdown,
  className,
}: {
  breakdown: Record<string, number>;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-ds-3 flex-wrap", className)}>
      {ORDER.map((sev) => (
        <SeverityBadge key={sev} severity={sev} count={breakdown[sev] ?? 0} />
      ))}
    </div>
  );
}
