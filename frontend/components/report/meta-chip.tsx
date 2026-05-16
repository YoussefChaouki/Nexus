import { cn } from "@/lib/cn";

export function MetaChip({
  label,
  value,
  className,
}: {
  label: string;
  value: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-baseline gap-ds-2 px-ds-3 py-[6px] border border-border",
        "text-[11px] text-fg-muted tracking-[0.06em] uppercase",
        className,
      )}
    >
      <span className="text-fg-faint">{label}</span>
      <span className="text-fg font-medium tabular">{value}</span>
    </span>
  );
}
