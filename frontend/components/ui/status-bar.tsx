import * as React from "react";
import { cn } from "@/lib/cn";

export function StatusBar({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-ds-5 flex-wrap",
        "px-ds-4 py-[10px] border border-border bg-bg-deep",
        "text-[11px] text-fg-muted tracking-[0.04em]",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function StatusSep() {
  return <span className="text-fg-faint" aria-hidden>│</span>;
}

export function StatusItem({
  label,
  children,
  className,
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-baseline gap-ds-2", className)}>
      <span className="uppercase tracking-[0.1em] text-fg-faint">{label}</span>
      <span className="text-fg font-medium">{children}</span>
    </span>
  );
}
