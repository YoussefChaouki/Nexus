import * as React from "react";
import { cn } from "@/lib/cn";

export function SectionHeader({
  num,
  title,
  meta,
  className,
}: {
  num: string;
  title: React.ReactNode;
  meta?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-baseline gap-ds-4 mb-ds-6 pb-ds-3 border-b border-border",
        className,
      )}
    >
      <span className="text-fg-faint text-[11px] tracking-[0.16em] tabular font-medium">
        {num} {"//"}
      </span>
      <h2 className="text-h2 text-fg m-0">{title}</h2>
      {meta && (
        <span className="ml-auto text-fg-faint text-[10.5px] uppercase tracking-[0.12em]">
          {meta}
        </span>
      )}
    </div>
  );
}

export function SubHeader({
  title,
  note,
  className,
}: {
  title: string;
  note?: string;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-ds-3 mt-ds-7 mb-ds-4", className)}>
      <span aria-hidden className="text-fg-faint">─</span>
      <span className="text-[11px] uppercase tracking-[0.16em] text-fg-muted font-medium">
        {title}
      </span>
      <span className="flex-1 h-px bg-border" />
      {note && (
        <span className="text-[10.5px] text-fg-faint tracking-[0.08em]">{note}</span>
      )}
    </div>
  );
}
