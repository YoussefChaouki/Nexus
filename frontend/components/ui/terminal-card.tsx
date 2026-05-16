import * as React from "react";
import { cn } from "@/lib/cn";

export function TerminalCard({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("border border-border bg-bg-card", className)}
      {...props}
    >
      {children}
    </div>
  );
}

export function TerminalCardBar({
  path,
  meta,
  className,
  children,
}: {
  path?: React.ReactNode;
  meta?: React.ReactNode;
  className?: string;
  children?: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-ds-3 px-ds-4 py-[10px]",
        "border-b border-border bg-bg-deep",
        "font-mono uppercase tracking-[0.12em] text-[10.5px] text-fg-muted",
        className,
      )}
    >
      <span className="inline-flex gap-[5px] mr-ds-2">
        <span className="w-2 h-2 bg-sev-critical/70" />
        <span className="w-2 h-2 bg-sev-high/70" />
        <span className="w-2 h-2 bg-sev-low/70" />
      </span>
      {path && <span className="text-fg font-medium">{path}</span>}
      {children}
      {meta && <span className="ml-auto text-fg-faint">{meta}</span>}
    </div>
  );
}

export function TerminalCardBody({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("p-ds-5 text-fg-muted text-[13px] leading-[1.7]", className)}
      {...props}
    />
  );
}

export function TerminalCardFooter({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "flex items-center gap-ds-4 px-ds-4 py-[10px]",
        "border-t border-border bg-bg-deep",
        "font-mono uppercase tracking-[0.1em] text-[10.5px] text-fg-faint",
        className,
      )}
      {...props}
    />
  );
}
