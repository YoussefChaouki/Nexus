import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/cn";

const monoTagVariants = cva(
  [
    "font-mono text-[0.92em] px-[6px] py-px",
    "bg-bg-deep border align-baseline",
  ],
  {
    variants: {
      tone: {
        default: "text-fg border-border",
        accent: "text-accent border-accent/40",
        muted: "text-fg-muted border-border",
        crit: "text-sev-critical border-sev-critical/40",
      },
    },
    defaultVariants: { tone: "default" },
  },
);

export interface MonoTagProps
  extends React.HTMLAttributes<HTMLElement>,
    VariantProps<typeof monoTagVariants> {
  as?: "code" | "span";
}

export function MonoTag({ as = "code", tone, className, ...props }: MonoTagProps) {
  const Comp = as as keyof React.JSX.IntrinsicElements;
  return React.createElement(Comp, {
    className: cn(monoTagVariants({ tone }), className),
    ...props,
  });
}
