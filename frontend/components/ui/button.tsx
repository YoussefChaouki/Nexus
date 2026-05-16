import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/cn";

const buttonVariants = cva(
  // Base — uppercase tracked monospace, sharp corners, hairline border.
  [
    "inline-flex items-center gap-ds-2",
    "font-mono uppercase tracking-[0.14em] font-medium",
    "border transition-colors duration-100",
    "focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent focus-visible:outline-offset-2",
    "disabled:opacity-40 disabled:pointer-events-none",
  ],
  {
    variants: {
      variant: {
        primary:
          "border-accent bg-accent/[0.06] text-accent font-semibold hover:bg-accent hover:text-bg",
        secondary:
          "border-border-emph text-fg hover:border-fg-muted hover:bg-bg-elev",
        ghost:
          "border-transparent text-fg-muted hover:text-fg hover:border-border",
        danger:
          "border-sev-critical/60 text-sev-critical hover:bg-sev-critical hover:text-bg",
      },
      size: {
        default: "px-[18px] py-[11px] text-[12px]",
        sm: "px-[11px] py-[6px] text-[10.5px]",
        lg: "px-ds-5 py-ds-4 text-[13px] tracking-widest",
      },
    },
    defaultVariants: {
      variant: "secondary",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  ),
);
Button.displayName = "Button";

export { buttonVariants };
