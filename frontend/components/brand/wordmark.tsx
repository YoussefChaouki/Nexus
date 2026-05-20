import { cn } from "@/lib/cn";

interface WordmarkProps {
  className?: string;
  caretClassName?: string;
  size?: "sm" | "md" | "lg" | "xl";
  // false = static caret (good for static contexts like footers);
  // default true keeps the blink and the "awaiting input" semantic.
  blink?: boolean;
}

const SIZE: Record<NonNullable<WordmarkProps["size"]>, string> = {
  sm: "text-[14px]",
  md: "text-[18px]",
  lg: "text-[28px]",
  xl: "text-[56px]",
};

// Logo #1 — wordmark `nexus_` with a blinking teal caret.
// Direct port from Logo.html § 01.
export function Wordmark({
  className,
  caretClassName,
  size = "md",
  blink = true,
}: WordmarkProps) {
  return (
    <span
      className={cn(
        "inline-flex items-baseline font-mono font-semibold",
        "tracking-[-0.02em] text-fg",
        SIZE[size],
        className,
      )}
      aria-label="nexus"
    >
      nexus
      <span
        aria-hidden
        className={cn(
          "ml-[2px] text-accent font-light",
          blink && "animate-blink",
          caretClassName,
        )}
      >
        _
      </span>
    </span>
  );
}
