import { cn } from "@/lib/cn";

const BLOCKS = 10;
const APPROVE_THRESHOLD = 0.6;

interface CriticGaugeProps {
  /** OWASP coverage score in [0, 1] computed by the Critic. */
  score: number;
  iterationCount?: number;
  maxIterations?: number;
  className?: string;
}

/**
 * Terminal block gauge for the Critic's deterministic coverage score —
 * `▰▰▰▰▰▰▰▱▱▱ 0.70`. Green at/above the approve threshold, amber below.
 */
export function CriticGauge({
  score,
  iterationCount,
  maxIterations = 3,
  className,
}: CriticGaugeProps) {
  const clamped = Math.max(0, Math.min(1, score));
  const filled = Math.round(clamped * BLOCKS);
  const passing = clamped >= APPROVE_THRESHOLD;
  const tone = passing ? "text-agent-writer" : "text-sev-high";

  return (
    <div className={cn("flex items-baseline gap-ds-3 flex-wrap", className)}>
      <span className="text-[10.5px] uppercase tracking-[0.14em] text-fg-faint">
        critic coverage
      </span>
      <span
        role="img"
        aria-label={`Critic coverage score ${clamped.toFixed(2)} out of 1 — ${
          passing ? "above" : "below"
        } the ${APPROVE_THRESHOLD} approve threshold`}
        className={cn("text-[13px] tracking-[0.08em] select-none", tone)}
      >
        {"▰".repeat(filled)}
        <span className="text-border-emph">{"▱".repeat(BLOCKS - filled)}</span>
      </span>
      <span className={cn("text-[13px] tabular font-semibold", tone)}>
        {clamped.toFixed(2)}
      </span>
      <span className="text-[10.5px] text-fg-faint tracking-[0.06em]">
        / {APPROVE_THRESHOLD.toFixed(1)} to approve
      </span>
      {typeof iterationCount === "number" && (
        <span className="text-[10.5px] uppercase tracking-[0.1em] text-fg-muted border border-border px-ds-2 py-px">
          pass <span className="tabular text-fg">{iterationCount}</span>
          <span className="text-fg-faint">/{maxIterations}</span>
        </span>
      )}
    </div>
  );
}
