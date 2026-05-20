import { cn } from "@/lib/cn";

interface GlyphProps {
  className?: string;
  // "compact" = square 64×64 — favicon, app icon, sidebar collapsed.
  // "wide"    = 180×64 horizontal multigraph with input/output nodes —
  //             splash screens, marketing surfaces.
  variant?: "compact" | "wide";
  size?: number;
  title?: string;
}

// Logo #4 — agent constellation, one colored node per pipeline agent.
// Direct port from Logo.html § 04.
//
// Node mapping (frozen — DO NOT reassign colors, they're the single
// source of truth used across badges, timeline, status pills):
//   planner    violet  #c4a8ff
//   researcher azure   #7eb8ff
//   analyst    teal    #5ed4c1
//   critic     coral   #ff8a7e
//   writer     lime    #9ee87a
export function NexusGlyph({
  className,
  variant = "compact",
  size,
  title = "nexus",
}: GlyphProps) {
  if (variant === "wide") {
    return (
      <svg
        viewBox="0 0 180 64"
        width={size ?? 180}
        height={size ? Math.round(size * (64 / 180)) : 64}
        role="img"
        aria-label={title}
        className={cn("shrink-0", className)}
      >
        <title>{title}</title>
        {/* edges */}
        <g stroke="#1a1f28" strokeWidth="1">
          <line x1="20" y1="32" x2="60" y2="14" />
          <line x1="20" y1="32" x2="60" y2="50" />
          <line x1="60" y1="14" x2="100" y2="14" />
          <line x1="60" y1="50" x2="100" y2="50" />
          <line x1="100" y1="14" x2="100" y2="50" />
          <line x1="60" y1="14" x2="100" y2="50" />
          <line x1="60" y1="50" x2="100" y2="14" />
          <line x1="100" y1="14" x2="160" y2="32" />
          <line x1="100" y1="50" x2="160" y2="32" />
        </g>
        {/* 5 agent nodes */}
        <rect x="16" y="28" width="8" height="8" fill="#c4a8ff" />
        <rect x="56" y="10" width="8" height="8" fill="#7eb8ff" />
        <rect x="56" y="46" width="8" height="8" fill="#5ed4c1" />
        <rect x="96" y="10" width="8" height="8" fill="#ff8a7e" />
        <rect x="96" y="46" width="8" height="8" fill="#9ee87a" />
        {/* output node — outlined teal, signals the synthesized report */}
        <rect
          x="156"
          y="28"
          width="8"
          height="8"
          fill="none"
          stroke="#5ed4c1"
          strokeWidth="1.5"
        />
      </svg>
    );
  }

  // compact 64×64 — keeps the multigraph but symmetric.
  const px = size ?? 24;
  return (
    <svg
      viewBox="0 0 64 64"
      width={px}
      height={px}
      role="img"
      aria-label={title}
      className={cn("shrink-0", className)}
      shapeRendering={px <= 24 ? "crispEdges" : "auto"}
    >
      <title>{title}</title>
      {/* bounding frame (drops out at very small sizes for clarity) */}
      {px > 24 && (
        <rect
          x="6"
          y="6"
          width="52"
          height="52"
          stroke="#1a1f28"
          strokeWidth="1"
          fill="none"
        />
      )}
      {/* edges (drop at very small sizes — the nodes carry the mark alone) */}
      {px > 24 && (
        <g stroke="#2a323e" strokeWidth="0.8">
          <line x1="17" y1="29" x2="29" y2="17" />
          <line x1="17" y1="29" x2="29" y2="41" />
          <line x1="29" y1="17" x2="41" y2="17" />
          <line x1="29" y1="41" x2="41" y2="41" />
          <line x1="29" y1="17" x2="41" y2="41" />
          <line x1="29" y1="41" x2="41" y2="17" />
        </g>
      )}
      {/* 5 agent nodes */}
      <rect x="14" y="26" width="6" height="6" fill="#c4a8ff" />
      <rect x="26" y="14" width="6" height="6" fill="#7eb8ff" />
      <rect x="26" y="38" width="6" height="6" fill="#5ed4c1" />
      <rect x="38" y="14" width="6" height="6" fill="#ff8a7e" />
      <rect x="38" y="38" width="6" height="6" fill="#9ee87a" />
    </svg>
  );
}
