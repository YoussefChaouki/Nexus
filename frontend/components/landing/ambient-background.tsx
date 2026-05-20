// Fixed-position decorative layers behind the landing content. Four
// stacked layers: radial glow tints, hairline grid masked radially,
// SVG fractal-noise overlay, a scanline that sweeps top→bottom every 9s.
// All pointer-events: none — never intercepts clicks.
export function AmbientBackground() {
  return (
    <div className="fixed inset-0 pointer-events-none z-0" aria-hidden>
      {/* Multi-source radial glow — teal centered up top, planner violet
          bottom-right, critic coral bottom-left. Very subtle. */}
      <div
        className="absolute inset-0"
        style={{
          background: [
            "radial-gradient(ellipse 60% 40% at 50% 0%, rgba(94, 212, 193, 0.07), transparent 70%)",
            "radial-gradient(ellipse 40% 30% at 90% 80%, rgba(196, 168, 255, 0.03), transparent 70%)",
            "radial-gradient(ellipse 40% 30% at 10% 70%, rgba(255, 138, 126, 0.02), transparent 70%)",
          ].join(", "),
        }}
      />
      {/* Hairline grid, masked so it fades at the edges. */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(94, 212, 193, 0.025) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(94, 212, 193, 0.025) 1px, transparent 1px)
          `,
          backgroundSize: "64px 64px",
          maskImage:
            "radial-gradient(ellipse 80% 70% at 50% 30%, black 30%, transparent 80%)",
          WebkitMaskImage:
            "radial-gradient(ellipse 80% 70% at 50% 30%, black 30%, transparent 80%)",
        }}
      />
      {/* SVG fractal noise overlay — adds organic texture to flat surfaces. */}
      <div
        className="absolute inset-0 opacity-50"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' stitchTiles='stitch'/%3E%3CfeColorMatrix values='0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.04 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`,
        }}
      />
      {/* Scanline — single teal line sweeping the viewport every 9s. */}
      <div className="absolute left-0 right-0 h-px animate-scanline bg-[linear-gradient(to_right,transparent,rgba(94,212,193,0.3),transparent)]" />
    </div>
  );
}
