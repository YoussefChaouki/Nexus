import Link from "next/link";

export function CtaStrip() {
  return (
    <section
      id="cta"
      className="relative overflow-hidden px-ds-6 py-ds-9 border-b border-border bg-bg-card"
    >
      {/* Vertical grid lines — adds visual rhythm without competing with the content */}
      <div
        className="absolute inset-0 pointer-events-none opacity-50"
        aria-hidden
        style={{
          backgroundImage:
            "linear-gradient(to right, rgba(94, 212, 193, 0.04) 1px, transparent 1px)",
          backgroundSize: "32px 100%",
        }}
      />
      <div className="relative flex items-center gap-ds-7 flex-wrap">
        <div className="flex-1 min-w-[280px]">
          <h2 className="m-0 mb-ds-3 text-[32px] font-medium text-fg tracking-[-0.01em] leading-[1.2]">
            Run an analysis<span className="text-accent">_</span>
          </h2>
          <p className="m-0 text-fg-muted text-[14px] leading-[1.7] max-w-[560px]">
            Paste an architecture, watch five agents converge, get a structured report
            with citations and gaps. No signup. The streaming pane shows every tool call.
            The trace opens straight into Langfuse.
          </p>
        </div>
        <div className="flex gap-ds-3 flex-wrap">
          <Link
            href="/analyze"
            className="inline-flex items-center gap-[10px] px-[22px] py-[13px] font-mono text-[12px] uppercase tracking-[0.14em] font-semibold border border-accent text-accent bg-accent/[0.07] transition-colors duration-100 hover:bg-accent hover:text-bg"
          >
            ▶ Launch nexus
            <kbd className="text-[10px] border border-current px-[5px] py-px opacity-60">⌘↵</kbd>
          </Link>
          <a
            href="https://github.com/YoussefChaouki/Nexus"
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-[10px] px-[22px] py-[13px] font-mono text-[12px] uppercase tracking-[0.14em] font-medium border border-border-emph text-fg transition-colors duration-100 hover:border-fg-muted hover:bg-bg-elev"
          >
            ↗ Source on GitHub
          </a>
        </div>
      </div>
    </section>
  );
}
