import Link from "next/link";

export function LandingHero() {
  return (
    <section className="relative px-ds-6 pt-ds-9 pb-ds-7 border-b border-border" id="top">
      <div className="flex gap-[14px] mb-ds-6 text-[10.5px] uppercase tracking-[0.14em] text-fg-faint flex-wrap">
        <Meta label="STATUS" value="● online" valueClass="text-accent" />
        <Meta label="BUILD" value="v0.7.1" />
        <Meta label="STAGE" value="portfolio · beta" />
        <Meta label="DOMAIN" value="ai security" />
      </div>

      {/* Giant wordmark — clamps from 80px on phone to 220px on wide screens. */}
      <h1 className="m-0 font-mono font-semibold text-fg flex items-baseline mb-ds-6 leading-[0.86] tracking-[-0.045em] text-[clamp(80px,16vw,220px)]">
        nexus
        <span
          aria-hidden
          className="text-accent font-light animate-blink ml-[0.04em]"
        >
          _
        </span>
      </h1>

      <p className="text-[clamp(16px,1.8vw,22px)] text-fg-muted max-w-[720px] leading-[1.55] mt-0 mb-ds-7 [text-wrap:pretty]">
        A <strong className="text-fg font-medium">multi-agent threat-surface analyzer</strong>{" "}
        for AI systems. Describe an architecture in plain language. Five
        specialized agents research, synthesize, criticize, and ship an
        actionable <span className="text-accent font-medium">ThreatReport</span> in under
        sixty seconds.
      </p>

      <blockquote className="border-l-2 border-accent border-t border-r border-b border-border bg-bg-card px-ds-5 py-ds-4 max-w-[760px] m-0 mb-ds-8">
        <p
          className="text-[17px] leading-[1.65] text-fg font-normal m-0 mb-ds-3 [text-wrap:pretty]
                     before:content-[open-quote] before:text-accent before:mr-1
                     after:content-[close-quote] after:text-accent after:ml-[2px]"
        >
          The interesting attack surfaces in AI systems don't live in the model.
          They live at the seams, where retrieval meets context, where tools
          meet agency, where evidence meets trust. Nexus maps the seams.
        </p>
        <div className="text-[10.5px] uppercase tracking-[0.14em] text-fg-faint">
          <strong className="text-fg-muted font-medium mr-1">Design rationale</strong>
          ADR-001 · choice of use case
        </div>
      </blockquote>

      <div className="flex gap-ds-3 flex-wrap items-center">
        <Link
          href="/analyze"
          className="inline-flex items-center gap-[10px] px-[22px] py-[13px] font-mono text-[12px] uppercase tracking-[0.14em] font-semibold border border-accent text-accent bg-accent/[0.07] transition-colors duration-100 hover:bg-accent hover:text-bg"
        >
          ▶ Run an analysis
          <kbd className="text-[10px] border border-current px-[5px] py-px opacity-60">⌘↵</kbd>
        </Link>
        <a
          href="#agents"
          className="inline-flex items-center gap-[10px] px-[22px] py-[13px] font-mono text-[12px] uppercase tracking-[0.14em] font-medium border border-border-emph text-fg transition-colors duration-100 hover:border-fg-muted hover:bg-bg-elev"
        >
          ↗ See the agents
        </a>
        <a
          href="#stack"
          className="inline-flex items-center gap-[10px] px-[22px] py-[13px] font-mono text-[12px] uppercase tracking-[0.14em] font-medium border border-transparent text-fg-muted transition-colors duration-100 hover:text-fg hover:border-border"
        >
          ⌘ Tech stack
        </a>
      </div>
    </section>
  );
}

function Meta({
  label,
  value,
  valueClass,
}: {
  label: string;
  value: string;
  valueClass?: string;
}) {
  return (
    <span>
      {label}
      <strong className={`ml-[6px] font-medium ${valueClass ?? "text-fg-muted"}`}>
        {value}
      </strong>
    </span>
  );
}
