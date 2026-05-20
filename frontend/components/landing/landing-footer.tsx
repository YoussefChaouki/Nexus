import Link from "next/link";

interface Col {
  title: string;
  links: { label: string; href: string; external?: boolean; colorClass?: string }[];
}

const COLS: Col[] = [
  {
    title: "─ Product",
    links: [
      { label: "Run an analysis", href: "/analyze" },
      { label: "History", href: "/history" },
      { label: "Logo · brand", href: "#top" },
    ],
  },
  {
    title: "─ Agents",
    links: [
      { label: "planner", href: "#agents", colorClass: "text-agent-planner" },
      { label: "researcher", href: "#agents", colorClass: "text-agent-researcher" },
      { label: "analyst", href: "#agents", colorClass: "text-agent-analyst" },
      { label: "critic", href: "#agents", colorClass: "text-agent-critic" },
      { label: "writer", href: "#agents", colorClass: "text-agent-writer" },
    ],
  },
  {
    title: "─ Sources",
    links: [
      { label: "arXiv MCP", href: "#stack" },
      { label: "NVD MCP", href: "#stack" },
      { label: "MITRE ATLAS", href: "#stack" },
      { label: "OWASP LLM Top 10", href: "#metrics" },
    ],
  },
  {
    title: "─ Docs",
    links: [
      {
        label: "GitHub ↗",
        href: "https://github.com/YoussefChaouki/Nexus",
        external: true,
      },
    ],
  },
];

export function LandingFooter() {
  return (
    <footer className="px-ds-6 pt-ds-8 pb-ds-7 text-fg-faint text-[11px] tracking-[0.08em] uppercase">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-ds-6 pb-ds-6 border-b border-border">
        {COLS.map((col) => (
          <div key={col.title}>
            <h4 className="m-0 mb-[14px] text-[10.5px] text-fg-muted tracking-[0.16em] font-medium">
              {col.title}
            </h4>
            {col.links.map((l) =>
              l.external ? (
                <a
                  key={l.label}
                  href={l.href}
                  target="_blank"
                  rel="noreferrer noopener"
                  className={`block ${l.colorClass ?? "text-fg-muted"} text-[11.5px] normal-case tracking-[0.02em] mb-[6px] hover:text-fg transition-colors`}
                >
                  {l.label}
                </a>
              ) : (
                <Link
                  key={l.label}
                  href={l.href as never}
                  className={`block ${l.colorClass ?? "text-fg-muted"} text-[11.5px] normal-case tracking-[0.02em] mb-[6px] hover:text-fg transition-colors`}
                >
                  {l.label}
                </Link>
              ),
            )}
          </div>
        ))}
      </div>
      <div className="mt-ds-6 flex justify-between flex-wrap gap-ds-3">
        <span className="text-fg-muted font-medium tracking-[0.1em]">
          <span className="text-accent">nexus</span>
          {" // multi-agent threat-surface analyzer · v0.7.1"}
        </span>
        <span>
          © {new Date().getFullYear()} youssef chaouki · build sha:a8f3c2e
        </span>
      </div>
    </footer>
  );
}
