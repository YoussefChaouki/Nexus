import Link from "next/link";
import { Pill } from "@/components/ui/pill";
import { StatusBar, StatusItem, StatusSep } from "@/components/ui/status-bar";
import { SeverityBadge } from "@/components/ui/badge";

// The backend currently exposes /report/{id} only; a list endpoint is
// planned. Until then this page renders the empty-state shell so the
// design is in place and the eventual wiring is a one-line swap.
export default function HistoryPage() {
  return (
    <>
      <StatusBar>
        <Pill tone="idle">History</Pill>
        <StatusSep />
        <StatusItem label="Source">episodic memory (pgvector)</StatusItem>
        <StatusSep />
        <StatusItem label="Backend">GET /reports — planned</StatusItem>
        <span className="ml-auto">
          <StatusItem label="Items"><span className="tabular">0</span></StatusItem>
        </span>
      </StatusBar>

      <header className="mt-ds-7 mb-ds-6 flex items-baseline gap-ds-4 pb-ds-3 border-b border-border">
        <span className="text-fg-faint text-[11px] tracking-[0.16em] tabular font-medium">
          02 //
        </span>
        <h1 className="text-h2 text-fg m-0">Past runs</h1>
        <span className="ml-auto text-fg-faint text-[10.5px] uppercase tracking-[0.12em]">
          episodic · most recent first
        </span>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-ds-5">
        <section className="border border-border bg-bg-card">
          <header className="px-ds-5 py-ds-3 border-b border-border text-[11px] uppercase tracking-[0.1em] text-fg-muted">
            tail -f /var/log/nexus/runs.log
          </header>

          <div className="px-ds-6 py-ds-9 text-center">
            <div className="text-fg-faint text-[10.5px] uppercase tracking-[0.14em] mb-ds-3">
              ─ empty state
            </div>
            <h2 className="text-h3 text-fg m-0">No runs to display yet</h2>
            <p className="text-fg-muted text-[13px] leading-[1.7] mt-ds-3 max-w-[460px] mx-auto">
              Past <em className="not-italic text-accent">ThreatReportSummary</em>{" "}
              entries persisted by the Writer agent will appear here. The
              backend list endpoint is still pending — once it lands, this
              page will paginate them by recency and let you filter on
              severity / focus area.
            </p>
            <div className="mt-ds-5 inline-flex gap-ds-3">
              <Link
                href="/"
                className="px-[18px] py-[11px] border border-accent bg-accent/[0.06] text-accent text-[12px] uppercase tracking-[0.14em] font-semibold hover:bg-accent hover:text-bg transition-colors duration-100"
              >
                ▶ Start a new analysis
              </Link>
            </div>
          </div>
        </section>

        <aside className="border border-border bg-bg-card h-fit">
          <header className="px-ds-4 py-ds-3 border-b border-border text-[11px] uppercase tracking-[0.1em] text-fg-muted">
            Filters
          </header>
          <div className="px-ds-4 py-ds-4">
            <div className="text-[10.5px] uppercase tracking-[0.1em] text-fg-faint mb-ds-3">
              Severity
            </div>
            <div className="flex flex-wrap gap-ds-2">
              <SeverityBadge severity="critical" count={0} />
              <SeverityBadge severity="high" count={0} />
              <SeverityBadge severity="medium" count={0} />
              <SeverityBadge severity="low" count={0} />
            </div>
          </div>
          <div className="px-ds-4 py-ds-4 border-t border-border">
            <div className="text-[10.5px] uppercase tracking-[0.1em] text-fg-faint mb-ds-3">
              Focus area
            </div>
            <ul className="space-y-[6px] text-fg-muted text-[12px]">
              <li>injection</li>
              <li>data leakage</li>
              <li>supply chain</li>
              <li>denial of service</li>
              <li>model extraction</li>
            </ul>
          </div>
        </aside>
      </div>
    </>
  );
}
