"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { Pill } from "@/components/ui/pill";
import { StatusBar, StatusItem, StatusSep } from "@/components/ui/status-bar";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SeverityRow } from "./severity-row";
import { MetaChip } from "./meta-chip";
import { SurfaceList } from "./surface-list";
import type { ThreatReportSummary } from "@/lib/schemas";
import { shortId } from "@/lib/format";
import { langfuseTraceUrl } from "@/lib/langfuse";

interface Props {
  report: ThreatReportSummary;
}

const FOCUS_LABEL: Record<string, string> = {
  injection: "injection",
  data_leakage: "data leakage",
  supply_chain: "supply chain",
  dos: "denial of service",
  model_extraction: "model extraction",
  other: "other",
};

export function ReportView({ report }: Props) {
  const router = useRouter();
  const total = Object.values(report.severity_breakdown).reduce(
    (acc, v) => acc + v,
    0,
  );
  const traceUrl = langfuseTraceUrl(report.id);

  return (
    <>
      <StatusBar>
        <Pill tone="complete">Analysis complete</Pill>
        <StatusSep />
        <StatusItem label="Run">{shortId(report.id)}</StatusItem>
        <StatusSep />
        <StatusItem label="Surfaces">
          <span className="tabular">{report.surface_count}</span>
        </StatusItem>
        <StatusSep />
        <StatusItem label="Findings">
          <span className="tabular">{total}</span>
        </StatusItem>
        <span className="ml-auto">
          {traceUrl ? (
            <a
              href={traceUrl}
              target="_blank"
              rel="noreferrer noopener"
              className="text-accent border-b border-dotted border-current"
            >
              ↗ langfuse trace
            </a>
          ) : (
            <span
              className="text-fg-faint uppercase tracking-[0.08em] text-[10.5px]"
              title="Set NEXT_PUBLIC_LANGFUSE_HOST in frontend/.env.local to enable"
            >
              langfuse — not configured
            </span>
          )}
        </span>
      </StatusBar>

      <section className="mt-ds-4 border border-border bg-bg-card px-ds-6 py-ds-6">
        <header className="flex items-center justify-between mb-ds-5 flex-wrap gap-ds-2">
          <div className="text-[11px] uppercase tracking-[0.1em] text-agent-writer before:content-['●_']">
            Report ready
          </div>
          <div className="text-[11px] text-fg-faint tracking-[0.06em] tabular">
            {formatDate(report.created_at)} · id:{shortId(report.id)}
          </div>
        </header>

        <blockquote className="text-[15px] text-fg leading-[1.65] mb-ds-6 pl-ds-3 border-l-2 border-accent">
          <div className="text-[10.5px] tracking-[0.12em] text-fg-faint mb-[6px]">
            TARGET /
          </div>
          {report.target_description}
        </blockquote>

        <div className="flex items-center gap-ds-3 flex-wrap">
          <SeverityRow breakdown={report.severity_breakdown} />
          <span className="ml-auto inline-flex gap-ds-2 flex-wrap">
            <MetaChip label="Surfaces" value={report.surface_count} />
            <MetaChip label="Focus areas" value={report.focus_areas_covered.length} />
            <MetaChip label="Vectors" value={report.top_attack_vectors.length} />
          </span>
        </div>

        {report.focus_areas_covered.length > 0 && (
          <div className="mt-ds-6 flex items-center gap-ds-2 flex-wrap">
            <span className="text-[10.5px] uppercase tracking-[0.14em] text-fg-faint mr-ds-2">
              ─ focus areas covered
            </span>
            {report.focus_areas_covered.map((f) => (
              <Badge key={f} tone="agent-researcher">
                {FOCUS_LABEL[f] ?? f}
              </Badge>
            ))}
          </div>
        )}
      </section>

      <section className="mt-ds-6">
        <div className="flex items-center gap-ds-3 mb-ds-4">
          <span aria-hidden className="text-fg-faint">─</span>
          <span className="text-[11px] uppercase tracking-[0.16em] text-fg-muted font-medium">
            Top attack vectors · {report.top_attack_vectors.length}
          </span>
          <span className="flex-1 h-px bg-border" />
          <span className="text-[10.5px] text-fg-faint tracking-[0.08em]">
            click to expand
          </span>
        </div>
        <SurfaceList vectors={report.top_attack_vectors} />
      </section>

      <footer className="mt-ds-6 border border-border bg-bg-deep px-ds-5 py-ds-4 flex items-center justify-between gap-ds-5 flex-wrap text-[11px] text-fg-muted tracking-[0.04em]">
        <div className="flex gap-ds-5 flex-wrap">
          <FooterStat label="Report ID" value={shortId(report.id)} />
          <FooterStat label="Surfaces" value={report.surface_count} />
          <FooterStat label="Critical" value={report.severity_breakdown.critical ?? 0} />
          <FooterStat label="High" value={report.severity_breakdown.high ?? 0} />
        </div>
        <div className="flex gap-ds-3 flex-wrap">
          <Button variant="primary" onClick={() => router.push("/")}>
            ▶ Re-run
          </Button>
          <Button
            variant="secondary"
            onClick={() => {
              navigator.clipboard?.writeText(JSON.stringify(report, null, 2));
            }}
          >
            Copy JSON
          </Button>
          {traceUrl && (
            <Link
              href={traceUrl as never}
              target="_blank"
              rel="noreferrer noopener"
              className="border border-transparent px-[18px] py-[11px] text-[12px] uppercase tracking-[0.14em] font-medium text-fg-muted hover:text-fg hover:border-border"
            >
              ↗ Open in Langfuse
            </Link>
          )}
        </div>
      </footer>
    </>
  );
}

function FooterStat({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <span className="uppercase tracking-[0.08em]">
      {label}
      <strong className="text-fg font-medium ml-[6px] tabular">{value}</strong>
    </span>
  );
}

function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    return `${d.toISOString().slice(0, 19).replace("T", " ")} UTC`;
  } catch {
    return iso;
  }
}
