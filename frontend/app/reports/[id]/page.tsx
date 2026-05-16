import { notFound } from "next/navigation";
import { ApiError, getReportSummary } from "@/lib/api";
import { ReportView } from "@/components/report/report-view";

interface Props {
  params: { id: string };
}

// Server-rendered: the summary endpoint is hit once on each navigation,
// then the rich UI (expandable rows, copy-JSON, etc.) hydrates client-side.
export default async function ReportPage({ params }: Props) {
  let summary;
  try {
    summary = await getReportSummary(params.id);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      return <ReportMissing id={params.id} />;
    }
    return <ReportError id={params.id} message={(err as Error).message} />;
  }
  if (!summary) notFound();

  return <ReportView report={summary} />;
}

function ReportMissing({ id }: { id: string }) {
  return (
    <div className="border border-border bg-bg-card px-ds-6 py-ds-7 mt-ds-6">
      <div className="text-[10.5px] uppercase tracking-[0.12em] text-fg-faint mb-ds-3">
        ─ 404
      </div>
      <h1 className="text-h2 text-fg m-0">Report not in episodic memory</h1>
      <p className="text-fg-muted text-[13px] leading-[1.7] mt-ds-3 max-w-[640px]">
        No report stored with id <code className="text-accent">{id}</code>.
        Episodic memory stores a <em className="not-italic text-accent">ThreatReportSummary</em>{" "}
        only once the writer agent completes — and only when Postgres /
        pgvector is reachable. Check that the backend has a running pool
        and that the run reached the writer stage.
      </p>
    </div>
  );
}

function ReportError({ id, message }: { id: string; message: string }) {
  return (
    <div className="border border-sev-critical/40 bg-bg-card px-ds-6 py-ds-6 mt-ds-6">
      <div className="text-[10.5px] uppercase tracking-[0.12em] text-sev-critical mb-ds-3">
        ─ fetch failed
      </div>
      <h1 className="text-h2 text-fg m-0">Could not load {id}</h1>
      <p className="text-fg-muted text-[13px] leading-[1.7] mt-ds-3 max-w-[640px]">
        {message}
      </p>
    </div>
  );
}
