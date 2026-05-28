import Link from "next/link";
import { Pill } from "@/components/ui/pill";
import { StatusBar, StatusItem, StatusSep } from "@/components/ui/status-bar";
import { SeverityBadge } from "@/components/ui/badge";
import {
  listReports,
  ApiError,
  type ListReportsParams,
} from "@/lib/api";
import {
  FocusAreaEnum,
  SeverityEnum,
  type FocusArea,
  type Severity,
  type ThreatReportSummary,
} from "@/lib/schemas";

export const dynamic = "force-dynamic";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FOCUS_AREAS: FocusArea[] = [
  "injection",
  "data_leakage",
  "supply_chain",
  "dos",
  "model_extraction",
  "other",
];

const PAGE_SIZE = 50;

interface SearchParams {
  severity?: string;
  focus_area?: string;
  offset?: string;
}

function parseFilters(searchParams: SearchParams): ListReportsParams {
  const params: ListReportsParams = { limit: PAGE_SIZE, offset: 0 };
  if (searchParams.severity) {
    const sev = SeverityEnum.safeParse(searchParams.severity);
    if (sev.success) params.severity = sev.data;
  }
  if (searchParams.focus_area) {
    const fa = FocusAreaEnum.safeParse(searchParams.focus_area);
    if (fa.success) params.focus_area = fa.data;
  }
  if (searchParams.offset) {
    const n = Number.parseInt(searchParams.offset, 10);
    if (Number.isFinite(n) && n >= 0) params.offset = n;
  }
  return params;
}

interface LoadResult {
  rows: ThreatReportSummary[] | null;
  error: "unavailable" | "fetch_failed" | null;
}

async function loadReports(params: ListReportsParams): Promise<LoadResult> {
  try {
    const rows = await listReports(params);
    return { rows, error: null };
  } catch (err) {
    if (err instanceof ApiError && err.status === 503) {
      return { rows: null, error: "unavailable" };
    }
    return { rows: null, error: "fetch_failed" };
  }
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().replace("T", " ").slice(0, 16) + "Z";
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max - 1) + "…";
}

function buildHref(filters: ListReportsParams, overrides: Partial<ListReportsParams>): string {
  const merged = { ...filters, ...overrides, limit: undefined };
  const qs = new URLSearchParams();
  if (merged.severity) qs.set("severity", merged.severity);
  if (merged.focus_area) qs.set("focus_area", merged.focus_area);
  if (merged.offset && merged.offset > 0) qs.set("offset", String(merged.offset));
  const suffix = qs.toString();
  return suffix ? `/history?${suffix}` : "/history";
}

export default async function HistoryPage({
  searchParams,
}: {
  searchParams: SearchParams;
}) {
  const filters = parseFilters(searchParams);
  const { rows, error } = await loadReports(filters);
  const count = rows?.length ?? 0;
  const offset = filters.offset ?? 0;
  const hasPrev = offset > 0;
  const hasNext = count === PAGE_SIZE;

  const statusTone =
    error === "unavailable" ? "warn" : error === "fetch_failed" ? "live" : "complete";
  const statusBackend =
    error === "unavailable"
      ? "GET /reports — 503"
      : error === "fetch_failed"
        ? "GET /reports — fetch failed"
        : "GET /reports — 200";

  return (
    <>
      <StatusBar>
        <Pill tone={statusTone}>History</Pill>
        <StatusSep />
        <StatusItem label="Source">episodic memory (pgvector)</StatusItem>
        <StatusSep />
        <StatusItem label="Backend">{statusBackend}</StatusItem>
        <span className="ml-auto">
          <StatusItem label="Items">
            <span className="tabular">{count}</span>
          </StatusItem>
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

          {error === "unavailable" ? (
            <EmptyState
              title="Backend unavailable"
              body="The /reports endpoint reported the episodic memory pool is not reachable. Check the API logs or `docker compose ps postgres`."
            />
          ) : error === "fetch_failed" ? (
            <EmptyState
              title="Could not load history"
              body="The frontend failed to talk to the API. Make sure `make dev` is running on :8000."
            />
          ) : !rows || rows.length === 0 ? (
            <EmptyState
              title="No runs to display yet"
              body={
                filters.severity || filters.focus_area
                  ? "No runs match the active filters. Clear them to see all past runs."
                  : "Past ThreatReportSummary entries persisted by the Writer will appear here once you run an analysis."
              }
            />
          ) : (
            <table className="w-full border-collapse text-[12.5px]">
              <thead>
                <tr className="text-fg-faint text-[10.5px] uppercase tracking-[0.12em]">
                  <th className="text-left px-ds-5 py-ds-3 border-b border-border font-medium">
                    Created
                  </th>
                  <th className="text-left px-ds-5 py-ds-3 border-b border-border font-medium">
                    Target
                  </th>
                  <th className="text-right px-ds-5 py-ds-3 border-b border-border font-medium tabular">
                    Surfaces
                  </th>
                  <th className="text-left px-ds-5 py-ds-3 border-b border-border font-medium">
                    Severity
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr
                    key={row.id}
                    className="border-b border-border last:border-b-0 hover:bg-bg-elev transition-colors"
                  >
                    <td className="px-ds-5 py-ds-3 tabular text-fg-muted whitespace-nowrap">
                      {formatTimestamp(row.created_at)}
                    </td>
                    <td className="px-ds-5 py-ds-3">
                      <Link
                        href={`/reports/${encodeURIComponent(row.id)}` as never}
                        className="text-fg hover:text-accent transition-colors"
                      >
                        {truncate(row.target_description, 80)}
                      </Link>
                    </td>
                    <td className="px-ds-5 py-ds-3 text-right tabular text-fg-muted">
                      {row.surface_count}
                    </td>
                    <td className="px-ds-5 py-ds-3">
                      <div className="flex flex-wrap gap-ds-2">
                        {SEVERITIES.map((sev) =>
                          (row.severity_breakdown[sev] ?? 0) > 0 ? (
                            <SeverityBadge
                              key={sev}
                              severity={sev}
                              count={row.severity_breakdown[sev]}
                            />
                          ) : null,
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {(hasPrev || hasNext) && rows && rows.length > 0 && (
            <footer className="flex items-center justify-between px-ds-5 py-ds-3 border-t border-border text-[11px] uppercase tracking-[0.1em] text-fg-muted">
              <span>
                offset <span className="tabular text-fg">{offset}</span> · page size{" "}
                <span className="tabular text-fg">{PAGE_SIZE}</span>
              </span>
              <div className="flex gap-ds-3">
                {hasPrev ? (
                  <Link
                    href={
                      buildHref(filters, { offset: Math.max(0, offset - PAGE_SIZE) }) as never
                    }
                    className="text-accent hover:underline"
                  >
                    ◀ Prev
                  </Link>
                ) : (
                  <span className="text-fg-faint">◀ Prev</span>
                )}
                {hasNext ? (
                  <Link
                    href={buildHref(filters, { offset: offset + PAGE_SIZE }) as never}
                    className="text-accent hover:underline"
                  >
                    Next ▶
                  </Link>
                ) : (
                  <span className="text-fg-faint">Next ▶</span>
                )}
              </div>
            </footer>
          )}
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
              {SEVERITIES.map((sev) => {
                const active = filters.severity === sev;
                return (
                  <Link
                    key={sev}
                    href={
                      buildHref(filters, {
                        severity: active ? undefined : sev,
                        offset: 0,
                      }) as never
                    }
                    aria-pressed={active}
                    className={
                      active
                        ? "ring-1 ring-accent ring-offset-1 ring-offset-bg-card rounded-sm"
                        : "opacity-80 hover:opacity-100"
                    }
                  >
                    <SeverityBadge severity={sev} />
                  </Link>
                );
              })}
            </div>
          </div>
          <div className="px-ds-4 py-ds-4 border-t border-border">
            <div className="text-[10.5px] uppercase tracking-[0.1em] text-fg-faint mb-ds-3">
              Focus area
            </div>
            <ul className="space-y-[6px] text-[12px]">
              {FOCUS_AREAS.map((fa) => {
                const active = filters.focus_area === fa;
                return (
                  <li key={fa}>
                    <Link
                      href={
                        buildHref(filters, {
                          focus_area: active ? undefined : fa,
                          offset: 0,
                        }) as never
                      }
                      className={
                        active
                          ? "text-accent"
                          : "text-fg-muted hover:text-fg transition-colors"
                      }
                    >
                      {active ? "▸ " : ""}
                      {fa.replace("_", " ")}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
          {(filters.severity || filters.focus_area) && (
            <div className="px-ds-4 py-ds-3 border-t border-border">
              <Link
                href="/history"
                className="text-[11px] uppercase tracking-[0.12em] text-fg-muted hover:text-accent transition-colors"
              >
                ✕ Clear filters
              </Link>
            </div>
          )}
        </aside>
      </div>
    </>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="px-ds-6 py-ds-9 text-center">
      <div className="text-fg-faint text-[10.5px] uppercase tracking-[0.14em] mb-ds-3">
        ─ empty state
      </div>
      <h2 className="text-h3 text-fg m-0">{title}</h2>
      <p className="text-fg-muted text-[13px] leading-[1.7] mt-ds-3 max-w-[460px] mx-auto">
        {body}
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
  );
}
