import {
  FocusArea,
  Severity,
  ThreatReport,
  ThreatReportSummary,
  ThreatReportSummaryList,
} from "./schemas";

export interface ListReportsParams {
  limit?: number;
  offset?: number;
  severity?: Severity;
  focus_area?: FocusArea;
}

export const API_BASE =
  process.env.NEXT_PUBLIC_NEXUS_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function jsonFetch<T>(
  path: string,
  init?: RequestInit,
  parser?: { parse: (data: unknown) => T },
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    throw new ApiError(res.status, `${path} → ${res.status}`);
  }
  const data: unknown = await res.json();
  return parser ? parser.parse(data) : (data as T);
}

export async function postAnalyze(targetDescription: string, sessionId?: string) {
  return jsonFetch(
    "/analyze",
    {
      method: "POST",
      body: JSON.stringify({
        target_description: targetDescription,
        session_id: sessionId,
      }),
    },
    ThreatReport,
  );
}

export async function getReportSummary(reportId: string) {
  return jsonFetch(`/report/${encodeURIComponent(reportId)}`, undefined, ThreatReportSummary);
}

export async function listReports(params: ListReportsParams = {}) {
  const qs = new URLSearchParams();
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  if (params.severity) qs.set("severity", params.severity);
  if (params.focus_area) qs.set("focus_area", params.focus_area);
  const suffix = qs.toString();
  const path = suffix ? `/reports?${suffix}` : "/reports";
  return jsonFetch(path, undefined, ThreatReportSummaryList);
}

export function buildStreamUrl(targetDescription: string, sessionId: string): string {
  const qs = new URLSearchParams({
    target_description: targetDescription,
    session_id: sessionId,
  });
  return `${API_BASE}/analyze/stream?${qs.toString()}`;
}
