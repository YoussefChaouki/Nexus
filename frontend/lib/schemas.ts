import { z } from "zod";

// Mirrors src/nexus/schemas/models.py. Kept narrow on purpose — only
// the fields the frontend actually reads. Unknown extra keys are stripped.

export const FocusAreaEnum = z.enum([
  "injection",
  "data_leakage",
  "supply_chain",
  "dos",
  "model_extraction",
  "other",
]);
export type FocusArea = z.infer<typeof FocusAreaEnum>;

export const PriorityEnum = z.enum(["high", "medium", "low"]);
export const SourceTypeEnum = z.enum(["arxiv", "nvd", "atlas", "web"]);
export const SeverityEnum = z.enum(["critical", "high", "medium", "low"]);
export const RecommendationEnum = z.enum(["approve", "re_research"]);

export type Severity = z.infer<typeof SeverityEnum>;
export type SourceType = z.infer<typeof SourceTypeEnum>;

export const FindingResult = z.object({
  id: z.string(),
  task_id: z.string(),
  source_type: SourceTypeEnum,
  title: z.string(),
  summary: z.string(),
  relevance_score: z.number(),
  url: z.string().nullable().optional(),
  identifiers: z.array(z.string()).default([]),
});
export type FindingResult = z.infer<typeof FindingResult>;

export const ThreatSurface = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  severity: SeverityEnum,
  attack_vectors: z.array(z.string()).default([]),
  evidence: z.array(FindingResult).default([]),
  mitigations: z.array(z.string()).default([]),
  cvss_score: z.number().nullable().optional(),
  owasp_category: z.string().nullable().optional(),
});
export type ThreatSurface = z.infer<typeof ThreatSurface>;

export const CriticReport = z.object({
  overall_score: z.number(),
  gaps: z.array(z.string()).default([]),
  bias_warnings: z.array(z.string()).default([]),
  recommendation: RecommendationEnum,
  re_research_tasks: z.array(z.unknown()).default([]),
});
export type CriticReport = z.infer<typeof CriticReport>;

export const ThreatReport = z.object({
  id: z.string(),
  target_description: z.string(),
  created_at: z.string(),
  threat_surfaces: z.array(ThreatSurface).default([]),
  critic_report: CriticReport,
  iteration_count: z.number(),
  metadata: z.record(z.unknown()).default({}),
});
export type ThreatReport = z.infer<typeof ThreatReport>;

export const ThreatReportSummary = z.object({
  id: z.string(),
  session_id: z.string().optional(),
  target_description: z.string(),
  created_at: z.string(),
  surface_count: z.number(),
  severity_breakdown: z.record(z.number()).default({}),
  focus_areas_covered: z.array(FocusAreaEnum).default([]),
  top_attack_vectors: z.array(z.string()).default([]),
  overall_critic_score: z.number().optional(),
  iteration_count: z.number().optional(),
});
export type ThreatReportSummary = z.infer<typeof ThreatReportSummary>;

export const ThreatReportSummaryList = z.array(ThreatReportSummary);
export type ThreatReportSummaryList = z.infer<typeof ThreatReportSummaryList>;

// SSE event from GET /analyze/stream.
// agent ∈ {pipeline, planner, researcher, analyst, critic, writer}
// event_type ∈ {started, node_completed, error, completed}
export const AgentEvent = z.object({
  session_id: z.string(),
  agent: z.string(),
  event_type: z.string(),
  payload: z.record(z.unknown()).default({}),
  timestamp: z.string(),
});
export type AgentEvent = z.infer<typeof AgentEvent>;

export const AGENT_NAMES = [
  "planner",
  "researcher",
  "analyst",
  "writer",
  "critic",
] as const;
export type AgentName = (typeof AGENT_NAMES)[number];

export function isKnownAgent(name: string): name is AgentName {
  return (AGENT_NAMES as readonly string[]).includes(name);
}
