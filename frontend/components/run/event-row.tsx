import { cn } from "@/lib/cn";
import type { AgentEvent } from "@/lib/schemas";
import { isKnownAgent } from "@/lib/schemas";

const AGENT_COLOR: Record<string, string> = {
  planner: "text-agent-planner",
  researcher: "text-agent-researcher",
  analyst: "text-agent-analyst",
  critic: "text-agent-critic",
  writer: "text-agent-writer",
  pipeline: "text-fg-faint",
};

interface EventRowProps {
  event: AgentEvent;
  startedAt: number;
  isLast: boolean;
}

export function EventRow({ event, startedAt, isLast }: EventRowProps) {
  const elapsed = new Date(event.timestamp).getTime() - startedAt;
  const elapsedSec = Math.max(0, elapsed) / 1000;
  const stamp = `${Math.floor(elapsedSec / 60)
    .toString()
    .padStart(2, "0")}:${(elapsedSec % 60).toFixed(3).padStart(6, "0")}`;
  const agentColor = AGENT_COLOR[event.agent] ?? "text-fg-muted";
  const description = describeEvent(event);

  return (
    <div
      className={cn(
        "grid grid-cols-[90px_116px_1fr] gap-ds-4 px-ds-5 py-[8px]",
        "items-baseline text-[12.5px] border-l-2",
        isLast && event.event_type !== "completed" && event.event_type !== "error"
          ? "bg-agent-writer/[0.04] border-agent-writer"
          : "border-transparent",
      )}
    >
      <span className="text-fg-faint text-[11px] tabular">{stamp}</span>
      <span
        className={cn(
          "text-[10.5px] uppercase tracking-[0.1em] font-semibold",
          "px-ds-2 py-px border border-current text-center",
          agentColor,
        )}
      >
        {event.agent}
      </span>
      <span className="text-fg">
        <span className="text-fg-faint mr-ds-2">▸</span>
        {description}
        {isLast &&
          event.event_type !== "completed" &&
          event.event_type !== "error" &&
          isKnownAgent(event.agent) && (
            <span className="text-agent-writer ml-ds-2 animate-blink">▊</span>
          )}
      </span>
    </div>
  );
}

function describeEvent(event: AgentEvent): React.ReactNode {
  const p = event.payload;

  if (event.event_type === "started") {
    return (
      <>
        pipeline initiated · target accepted (
        <span className="text-fg font-medium tabular">
          {typeof p["target_description"] === "string"
            ? `${(p["target_description"] as string).length} chars`
            : "—"}
        </span>
        )
      </>
    );
  }
  if (event.event_type === "completed") {
    return <span className="text-agent-writer">pipeline complete — report ready</span>;
  }
  if (event.event_type === "error") {
    return (
      <span className="text-sev-critical">
        error · {String(p["error_type"] ?? "AgentError")}:{" "}
        {String(p["error"] ?? "pipeline failure")}
      </span>
    );
  }

  // node_completed — describe based on agent + counts.
  const parts: React.ReactNode[] = [];
  switch (event.agent) {
    case "planner":
      if (typeof p["plan_count"] === "number") {
        parts.push(
          <>
            decomposed target into{" "}
            <Num value={p["plan_count"] as number} /> research task
            {p["plan_count"] === 1 ? "" : "s"}
          </>,
        );
      } else {
        parts.push("planning research tasks");
      }
      break;
    case "researcher":
      if (typeof p["findings_count"] === "number") {
        parts.push(
          <>
            collected <Num value={p["findings_count"] as number} /> finding
            {p["findings_count"] === 1 ? "" : "s"} from MCP sources
          </>,
        );
      } else {
        parts.push("querying arxiv / nvd / atlas");
      }
      break;
    case "analyst":
      if (typeof p["threat_surfaces_count"] === "number") {
        parts.push(
          <>
            synthesized <Num value={p["threat_surfaces_count"] as number} />{" "}
            threat surface
            {p["threat_surfaces_count"] === 1 ? "" : "s"}
          </>,
        );
      } else {
        parts.push("scoring surfaces");
      }
      break;
    case "critic": {
      const rec = p["critic_recommendation"];
      const score = p["critic_score"];
      if (typeof rec === "string" && typeof score === "number") {
        const isApprove = rec === "approve";
        parts.push(
          <>
            score=<span className="tabular font-medium">{score.toFixed(2)}</span>{" "}
            <span
              className={
                isApprove ? "text-agent-writer font-medium" : "text-sev-high font-medium"
              }
            >
              · {rec.replace("_", "-")}
            </span>
          </>,
        );
      } else {
        parts.push("auditing report quality");
      }
      break;
    }
    case "writer":
      if (typeof p["report_id"] === "string") {
        parts.push(
          <>
            wrote final report{" "}
            <span className="text-accent">
              {(p["report_id"] as string).slice(0, 8)}
            </span>
          </>,
        );
      } else {
        parts.push("composing report");
      }
      break;
    default:
      parts.push(event.event_type);
  }
  if (typeof p["iteration_count"] === "number" && (p["iteration_count"] as number) > 0) {
    parts.push(
      <span className="text-fg-faint ml-ds-2">
        iter <Num value={p["iteration_count"] as number} />
      </span>,
    );
  }
  return <>{parts}</>;
}

function Num({ value }: { value: number }) {
  return <span className="text-fg font-medium tabular">{value}</span>;
}
