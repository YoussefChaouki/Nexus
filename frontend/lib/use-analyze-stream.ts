"use client";

import { useEffect, useRef, useState } from "react";
import { AgentEvent } from "./schemas";
import { buildStreamUrl } from "./api";

// Frontend-derived state aggregated from the SSE event stream.
// The backend only sends *_count summaries — we keep the running ledger here.
export interface StreamState {
  status: "connecting" | "streaming" | "completed" | "error";
  events: AgentEvent[];
  activeAgent: string | null;
  iteration: number;
  planCount: number;
  findingsCount: number;
  surfacesCount: number;
  criticScore: number | null;
  reportId: string | null;
  error: string | null;
  startedAt: number | null;
}

const INITIAL: StreamState = {
  status: "connecting",
  events: [],
  activeAgent: null,
  iteration: 0,
  planCount: 0,
  findingsCount: 0,
  surfacesCount: 0,
  criticScore: null,
  reportId: null,
  error: null,
  startedAt: null,
};

export function useAnalyzeStream(
  targetDescription: string | null,
  sessionId: string | null,
): StreamState {
  const [state, setState] = useState<StreamState>(INITIAL);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!targetDescription || !sessionId) return;
    setState({ ...INITIAL, startedAt: Date.now() });

    const url = buildStreamUrl(targetDescription, sessionId);
    const es = new EventSource(url);
    esRef.current = es;

    es.onmessage = (msg: MessageEvent<string>) => {
      try {
        const parsed = AgentEvent.parse(JSON.parse(msg.data));
        setState((prev) => applyEvent(prev, parsed, es));
      } catch {
        // Malformed frame — ignore; the next valid one will resync.
      }
    };
    es.onerror = () => {
      setState((prev) =>
        prev.status === "completed"
          ? prev
          : { ...prev, status: "error", error: "stream lost" },
      );
      es.close();
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [targetDescription, sessionId]);

  return state;
}

function applyEvent(prev: StreamState, ev: AgentEvent, es: EventSource): StreamState {
  const next: StreamState = { ...prev, events: [...prev.events, ev] };

  if (ev.event_type === "started") {
    next.status = "streaming";
    return next;
  }

  if (ev.event_type === "error") {
    const err = ev.payload["error"];
    next.status = "error";
    next.error = typeof err === "string" ? err : "pipeline failure";
    es.close();
    return next;
  }

  if (ev.event_type === "completed") {
    next.status = "completed";
    es.close();
    return next;
  }

  // node_completed — pull counters from payload.
  if (ev.agent !== "pipeline") next.activeAgent = ev.agent;
  const p = ev.payload;
  if (typeof p["iteration_count"] === "number") next.iteration = p["iteration_count"];
  if (typeof p["plan_count"] === "number") next.planCount = p["plan_count"];
  if (typeof p["findings_count"] === "number") next.findingsCount = p["findings_count"];
  if (typeof p["threat_surfaces_count"] === "number") next.surfacesCount = p["threat_surfaces_count"];
  if (typeof p["critic_score"] === "number") next.criticScore = p["critic_score"];
  if (typeof p["report_id"] === "string") next.reportId = p["report_id"];

  return next;
}
