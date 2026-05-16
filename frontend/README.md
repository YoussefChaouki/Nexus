# Nexus // Frontend

Next.js 14 frontend for the NEXUS multi-agent threat-surface analyzer.

Aesthetic: **threat intel terminal**. Dark-only, monospace-only (JetBrains Mono),
hairlines instead of cards-with-shadows, zero border-radius, dense rows in
generous negative space. Tokens come from
[`/tmp/nexus_design/nexus/project/Design System.html`](../) (Claude Design
handoff bundle) and live in `tailwind.config.ts` + `app/globals.css`.

## Pages

| Route                | Purpose                                                                |
| -------------------- | ---------------------------------------------------------------------- |
| `/`                  | Prompt textarea, example chips, "Execute analysis" → starts a run.     |
| `/runs/[id]`         | Live SSE feed (event timeline + per-agent stats sidebar).              |
| `/reports/[id]`      | Summary of a completed run (target, severity counters, top vectors).   |
| `/history`           | Past runs (placeholder until backend `GET /reports` lands).            |

## Stack

- **Next 14** App Router, TypeScript `strict`, server components by default.
- **Tailwind 3.4** with full design tokens (surfaces / agents / severity / accent).
- **shadcn-style primitives** built in-tree (`components/ui/*`) using
  `class-variance-authority` + `clsx` + `tailwind-merge`. No shadcn install — every
  primitive matches the design system 1:1 instead of fighting defaults.
- **Zod** schemas in `lib/schemas.ts` mirror the Pydantic models in
  `src/nexus/schemas/models.py` (single source of truth, no drift on parsing).
- **EventSource** (browser-native) for the SSE consumer in
  `lib/use-analyze-stream.ts`. No third-party SSE lib.

## Getting started

```bash
cd frontend
cp .env.local.example .env.local         # NEXT_PUBLIC_NEXUS_API_URL=http://localhost:8000
npm install
npm run dev                              # → http://localhost:3000
```

The FastAPI backend must be running on the URL set in `.env.local`. Start it
from the repo root with `make dev` (or `uvicorn nexus.api.main:app --reload`).

CORS on the backend already whitelists `http://localhost:3000`
(see `src/nexus/api/main.py`).

## Scripts

| Command         | What it does                                |
| --------------- | ------------------------------------------- |
| `npm run dev`   | Next dev server with HMR.                   |
| `npm run build` | Production build (also runs `tsc`).         |
| `npm run start` | Serve the production build.                 |
| `npm run lint`  | `eslint` via `next lint`.                   |
| `npm run typecheck` | `tsc --noEmit` (strict mode).           |

## File layout

```
frontend/
├── app/
│   ├── layout.tsx                  Root layout · Nav · footer
│   ├── globals.css                 Tokens · base body · JetBrains Mono import
│   ├── page.tsx                    Home (input)
│   ├── runs/[id]/page.tsx          Live SSE
│   ├── reports/[id]/page.tsx       Report viewer
│   └── history/page.tsx            Past runs
├── components/
│   ├── nav.tsx                     Sticky brand bar + tabs
│   ├── ui/                         Design-system primitives
│   │   ├── button.tsx
│   │   ├── badge.tsx
│   │   ├── pill.tsx
│   │   ├── terminal-card.tsx
│   │   ├── mono-tag.tsx
│   │   ├── prompt-textarea.tsx
│   │   ├── status-bar.tsx
│   │   └── section-header.tsx
│   ├── home/                       /  composition
│   ├── run/                        SSE feed + sidebar
│   └── report/                     Summary view
└── lib/
    ├── api.ts                      fetch wrappers (typed via Zod)
    ├── schemas.ts                  Zod mirrors of Pydantic models
    ├── use-analyze-stream.ts       EventSource hook
    ├── format.ts                   elapsed / tokens / cost helpers
    └── cn.ts                       clsx + tailwind-merge
```

## Wiring the SSE stream

`useAnalyzeStream(target, sessionId)` opens an `EventSource` against
`GET /analyze/stream?target_description=…&session_id=…` and aggregates the
backend events into a single `StreamState` reducer:

- `started` → status becomes `streaming`, clock starts.
- `node_completed` → pull `plan_count`, `findings_count`,
  `threat_surfaces_count`, `iteration_count`, `critic_score`, `report_id`
  from `payload` (the backend only sends counters — never full objects).
- `error` → terminal, surfaced inline.
- `completed` → status flips, the `LiveFeed` auto-routes to
  `/reports/[reportId]` after 1.2 s.

The `agent` field selects the visual color (`text-agent-{planner,…,writer}`),
keeping the design system's "one hue per agent" rule.

## Known limitations / future backend work

- `GET /reports` (list) does not exist yet — the history page is a styled
  empty-state. One small async function on `EpisodicMemory` and a route in
  `src/nexus/api/main.py` will unblock it.
- The persisted summary intentionally omits per-surface evidence and
  mitigations (see CLAUDE.md: episodic stores `ThreatReportSummary`, not the
  full report). The "Top attack vectors" section therefore renders flat
  rows; if a `GET /reports/{id}/full` endpoint is added later, swap
  `SurfaceList` for a richer renderer over `ThreatSurface[]`.
- Auth: none yet. The current backend has no auth either; both will need
  to land together when we move past local dev.
