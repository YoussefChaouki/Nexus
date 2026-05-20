// Build a Langfuse traces deep-link for a given session, or null when
// Langfuse isn't configured. We don't fabricate URLs that point to 404s.
//
// Project-scoped URL is preferred when NEXT_PUBLIC_LANGFUSE_PROJECT_ID is
// set; otherwise we fall back to the host root which lets the user
// navigate manually.

const HOST = process.env.NEXT_PUBLIC_LANGFUSE_HOST?.replace(/\/$/, "") ?? "";
const PROJECT_ID = process.env.NEXT_PUBLIC_LANGFUSE_PROJECT_ID ?? "";

export function langfuseTraceUrl(sessionId: string): string | null {
  if (!HOST) return null;
  if (PROJECT_ID) {
    const filter = encodeURIComponent(
      JSON.stringify([
        { column: "sessionId", operator: "=", value: sessionId, type: "string" },
      ]),
    );
    return `${HOST}/project/${PROJECT_ID}/traces?filter=${filter}`;
  }
  return `${HOST}/traces`;
}

export const langfuseEnabled = HOST !== "";
