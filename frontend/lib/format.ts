export function formatElapsed(ms: number): string {
  const total = Math.max(0, ms);
  const m = Math.floor(total / 60000);
  const s = Math.floor((total % 60000) / 1000);
  const cs = Math.floor((total % 1000) / 10);
  return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}.${cs
    .toString()
    .padStart(2, "0")}`;
}

export function formatTokens(n: number): string {
  return n.toLocaleString("en-US");
}

export function formatCost(usd: number): string {
  return `$${usd.toFixed(3)}`;
}

export function shortId(id: string): string {
  return id.split("-").slice(0, 2).join("-");
}

export function estimateTokens(chars: number): number {
  return Math.ceil(chars / 4);
}

/** "3m ago" / "2h ago" / "5d ago" — falls back to the ISO date past 30 days. */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diff = Math.max(0, now - then);
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days <= 30) return `${days}d ago`;
  return iso.slice(0, 10);
}
