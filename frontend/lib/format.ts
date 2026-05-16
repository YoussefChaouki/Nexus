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
