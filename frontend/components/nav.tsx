"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/cn";

const TABS = [
  { href: "/", label: "01 / Input" },
  { href: "/history", label: "02 / History" },
] as const;

export function Nav() {
  const pathname = usePathname();

  return (
    <nav
      className={cn(
        "sticky top-0 z-50",
        "bg-bg/85 backdrop-blur-md",
        "border-b border-border",
      )}
    >
      <div className="max-w-[1320px] mx-auto px-ds-6 py-ds-3 flex items-center gap-ds-5 flex-wrap">
        <Link href="/" className="text-[12px] uppercase tracking-[0.1em] font-semibold">
          <span className="text-accent">nexus</span>
          <span className="text-fg-faint ml-ds-2 font-normal">
            {"// threat surface analyzer · v0.7.1"}
          </span>
        </Link>
        <div className="flex gap-ds-1 ml-auto flex-wrap">
          {TABS.map((tab) => {
            const isActive =
              tab.href === "/"
                ? pathname === "/" || pathname.startsWith("/runs") || pathname.startsWith("/reports")
                : pathname.startsWith(tab.href);
            return (
              <Link
                key={tab.href}
                href={tab.href}
                className={cn(
                  "px-[10px] py-[5px] border border-border",
                  "text-[10.5px] uppercase tracking-[0.08em]",
                  "transition-colors duration-100",
                  isActive
                    ? "bg-accent border-accent text-bg font-semibold"
                    : "text-fg-muted hover:text-fg hover:border-border-emph hover:bg-bg-elev",
                )}
              >
                {tab.label}
              </Link>
            );
          })}
        </div>
      </div>
    </nav>
  );
}
