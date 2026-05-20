import { cn } from "@/lib/cn";

export function Section({
  id,
  num,
  title,
  meta,
  children,
  className,
}: {
  id?: string;
  num: string;
  title: React.ReactNode;
  meta?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      id={id}
      className={cn("relative px-ds-6 py-ds-9 border-b border-border", className)}
    >
      <div className="flex items-baseline gap-ds-4 mb-ds-7 flex-wrap">
        <span className="text-[11px] tracking-[0.16em] text-fg-faint font-medium">
          {num} {"//"}
        </span>
        <h2 className="text-[28px] font-medium text-fg m-0 tracking-[-0.01em]">{title}</h2>
        {meta && (
          <span className="ml-auto text-[10.5px] uppercase tracking-[0.14em] text-fg-faint">
            {meta}
          </span>
        )}
      </div>
      {children}
    </section>
  );
}
