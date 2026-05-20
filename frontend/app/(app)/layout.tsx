import { Nav } from "@/components/nav";

export default function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <Nav />
      <main className="max-w-[1320px] mx-auto px-ds-6 py-ds-6 pb-ds-9">
        {children}
      </main>
      <footer className="max-w-[1320px] mx-auto px-ds-6 py-ds-5 mt-ds-9 border-t border-border flex items-center justify-between text-[10.5px] uppercase tracking-[0.1em] text-fg-faint flex-wrap gap-ds-3">
        <span>{"nexus // threat surface analyzer v0.7.1"}</span>
        <span>
          © {new Date().getFullYear()} youssef chaouki
          <span className="text-fg-faint/60 mx-ds-2" aria-hidden>·</span>
          <a
            href="https://github.com/YoussefChaouki/Nexus"
            target="_blank"
            rel="noreferrer noopener"
            className="text-fg-faint hover:text-accent border-b border-dotted border-current transition-colors"
          >
            source
          </a>
        </span>
      </footer>
    </>
  );
}
