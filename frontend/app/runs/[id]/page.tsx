import { redirect } from "next/navigation";
import { LiveFeed } from "@/components/run/live-feed";

interface Props {
  params: { id: string };
  searchParams: { target?: string };
}

export default function RunPage({ params, searchParams }: Props) {
  const target = searchParams.target?.trim();
  if (!target || target.length < 20) {
    redirect("/");
  }
  return <LiveFeed sessionId={params.id} target={target!} />;
}
