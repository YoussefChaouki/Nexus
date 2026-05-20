"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { Button } from "@/components/ui/button";
import { PromptTextarea } from "@/components/ui/prompt-textarea";
import { ExampleChips } from "./example-chips";
import { AGENT_NAMES } from "@/lib/schemas";

const MIN_LEN = 20;
const MAX_LEN = 2000;

export function Launcher() {
  const [value, setValue] = useState("");
  const [pending, startTransition] = useTransition();
  const router = useRouter();

  const tooShort = value.trim().length < MIN_LEN;
  const tooLong = value.length > MAX_LEN;
  const disabled = pending || tooShort || tooLong;

  function execute() {
    if (disabled) return;
    const sessionId = (typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : Date.now().toString(36)) as string;
    const qs = new URLSearchParams({ target: value.trim() });
    startTransition(() => {
      router.push(`/runs/${sessionId}?${qs.toString()}`);
    });
  }

  return (
    <div className="mt-ds-7">
      <PromptTextarea
        value={value}
        onChange={setValue}
        footRight={
          <span className="inline-flex items-center gap-ds-4">
            {AGENT_NAMES.map((a) => (
              <span
                key={a}
                className="text-fg-faint text-[10.5px] uppercase tracking-[0.08em] before:content-['○'] before:mr-[6px]"
              >
                {a}
              </span>
            ))}
          </span>
        }
      />

      <ExampleChips onPick={(t) => setValue(t)} />

      <div className="mt-ds-5 flex gap-ds-3 items-center flex-wrap">
        <Button
          variant="primary"
          size="lg"
          disabled={disabled}
          onClick={execute}
          className="flex-1 min-w-[200px] justify-center"
        >
          ▶ Execute analysis
        </Button>
        {tooShort && value.length > 0 && (
          <span className="text-[10.5px] text-sev-high uppercase tracking-[0.1em]">
            {MIN_LEN - value.trim().length} more chars required
          </span>
        )}
        {tooLong && (
          <span className="text-[10.5px] text-sev-critical uppercase tracking-[0.1em]">
            description exceeds {MAX_LEN} chars
          </span>
        )}
      </div>
    </div>
  );
}
