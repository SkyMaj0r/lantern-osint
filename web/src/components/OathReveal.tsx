import { useEffect, useState } from "react";

interface OathRevealProps {
  lines: string[];
}

const CHAR_DELAY_MS = 35;
const LINE_PAUSE_MS = 450;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function OathReveal({ lines }: OathRevealProps) {
  const [revealedLines, setRevealedLines] = useState<string[]>([]);
  const [activeLineText, setActiveLineText] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => {
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let cancelled = false;

    setRevealedLines([]);
    setActiveLineText("");
    setDone(false);

    if (reducedMotion) {
      setRevealedLines(lines);
      setDone(true);
      return;
    }

    async function play() {
      for (const line of lines) {
        for (let i = 1; i <= line.length; i++) {
          if (cancelled) return;
          setActiveLineText(line.slice(0, i));
          await sleep(CHAR_DELAY_MS);
        }
        if (cancelled) return;
        setRevealedLines((prev) => [...prev, line]);
        setActiveLineText("");
        await sleep(LINE_PAUSE_MS);
      }
      if (!cancelled) setDone(true);
    }

    void play();

    return () => {
      cancelled = true;
    };
  }, [lines]);

  return (
    <div className="oath" aria-live="polite">
      {revealedLines.map((line, i) => (
        <p className="oath__line" key={i}>
          {line}
        </p>
      ))}
      {!done && (
        <p className="oath__line">
          {activeLineText}
          <span className="oath__cursor" aria-hidden="true" />
        </p>
      )}
    </div>
  );
}
