interface ConfidenceMarkProps {
  confidence: number;
}

/** Confidence shown with weight and a small monochrome/accent indicator —
 * deliberately not a rainbow of status colors. */
export function ConfidenceMark({ confidence }: ConfidenceMarkProps) {
  const isHigh = confidence >= 0.8;
  return (
    <span className={`confidence ${isHigh ? "confidence--high" : ""}`}>
      <span className="confidence__dot" aria-hidden="true" />
      <span className="confidence__value">{Math.round(confidence * 100)}%</span>
    </span>
  );
}
