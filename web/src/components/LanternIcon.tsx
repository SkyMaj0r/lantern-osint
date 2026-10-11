interface LanternIconProps {
  size?: number;
}

/** The wordmark glyph — same silhouette as the favicon, but outline-only
 * so it rides on var(--color-accent) and follows light/dark mode instead
 * of carrying its own fixed background. */
export function LanternIcon({ size = 20 }: LanternIconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <circle cx="16" cy="17" r="5" fill="var(--color-accent)" opacity="0.9" />
      <rect x="9" y="8.5" width="14" height="17" rx="3" stroke="var(--color-accent)" strokeWidth="2" />
      <line x1="9" y1="13.5" x2="23" y2="13.5" stroke="var(--color-accent)" strokeWidth="1.4" />
      <line x1="9" y1="20.5" x2="23" y2="20.5" stroke="var(--color-accent)" strokeWidth="1.4" />
      <path d="M16 8.5V4.5" stroke="var(--color-accent)" strokeWidth="2" strokeLinecap="round" />
      <circle cx="16" cy="3.4" r="1.7" fill="var(--color-accent)" />
      <path d="M12 25.5h8" stroke="var(--color-accent)" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}
