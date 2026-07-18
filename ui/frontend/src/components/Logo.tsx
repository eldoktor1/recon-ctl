// recon-ui brand mark — a targeting scope with a radar sweep. Reads as "recon":
// reticle ring + crosshair ticks + a rotating sweep wedge + center lock dot.
let _uid = 0;

export function Logo({ size = 28, spin = false, glow = true }:
  { size?: number; spin?: boolean; glow?: boolean }) {
  const id = `lg${++_uid}`;
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none"
      style={glow ? { filter: "drop-shadow(0 0 5px rgba(77,216,192,0.45))" } : undefined}>
      <defs>
        <linearGradient id={`${id}s`} x1="16" y1="16" x2="28" y2="4" gradientUnits="userSpaceOnUse">
          <stop stopColor="var(--color-accent)" stopOpacity="0.55" />
          <stop offset="1" stopColor="var(--color-accent)" stopOpacity="0" />
        </linearGradient>
        <radialGradient id={`${id}r`} cx="0.5" cy="0.5" r="0.5">
          <stop stopColor="var(--color-accent)" stopOpacity="0.18" />
          <stop offset="1" stopColor="var(--color-accent)" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* faint field */}
      <circle cx="16" cy="16" r="13" fill={`url(#${id}r)`} />

      {/* rotating group: sweep only */}
      <g style={spin ? { transformOrigin: "16px 16px", animation: "logospin 3.2s linear infinite" } : undefined}>
        <path d="M16 16 L16 4 A12 12 0 0 1 28 16 Z" fill={`url(#${id}s)`} />
        <line x1="16" y1="16" x2="16" y2="4" stroke="var(--color-accent)" strokeWidth="1" strokeOpacity="0.7" />
      </g>

      {/* reticle ring */}
      <circle cx="16" cy="16" r="12" stroke="var(--color-accent)" strokeWidth="1.6" strokeOpacity="0.85" />
      <circle cx="16" cy="16" r="7" stroke="var(--color-accent)" strokeWidth="1" strokeOpacity="0.35" />

      {/* crosshair ticks */}
      <g stroke="var(--color-accent)" strokeWidth="1.6" strokeLinecap="round">
        <line x1="16" y1="1.5" x2="16" y2="6" />
        <line x1="16" y1="26" x2="16" y2="30.5" />
        <line x1="1.5" y1="16" x2="6" y2="16" />
        <line x1="26" y1="16" x2="30.5" y2="16" />
      </g>

      {/* center lock */}
      <circle cx="16" cy="16" r="2" fill="var(--color-accent)" />
    </svg>
  );
}
