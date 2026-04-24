import React from 'react';
import {AbsoluteFill, useCurrentFrame} from 'remotion';

/* ─── Brand colours ────────────────────────── */
const GOLD = '#E8A020';
const G = '232,160,32'; // gold as rgb triple for rgba()
const DARK = '#030d1a';

/* ─── Canvas dimensions ────────────────────── */
const W = 900;
const H = 900;
const CX = W / 2;          // 450
const CY = H / 2 - 10;     // 440

/* ─── Insurance product labels ─────────────── */
const PRODUCTS = ['Motor', 'Health', 'Life', 'Business', 'Domestic', 'Pensions'];

/* ─── Deterministic particle field ─────────── */
// All speeds are chosen so every particle completes a whole number
// of orbits in 240 frames (8 s at 30 fps) → perfect seamless loop.
const PARTICLES = Array.from({length: 48}, (_, i) => ({
  startAngle: (i / 48) * 360,
  radius: 55 + ((i * 23 + 7) % 340),
  // speed in full-rotations-per-8s (integer → perfect loop)
  laps: 1 + (i % 4),
  size: 0.9 + (i % 3) * 0.7,
  isGold: i % 6 === 0,
  opacityPhase: (i * 0.41) % (Math.PI * 2),
}));

/* ─── Shield SVG paths (pre-computed) ──────── */
const SHIELD_OUTER = `M${CX} 295 L${CX + 116} 338 L${CX + 116} 455
  C${CX + 116} 528 ${CX} 585 ${CX} 585
  C${CX} 585 ${CX - 116} 528 ${CX - 116} 455
  L${CX - 116} 338 Z`;

const SHIELD_INNER = `M${CX} 312 L${CX + 98} 350 L${CX + 98} 453
  C${CX + 98} 516 ${CX} 568 ${CX} 568
  C${CX} 568 ${CX - 98} 516 ${CX - 98} 453
  L${CX - 98} 350 Z`;

export const DoveNestVision: React.FC = () => {
  const frame = useCurrentFrame();

  /* ── Normalised loop time (0→1 over 8 s) ── */
  const t = frame / 240;

  /* ── Derived animation values ── */
  // One full product orbit per loop (perfect)
  const orbitDeg = t * 360;

  // Shield breathes gently — 2 breath cycles per loop
  const breathe = 0.4 + 0.22 * Math.sin(t * Math.PI * 4);

  // Shield floats — 1 vertical cycle per loop
  const floatY = Math.sin(t * Math.PI * 2) * 11;

  // Dove wing — 3 flap cycles per loop (6 beats)
  const wingOpacity = 0.25 + 0.2 * Math.abs(Math.sin(t * Math.PI * 6));

  /* ── Pulse ring helper ── */
  // 3 rings, each cycling in 80 frames (2.67 s), staggered by 26.7 frames
  const pulseProps = (stagger: number) => {
    const p = ((frame + stagger * 80) % 80) / 80;
    return {r: 100 + p * 260, opacity: (1 - p) * 0.48};
  };

  return (
    <AbsoluteFill
      style={{
        background: `radial-gradient(ellipse 80% 70% at 50% 42%, #0d2545 0%, ${DARK} 72%)`,
      }}
    >
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`}>
        <defs>
          {/* Multi-layer glow for shield */}
          <filter id="shieldGlow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="12" result="b1" />
            <feGaussianBlur stdDeviation="4"  result="b2" in="SourceGraphic"/>
            <feMerge>
              <feMergeNode in="b1" />
              <feMergeNode in="b2" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Soft glow for orbit dots */}
          <filter id="dotGlow" x="-150%" y="-150%" width="400%" height="400%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Very soft wide glow for lines */}
          <filter id="lineGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2" />
          </filter>
        </defs>

        {/* ════ 1. PULSE RINGS ════ */}
        {[0, 0.333, 0.666].map((stagger, i) => {
          const {r, opacity} = pulseProps(stagger);
          return (
            <circle
              key={`pulse-${i}`}
              cx={CX} cy={CY} r={r}
              fill="none"
              stroke={GOLD}
              strokeWidth="1.2"
              opacity={opacity}
            />
          );
        })}

        {/* ════ 2. ROTATING DASHED ORBIT TRACKS ════ */}
        {/* Outer track — slow clockwise */}
        <circle
          cx={CX} cy={CY} r={270}
          fill="none"
          stroke={`rgba(${G},0.14)`}
          strokeWidth="0.8"
          strokeDasharray="7 18"
          transform={`rotate(${orbitDeg * 0.25} ${CX} ${CY})`}
        />
        {/* Inner track — slightly faster counter-clockwise */}
        <circle
          cx={CX} cy={CY} r={188}
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth="0.7"
          strokeDasharray="4 12"
          transform={`rotate(${-orbitDeg * 0.4} ${CX} ${CY})`}
        />

        {/* ════ 3. PARTICLE FIELD ════ */}
        {PARTICLES.map((p, i) => {
          const angle = (p.startAngle + t * 360 * p.laps) % 360;
          const rad = (angle - 90) * (Math.PI / 180);
          const x = CX + Math.cos(rad) * p.radius;
          const y = CY + Math.sin(rad) * p.radius;
          const op = 0.08 + 0.18 * Math.abs(Math.sin(t * Math.PI * 2 * p.laps + p.opacityPhase));
          return (
            <circle
              key={`pt-${i}`}
              cx={x} cy={y} r={p.size}
              fill={p.isGold ? GOLD : '#fff'}
              opacity={op}
            />
          );
        })}

        {/* ════ 4. RADIAL CONNECTION LINES (every 4th particle) ════ */}
        {PARTICLES.filter((_, i) => i % 4 === 0).map((p, i) => {
          const angle = (p.startAngle + t * 360 * p.laps) % 360;
          const rad = (angle - 90) * (Math.PI / 180);
          const x = CX + Math.cos(rad) * p.radius;
          const y = CY + Math.sin(rad) * p.radius;
          const op = 0.035 + 0.04 * Math.abs(Math.sin(t * Math.PI * 2 + i));
          return (
            <line
              key={`cl-${i}`}
              x1={CX} y1={CY} x2={x} y2={y}
              stroke={GOLD}
              strokeWidth="0.4"
              opacity={op}
            />
          );
        })}

        {/* ════ 5. ORBIT-TO-CENTRE SPOKE LINES ════ */}
        {PRODUCTS.map((_, i) => {
          const angle = (i / PRODUCTS.length) * 360 + orbitDeg;
          const rad = (angle - 90) * (Math.PI / 180);
          const x = CX + Math.cos(rad) * 270;
          const y = CY + Math.sin(rad) * 270;
          return (
            <line
              key={`spoke-${i}`}
              x1={CX} y1={CY} x2={x} y2={y}
              stroke={GOLD}
              strokeWidth="0.6"
              strokeDasharray="3 10"
              opacity="0.1"
            />
          );
        })}

        {/* ════ 6. CENTRAL SHIELD + DOVE (floating) ════ */}
        <g transform={`translate(0, ${floatY.toFixed(2)})`} filter="url(#shieldGlow)">
          {/* Ambient glow pool behind shield */}
          <circle
            cx={CX} cy={CY} r={138}
            fill={`rgba(${G},${(breathe * 0.055).toFixed(3)})`}
          />

          {/* Shield outer */}
          <path
            d={SHIELD_OUTER}
            stroke={GOLD}
            strokeWidth="2.8"
            strokeLinejoin="round"
            fill={`rgba(${G},${(breathe * 0.062).toFixed(3)})`}
            opacity={(0.78 + 0.22 * breathe / 0.65).toFixed(3)}
          />
          {/* Shield inner bevel */}
          <path
            d={SHIELD_INNER}
            stroke={`rgba(${G},0.24)`}
            strokeWidth="1.1"
            fill="none"
          />

          {/* ── DOVE (centred ~450, 450) ── */}
          {/* Tail feathers */}
          <path
            d={`M406 466 C386 476 380 492 398 496 C413 499 422 480 417 462`}
            fill={`rgba(${G},0.28)`}
            stroke={GOLD}
            strokeWidth="1.8"
            strokeLinecap="round"
          />
          {/* Wing — opacity animates to simulate beat */}
          <path
            d={`M413 450 C392 422 386 396 411 388 C435 380 450 415 455 442`}
            fill={`rgba(${G},${wingOpacity.toFixed(3)})`}
            stroke={GOLD}
            strokeWidth="2.1"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {/* Body */}
          <ellipse
            cx={443} cy={456}
            rx={42} ry={23}
            transform={`rotate(-9 443 456)`}
            fill={`rgba(${G},0.48)`}
            stroke={GOLD}
            strokeWidth="2.2"
          />
          {/* Head */}
          <circle
            cx={480} cy={432}
            r={17}
            fill={`rgba(${G},0.52)`}
            stroke={GOLD}
            strokeWidth="2.2"
          />
          {/* Beak */}
          <path d="M497 430 L516 434 L497 438 Z" fill={GOLD} />
          {/* Eye */}
          <circle cx={484} cy={430} r={4.5} fill="#091e36" />
          <circle cx={482.5} cy={428.5} r={1.8} fill="rgba(255,255,255,0.78)" />
        </g>

        {/* ════ 7. ORBITING PRODUCT LABELS ════ */}
        {PRODUCTS.map((label, i) => {
          const angle = (i / PRODUCTS.length) * 360 + orbitDeg;
          const rad = (angle - 90) * (Math.PI / 180);
          const x = CX + Math.cos(rad) * 270;
          const y = CY + Math.sin(rad) * 270;
          const pillW = 82;
          const pillH = 26;
          return (
            <g key={label} filter="url(#dotGlow)">
              {/* Outer glow ring */}
              <circle cx={x} cy={y} r={15} fill={`rgba(${G},0.1)`} />
              {/* Core dot */}
              <circle cx={x} cy={y} r={6} fill={GOLD} opacity={0.95} />
              {/* Pill background */}
              <rect
                x={x - pillW / 2} y={y - pillH - 10}
                width={pillW} height={pillH}
                rx={13}
                fill="rgba(2,10,22,0.9)"
                stroke={`rgba(${G},0.45)`}
                strokeWidth="0.8"
              />
              {/* Label */}
              <text
                x={x}
                y={y - 10 - pillH / 2}
                textAnchor="middle"
                dominantBaseline="middle"
                fontFamily="Arial, Helvetica, sans-serif"
                fontSize="11"
                fontWeight="700"
                letterSpacing="2"
                fill="rgba(255,255,255,0.9)"
              >
                {label.toUpperCase()}
              </text>
            </g>
          );
        })}

        {/* ════ 8. SUBTLE BRAND MARK at bottom ════ */}
        <text
          x={CX} y={855}
          textAnchor="middle"
          fontFamily="Arial, Helvetica, sans-serif"
          fontSize="13"
          fontWeight="700"
          letterSpacing="7"
          fill={`rgba(${G},0.28)`}
        >
          DOVENEST INSURANCE
        </text>
      </svg>
    </AbsoluteFill>
  );
};
