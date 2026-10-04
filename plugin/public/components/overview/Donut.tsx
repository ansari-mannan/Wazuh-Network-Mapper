import React from 'react';
import { Slice } from '../../lib/stats';

interface DonutProps {
  slices: Slice[];
  /** caption under the total in the middle */
  caption: string;
  size?: number;
  thickness?: number;
}

// A small dependency-free SVG donut. Each slice is a circle stroke whose dash
// length is its share of the circumference, rotated so slices run clockwise
// from 12 o'clock. Colours of the track and text come from overview.scss.
export function Donut({ slices, caption, size = 132, thickness = 16 }: DonutProps) {
  const total = slices.reduce((sum, s) => sum + s.value, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const gap = slices.filter((s) => s.value > 0).length > 1 ? 2 : 0;
  const centre = size / 2;
  let offset = 0;

  return (
    <svg
      className="vmDonut"
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      role="img"
      aria-label={`${total} ${caption}: ${slices.map((s) => `${s.label} ${s.value}`).join(', ')}`}
    >
      <circle
        className="vmDonut__track"
        cx={centre}
        cy={centre}
        r={r}
        fill="none"
        strokeWidth={thickness}
      />
      <g transform={`rotate(-90 ${centre} ${centre})`}>
        {total > 0 &&
          slices.map((s) => {
            const len = (s.value / total) * c;
            const dash = Math.max(len - gap, 0.5);
            const el = (
              <circle
                key={s.label}
                cx={centre}
                cy={centre}
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth={thickness}
                strokeDasharray={`${dash} ${c - dash}`}
                strokeDashoffset={-offset}
              >
                <title>{`${s.label}: ${s.value}`}</title>
              </circle>
            );
            offset += len;
            return el;
          })}
      </g>
      <text className="vmDonut__total" x={centre} y={centre} textAnchor="middle" dy="0.1em">
        {total}
      </text>
      <text className="vmDonut__caption" x={centre} y={centre} textAnchor="middle" dy="1.6em">
        {caption}
      </text>
    </svg>
  );
}
