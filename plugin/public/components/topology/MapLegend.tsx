// The map's line legend; each sample is drawn with the map's own edgeStyle.
import React from 'react';
import { themeVars } from '../../lib/theme';
import { edgeStyle, WifiGlyph } from './TopologyView';

const ENTRIES: Array<[string, Parameters<typeof edgeStyle>[0], boolean]> = [
  ['Device link', { type: 'lldp', inferred: false }, false],
  ['Host link', { type: 'endpoint_link', confidence: 'lldp', inferred: false }, false],
  ['Wireless link', { type: 'endpoint_link', confidence: 'wifi', inferred: false }, true],
  ['Inferred', { type: 'inferred', inferred: true }, false],
];

export function MapLegend() {
  return (
    <div className="vmMapLegend" data-test-subj="vmMapLegend">
      {ENTRIES.map(([text, edge, wifi]) => {
        const { stroke, strokeWidth, strokeDasharray, opacity } = edgeStyle(edge);
        return (
          <span key={text}>
            <svg width={44} height={20} aria-hidden="true">
              <line x1={2} y1={10} x2={42} y2={10} stroke={stroke} strokeWidth={strokeWidth} strokeDasharray={strokeDasharray} opacity={opacity} />
              {wifi && <WifiGlyph x={22} y={10} color={stroke} background={themeVars.euiColorEmptyShade} />}
            </svg>
            {text}
          </span>
        );
      })}
    </div>
  );
}
