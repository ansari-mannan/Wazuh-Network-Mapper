// The dark tooltip box of the front panel and the map's Wi-Fi links: it follows
// the cursor, or sits by a focused element, always inside the viewport. It is
// visual only; each target keeps its own aria-label.
import React, { useLayoutEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom';
import { ROUTE_LINE, TipContent } from '../../lib/faceplate';

const OFFSET = 14;
const MARGIN = 8;

function HoverTip({ content, x, y }: { content: TipContent; x: number; y: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x + OFFSET, top: y + OFFSET });
  // below-right of the pointer; flipped or pushed back when that leaves the window
  useLayoutEffect(() => {
    const box = ref.current?.getBoundingClientRect();
    const w = box?.width ?? 0;
    const h = box?.height ?? 0;
    const left = Math.max(MARGIN, Math.min(x + OFFSET, window.innerWidth - w - MARGIN));
    const below = y + OFFSET;
    const top = below + h > window.innerHeight - MARGIN ? Math.max(MARGIN, y - h - OFFSET) : below;
    setPos({ left, top });
  }, [x, y, content]);
  return ReactDOM.createPortal(
    <div ref={ref} className="vmTip" role="tooltip" style={pos} data-test-subj="vmHoverTip">
      <b>{content.title}</b>
      {content.lines.map((line, i) => (
        <div key={i}>{line}</div>
      ))}
      {content.route && <div className="vmTip__route">{ROUTE_LINE}</div>}
    </div>,
    document.body
  );
}

/**
 * Tooltip state for one component: `bind(content)` gives a target's event
 * handlers (hover and keyboard focus show it; leave, blur and Escape hide
 * it), and `tip` is the box to render, or null.
 */
export function useHoverTip() {
  const [shown, setShown] = useState<{ content: TipContent; x: number; y: number } | null>(null);
  const hide = () => setShown(null);
  const bind = (content: TipContent) => ({
    onMouseMove: (e: React.MouseEvent) => setShown({ content, x: e.clientX, y: e.clientY }),
    onMouseLeave: hide,
    onFocus: (e: React.FocusEvent) => {
      const r = (e.currentTarget as Element).getBoundingClientRect();
      setShown({ content, x: r.right, y: r.bottom });
    },
    onBlur: hide,
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') hide();
    },
  });
  return { tip: shown && <HoverTip {...shown} />, bind };
}
