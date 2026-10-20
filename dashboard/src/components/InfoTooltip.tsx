import { useRef, useState, useLayoutEffect, useId } from 'react';
import { Info } from 'lucide-react';
import type { ReactNode } from 'react';

interface Props {
  /** Tooltip body. Plain text or rich nodes. */
  children: ReactNode;
  /** Optional heading shown above the body. */
  title?: string;
  /** Icon size in px. */
  size?: number;
  /** Which edge of the trigger the bubble aligns to (default: left edge). */
  align?: 'left' | 'right';
}

const WIDTH = 262;

/**
 * A small "(i)" affordance that reveals an explanation on hover or keyboard
 * focus, used to show how a displayed number was calculated.
 *
 * The bubble is positioned `fixed` against the viewport rather than absolutely
 * inside the trigger: the panels it lives in (`.stat-card`, `.path-item`) clip
 * their overflow, which would otherwise hide most of the bubble. Fixed
 * positioning escapes that, and the coordinates are measured from the trigger
 * each time it opens. Hover is tracked on the whole wrapper so moving the
 * pointer from the icon into the bubble does not dismiss it.
 */
export default function InfoTooltip({ children, title, size = 13, align = 'right' }: Props) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const id = useId();

  useLayoutEffect(() => {
    if (!open || !triggerRef.current) { setPos(null); return; }
    const r = triggerRef.current.getBoundingClientRect();
    const top = r.bottom + 8;
    // align 'left'  → bubble's right edge tracks the trigger (opens leftward)
    // align 'right' → bubble's left edge tracks the trigger (opens rightward)
    let left = align === 'left' ? r.right - WIDTH : r.left;
    left = Math.max(8, Math.min(left, window.innerWidth - WIDTH - 8));
    setPos({ top, left });
  }, [open, align]);

  // A fixed bubble would detach from its trigger on scroll/resize; close it.
  useLayoutEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    return () => {
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
    };
  }, [open]);

  return (
    <span
      className="info-tip"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        ref={triggerRef}
        type="button"
        className="info-tip-trigger"
        aria-label={title ? `Explain: ${title}` : 'More information'}
        aria-expanded={open}
        aria-describedby={open ? id : undefined}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen(o => !o); }}
      >
        <Info size={size} />
      </button>
      {open && pos && (
        <span
          id={id}
          role="tooltip"
          className="info-tip-bubble"
          style={{ position: 'fixed', top: pos.top, left: pos.left, width: WIDTH }}
          onClick={(e) => e.stopPropagation()}
        >
          {title && <span className="info-tip-title">{title}</span>}
          <span className="info-tip-body">{children}</span>
        </span>
      )}
    </span>
  );
}
