import { useEffect, useState } from 'react';

/** Ease displayed value toward target for smooth metric updates. */
export function useSmoothNumber(target: number, durationMs = 600) {
  const [display, setDisplay] = useState(target);

  useEffect(() => {
    const start = display;
    const diff = target - start;
    if (Math.abs(diff) < 0.0001) {
      setDisplay(target);
      return;
    }
    const t0 = performance.now();
    let frame: number;

    const tick = (now: number) => {
      const t = Math.min(1, (now - t0) / durationMs);
      const eased = 1 - (1 - t) ** 3;
      setDisplay(start + diff * eased);
      if (t < 1) frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- animate from last display
  }, [target, durationMs]);

  return display;
}
