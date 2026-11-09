const suffixes = ['', 'k', 'M', 'B', 'T', 'P', 'E'];

export function exactMetric(value: number | null | undefined, unit = '', empty = '—'): string {
  return value == null || !Number.isFinite(value) ? empty : `${value}${unit}`;
}

// Compact magnitudes keep counters readable: M = million, B = billion. The tooltip retains the original value.
export function formatMetric(value: number | null | undefined, precision = 1, unit = '', empty = '—', trim = false): string {
  if (value == null || !Number.isFinite(value)) return empty;
  if (Math.abs(value) >= 1e21) return `${value.toExponential(1).replace('e+', 'e')}${unit}`;
  let scaled = value, index = 0;
  while (Math.abs(Number(scaled.toFixed(precision))) >= 1000 && index < suffixes.length - 1) {
    scaled /= 1000; index++;
  }
  return `${index || trim ? Number(scaled.toFixed(precision)) : scaled.toFixed(precision)}${suffixes[index]}${unit}`;
}
