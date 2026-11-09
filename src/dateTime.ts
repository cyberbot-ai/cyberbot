export type DateUnit = 'seconds' | 'milliseconds';

const relative = new Intl.RelativeTimeFormat('en-US', { numeric: 'always' });
const days = new Intl.RelativeTimeFormat('en-US', { numeric: 'auto' });
const exact = new Intl.DateTimeFormat('en-US', {
  day: '2-digit', month: '2-digit', year: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  timeZoneName: 'short',
});
const utcDay = new Intl.DateTimeFormat('en-US', {
  day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC',
});
const localDay = new Intl.DateTimeFormat('en-US', { day: '2-digit', month: '2-digit', year: 'numeric' });
const localTime = new Intl.DateTimeFormat('en-US', {
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
});

export function dateMillis(at: number | null | undefined, unit: DateUnit = 'seconds'): number | null {
  if (at == null || !Number.isFinite(at)) return null;
  const ms = at * (unit === 'seconds' ? 1000 : 1);
  return Number.isFinite(new Date(ms).getTime()) ? ms : null;
}

export function relativeDate(ms: number, now: number, calendarDay = false): string {
  if (calendarDay) return days.format(Math.floor(ms / 86400000) - Math.floor(now / 86400000), 'day');
  const seconds = (ms - now) / 1000;
  const distance = Math.abs(seconds);
  if (distance < 5) return 'just now';
  const [size, unit]: [number, Intl.RelativeTimeFormatUnit] = distance < 60 ? [1, 'second']
    : distance < 3600 ? [60, 'minute'] : distance < 86400 ? [3600, 'hour']
    : distance < 2592000 ? [86400, 'day'] : distance < 31536000 ? [2592000, 'month']
    : [31536000, 'year'];
  return relative.format(Math.sign(seconds) * Math.floor(distance / size), unit);
}

export function exactDate(ms: number, milliseconds = false, calendarDay = false): string {
  if (calendarDay) return `${utcDay.format(ms)} (UTC)`;
  return exact.formatToParts(ms).map(part => part.type === 'second' && milliseconds
    ? `${part.value}.${String(new Date(ms).getUTCMilliseconds()).padStart(3, '0')}`
    : part.value).join('');
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return remaining ? `${minutes} min ${remaining} s` : `${minutes} min`;
}

export function formatTimeRange(from: number, to: number): string {
  const start = dateMillis(from), end = dateMillis(to);
  if (start == null || end == null) return 'Time unavailable';
  const firstDay = localDay.format(start), lastDay = localDay.format(end);
  const firstTime = localTime.format(start), lastTime = localTime.format(end);
  if (start === end) return `${firstDay}, ${firstTime}`;
  return firstDay === lastDay
    ? `${firstDay}, ${firstTime}–${lastTime}`
    : `${firstDay}, ${firstTime} — ${lastDay}, ${lastTime}`;
}
