import { describe, expect, it } from 'vitest';
import { dateMillis, exactDate, relativeDate } from './dateTime';

const now = Date.parse('2026-11-05T12:00:00Z');
describe('relative English dates', () => {
  it.each([
    [2, 'just now'], [30, '30 seconds ago'], [60, '1 minute ago'],
    [120, '2 minutes ago'], [300, '5 minutes ago'], [3600, '1 hour ago'],
    [7200, '2 hours ago'], [86400, '1 day ago'], [2592000, '1 month ago'],
    [31536000, '1 year ago'], [-120, 'in 2 minutes'],
  ])('formats an offset of %s seconds', (seconds, label) => {
    expect(relativeDate(now - seconds * 1000, now)).toBe(label);
  });
  it('distinguishes seconds, milliseconds, missing values and the Unix epoch', () => {
    expect(dateMillis(now / 1000)).toBe(now);
    expect(dateMillis(now, 'milliseconds')).toBe(now);
    expect(dateMillis(0)).toBe(0);
    for (const value of [null, undefined, NaN, Infinity, 9e15]) expect(dateMillis(value)).toBeNull();
  });
  it('shows exact local seconds, timezone and optional audit milliseconds', () => {
    const ms = now + 123;
    const expected = new Intl.DateTimeFormat('en-US', {
      day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false, timeZoneName:'short',
    }).format(ms);
    expect(exactDate(ms)).toBe(expected);
    expect(exactDate(ms, true)).toContain('.123');
    expect(exactDate(ms, true)).toMatch(/GMT|UTC|MSK/);
  });
  it('keeps a UTC accounting day a calendar day rather than elapsed hours', () => {
    const today = Date.parse('2026-11-05T00:00:00Z');
    expect(relativeDate(today, now, true)).toBe('today');
    expect(relativeDate(today - 86400000, now, true)).toBe('yesterday');
    expect(exactDate(today, false, true)).toBe('November 5, 2026 (UTC)');
  });
});
