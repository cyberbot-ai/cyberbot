import { describe, expect, it } from 'vitest';
import { exactMetric, formatMetric } from './metrics';
describe('bounded metric labels', () => {
  it.each([
    [1.4, '1.4'], [0, '0.0'], [999.9, '999.9'], [999.99, '1k'],
    [1000, '1k'], [999999, '1M'], [12884901888.5, '12.9B'],
    [-12884901888.5, '-12.9B'], [1e18, '1E'], [1e100, '1.0e100'],
  ])('formats %s without an unbounded decimal expansion', (value, expected) => {
    expect(formatMetric(value)).toBe(expected);
    expect(exactMetric(value)).toBe(String(value));
  });
  it('preserves units, precision, zero and missing data', () => {
    expect(formatMetric(15,0,'%')).toBe('15%');
    expect(formatMetric(12884901888.5,1,' rps')).toBe('12.9B rps');
    expect(formatMetric(4,2,'','—',true)).toBe('4');
    expect(exactMetric(12884901888.5,' rps')).toBe('12884901888.5 rps');
    for(const value of [null,undefined,NaN,Infinity,-Infinity]) expect(formatMetric(value)).toBe('—');
  });
  it('keeps every finite exponent bounded, including negative and maximum numbers', () => {
    for(let exponent=-308;exponent<=308;exponent++) {
      for(const sign of [-1,1]) expect(formatMetric(sign*10**exponent).length).toBeLessThanOrEqual(10);
    }
    expect(formatMetric(Number.MAX_VALUE)).toBe('1.8e308');
  });
});
