// @vitest-environment happy-dom
import { afterEach, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { call } from '../api';
import type { LocalResourceSample } from '../types';
import LocalResourceSummary from './LocalResourceSummary.vue';

vi.mock('../api', () => ({ call: vi.fn() }));
const measure = vi.mocked(call);
const first: LocalResourceSample = {
  cpuPercent: 12.5, memoryBytes: 104857600, rxBytes: 5120, txBytes: 0, durationMs: 5000,
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  measure.mockReset();
});

it('shows unavailable values and distinguishes measured zero from missing network data', async () => {
  measure.mockResolvedValueOnce(first).mockResolvedValueOnce({ ...first, rxBytes: null, txBytes: null });
  vi.useFakeTimers();
  const w = mount(LocalResourceSummary);
  const readings = () => w.findAll('dd').map(dd => dd.text());
  expect(readings()).toEqual(['—', '—', '—', '—']);
  await flushPromises();
  expect(readings()).toEqual(['12.5%', '100 MB', '1 KB/s', '0 B/s']);
  expect(w.get('.totals').text()).toContain('↓ 5 KB');
  await vi.advanceTimersByTimeAsync(5000);
  expect(readings()).toEqual(['12.5%', '100 MB', '—', '—']);
  expect(w.get('.totals').text()).toContain('↑ 0 B');
  w.unmount();
});

it('waits for an outstanding sample and preserves totals across hide and resume', async () => {
  vi.useFakeTimers();
  let hidden = false;
  vi.spyOn(document, 'hidden', 'get').mockImplementation(() => hidden);
  let finish!: (value: LocalResourceSample) => void;
  measure.mockResolvedValueOnce(first)
    .mockReturnValueOnce(new Promise(resolve => { finish = resolve; }))
    .mockResolvedValue({ ...first, rxBytes: 10240, txBytes: 5120 });
  const w = mount(LocalResourceSummary);
  await flushPromises();
  await vi.advanceTimersByTimeAsync(15000);
  expect(measure).toHaveBeenCalledTimes(2);
  hidden = true;
  document.dispatchEvent(new Event('visibilitychange'));
  finish(first);
  await vi.advanceTimersByTimeAsync(15000);
  expect(measure).toHaveBeenCalledTimes(2);
  expect(w.get('.totals').text()).toContain('↓ 5 KB');
  hidden = false;
  document.dispatchEvent(new Event('visibilitychange'));
  await flushPromises();
  expect(measure).toHaveBeenCalledTimes(3);
  expect(w.get('.totals').text()).toContain('↓ 15 KB');
  expect(w.get('.totals').text()).toContain('↑ 5 KB');
  w.unmount();
  await vi.advanceTimersByTimeAsync(15000);
  expect(measure).toHaveBeenCalledTimes(3);
  const reopened = mount(LocalResourceSummary);
  await flushPromises();
  expect(reopened.get('.totals').text()).toContain('↓ 10 KB');
  reopened.unmount();
});
