// @vitest-environment happy-dom
import { mount, type VueWrapper } from '@vue/test-utils';
import { defineComponent, h } from 'vue';
import { afterEach, expect, it, vi } from 'vitest';
import { useClock } from './useClock';

const Consumer = defineComponent({ setup() { const now = useClock(); return () => h('span', now.value); } });
let wrappers: VueWrapper[] = [];
afterEach(() => { wrappers.forEach(w => w.unmount()); wrappers = []; vi.useRealTimers(); vi.restoreAllMocks(); });
it('shares one clock, pauses while hidden, catches up on wake and cleans up the last subscriber', async () => {
  vi.useFakeTimers(); vi.setSystemTime(100000);
  let hidden = false;
  vi.spyOn(document, 'hidden', 'get').mockImplementation(() => hidden);
  const intervals = vi.spyOn(globalThis, 'setInterval');
  const cleared = vi.spyOn(globalThis, 'clearInterval');
  const a = mount(Consumer), b = mount(Consumer);
  wrappers.push(a,b);
  expect(intervals).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(15000);
  expect(a.text()).toBe('115'); expect(b.text()).toBe('115');
  hidden = true; document.dispatchEvent(new Event('visibilitychange'));
  expect(cleared).toHaveBeenLastCalledWith(intervals.mock.results[0].value);
  await vi.advanceTimersByTimeAsync(600000);
  expect(a.text()).toBe('115');
  hidden = false; document.dispatchEvent(new Event('visibilitychange'));
  await a.vm.$nextTick();
  expect(a.text()).toBe('715'); expect(intervals).toHaveBeenCalledTimes(2);
  const before = cleared.mock.calls.length;
  a.unmount(); expect(cleared).toHaveBeenCalledTimes(before);
  b.unmount(); expect(cleared).toHaveBeenLastCalledWith(intervals.mock.results[1].value);
  wrappers = [];
});
