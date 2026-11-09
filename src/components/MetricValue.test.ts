// @vitest-environment happy-dom
import { mount } from '@vue/test-utils';
import { expect,it } from 'vitest';
import MetricValue from './MetricValue.vue';
it('keeps the exact value and unit available when the display is abbreviated',()=>{
  const w=mount(MetricValue,{props:{value:12884901888.5,unit:' rps'}});
  expect(w.text()).toBe('12.9B rps');
  expect(w.attributes('title')).toBe('12884901888.5 rps');
  expect(w.attributes('aria-label')).toBe('12884901888.5 rps');w.unmount();
});
it('supports a converted display while retaining the original measurement',()=>{
  const w=mount(MetricValue,{props:{value:1,unit:' MiB',exact:'1048576 bytes',trim:true}});
  expect(w.text()).toBe('1 MiB');expect(w.attributes('title')).toBe('1048576 bytes');w.unmount();
});
