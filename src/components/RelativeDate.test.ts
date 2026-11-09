// @vitest-environment happy-dom
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { h } from 'vue';
import RelativeDate from './RelativeDate.vue';
import DatedSelect from './DatedSelect.vue';
import { exactDate } from '../dateTime';

const now = Date.parse('2026-11-05T12:00:00.123Z');
let wrappers: VueWrapper[] = [];
function render(props: Record<string,unknown> = {}, target: HTMLElement = document.body) {
  const w = mount(RelativeDate, { props: { at: (now - 60000) / 1000, ...props }, attachTo: target });
  wrappers.push(w); return w;
}
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(now); });
afterEach(() => { wrappers.forEach(w => w.unmount()); wrappers = []; document.body.innerHTML = ''; vi.useRealTimers(); vi.restoreAllMocks(); });
describe('date popovers', () => {
  it('does not show a fresh event as future-dated between shared clock ticks', async () => {
    const w = render();
    await vi.advanceTimersByTimeAsync(9000);
    await w.setProps({at:Date.now()/1000});
    expect(w.text()).toBe('just now');
    await vi.advanceTimersByTimeAsync(66000);
    expect(w.text()).toBe('1 minute ago');
  });
  it('shows relative time, opens on hover, preserves milliseconds and allows entering the popover', async () => {
    const w = render({ at:now - 60000, unit:'milliseconds' });
    await w.vm.$nextTick();
    expect(w.text()).toBe('1 minute ago');
    expect(w.get('time').attributes('datetime')).toBe('2026-11-05T11:59:00.123Z');
    await w.get('.relative-date').trigger('mouseenter'); await flushPromises();
    const popup = document.querySelector('[role=tooltip]')!;
    expect(popup.textContent).toBe(exactDate(now - 60000, true));
    expect(w.get('.relative-date').attributes('aria-describedby')).toBe(popup.id);
    await w.get('.relative-date').trigger('mouseleave');
    popup.dispatchEvent(new Event('mouseenter'));
    await vi.advanceTimersByTimeAsync(150);
    expect(document.querySelector('[role=tooltip]')).not.toBeNull();
    popup.dispatchEvent(new Event('mouseleave'));
    await vi.advanceTimersByTimeAsync(150);
    expect(document.querySelector('[role=tooltip]')).toBeNull();
  });
  it('supports focus and Escape without closing a parent dialog', async () => {
    const modal = document.createElement('dialog'); modal.setAttribute('open',''); document.body.append(modal);
    const escaped = vi.fn(); modal.addEventListener('keydown', escaped);
    const w = render({}, modal);
    await w.get('.relative-date').trigger('focusin'); await flushPromises();
    expect(modal.querySelector('[role=tooltip]')).not.toBeNull();
    const escape = new KeyboardEvent('keydown', { key:'Escape', bubbles:true, cancelable:true });
    w.get('.relative-date').element.dispatchEvent(escape);
    await flushPromises();
    expect(escaped).not.toHaveBeenCalled(); expect(document.querySelector('[role=tooltip]')).toBeNull();
    expect(escape.defaultPrevented).toBe(true);
  });
  it('inherits the app theme, escapes scroll containers, clamps to the viewport and closes on scrolling', async () => {
    const app = document.createElement('div'); app.className = 'app';
    const scroll = document.createElement('div'); app.append(scroll); document.body.append(app);
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function(this:HTMLElement) {
      return this.classList.contains('date-popover')
        ? {width:210,height:36,left:0,top:0,right:210,bottom:36,x:0,y:0,toJSON(){}}
        : {width:80,height:20,left:0,top:window.innerHeight-21,right:80,bottom:window.innerHeight-1,x:0,y:0,toJSON(){}};
    });
    const w = render({}, scroll);
    await w.get('.relative-date').trigger('mouseenter'); await flushPromises();
    const popup = app.querySelector<HTMLElement>('[role=tooltip]')!;
    expect(popup.parentElement).toBe(app); expect(popup.style.left).toBe('8px');
    expect(Number.parseFloat(popup.style.top)).toBeLessThan(window.innerHeight-36);
    scroll.dispatchEvent(new Event('scroll')); await flushPromises();
    expect(app.querySelector('[role=tooltip]')).toBeNull();
  });
  it('never opens a tooltip for missing/invalid data and forwards layout attributes', async () => {
    const w = render({at:null});
    expect(w.text()).toBe('—'); expect(w.get('span').attributes('tabindex')).toBeUndefined();
    await w.get('span').trigger('mouseenter'); expect(document.querySelector('[role=tooltip]')).toBeNull();
    await w.setProps({at:NaN}); expect(w.get('time').attributes('datetime')).toBeUndefined();
    const decorated = mount(RelativeDate, { props:{at:now/1000}, attrs:{class:'freshness','data-test':'when'} });
    wrappers.push(decorated); expect(decorated.get('.freshness').attributes('data-test')).toBe('when');
  });
  it('opens by touch/click without activating the surrounding row and dismisses the previous date', async () => {
    const click = vi.fn();
    const w = mount({render:()=>h('button',{onClick:click},h(RelativeDate,{at:now/1000}))},{attachTo:document.body}); wrappers.push(w);
    await w.get('.relative-date').trigger('click'); await flushPromises(); expect(click).not.toHaveBeenCalled();
    const other = render({at:(now-120000)/1000});
    await other.get('.relative-date').trigger('mouseenter'); await flushPromises();
    expect(document.querySelectorAll('[role=tooltip]')).toHaveLength(1);
    document.body.dispatchEvent(new Event('pointerdown',{bubbles:true})); await flushPromises();
    expect(document.querySelector('[role=tooltip]')).toBeNull();
  });
  it('uses relative labels in native date menus and reveals the selected exact date on focus', async () => {
    const w = mount(DatedSelect, {props:{modelValue:'a', label:'History',options:[{value:'a',label:'Codex',at:(now-60000)/1000},{value:'b',label:'Claude',at:(now-120000)/1000}]},attachTo:document.body}); wrappers.push(w);
    expect(w.get('option').text()).toBe('Codex · 1 minute ago');
    await w.get('select').trigger('focusin'); await flushPromises();
    expect(document.querySelector('[role=tooltip]')?.textContent).toBe(exactDate(now-60000));
    expect(w.get('select').attributes('aria-describedby')).toBe(document.querySelector('[role=tooltip]')?.id);
    await w.get('select').setValue('b');
    expect(w.emitted('update:modelValue')?.[0]).toEqual(['b']); expect(w.emitted('change')).toHaveLength(1);
    await w.setProps({modelValue:'b'}); await flushPromises();
    expect(document.querySelector('[role=tooltip]')).toBeNull();
  });
});
