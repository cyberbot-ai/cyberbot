// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import MonitoringSettings from './MonitoringSettings.vue';
import { onSettingsSaved } from '../settings';
import type { Settings } from '../types';
const mocks = vi.hoisted(() => ({ call: vi.fn() }));
vi.mock('../api', () => ({ call: mocks.call }));
const defaults: Settings = { mode:'auto', dailyRunLimit:4, dailyTokenLimit:200000, runTokenLimit:50000, autoAgent:'claude', pollSeconds:180, logPollSeconds:600, concurrency:4, paused:false, dockBadgeEnabled: true };
let stored: Settings;
beforeEach(() => {
  vi.useFakeTimers();vi.clearAllMocks();stored={...defaults};
  mocks.call.mockImplementation(async (_command,args)=>stored={...stored,...args.patch});
});
afterEach(()=>vi.useRealTimers());
const settle = async () => { await vi.advanceTimersByTimeAsync(250); await flushPromises(); };

describe('monitoring autosave',()=>{
  it('saves a custom connectivity host and clears the optional backup',async()=>{
    const w = mount(MonitoringSettings,{props:{settings:{...stored}}});
    const [primary, backup] = w.findAll('fieldset input');
    expect((primary.element as HTMLInputElement).value).toBe('cloudflare-dns.com');
    expect((backup.element as HTMLInputElement).value).toBe('www.microsoft.com');
    await primary.setValue(' 2001:db8::1 ');
    await backup.setValue('');
    await settle();
    expect(mocks.call).toHaveBeenCalledWith('update_settings', {
      patch: {connectivityProbe: {host:'2001:db8::1',backupHost:null}},
    });
    w.unmount();
  });
  it('coalesces input, uses a partial update and does not save on mount or prop refresh',async()=>{
    const w=mount(MonitoringSettings,{props:{settings:{...stored}}});
    expect(w.find('button').exists()).toBe(false);expect(mocks.call).not.toHaveBeenCalled();
    await w.findAll('input')[0].setValue('300');await w.findAll('input')[0].setValue('600');
    stored={...stored,paused:true,autoAgent:'codex'};await w.setProps({settings:{...stored}});
    expect((w.findAll('input')[0].element as HTMLInputElement).value).toBe('600');
    await settle();expect(mocks.call.mock.calls).toEqual([['update_settings',{patch:{pollSeconds:600}}]]);
    expect(stored.paused).toBe(true);expect(stored.autoAgent).toBe('codex');
    await w.setProps({settings:{...stored,logPollSeconds:900}});await settle();expect(mocks.call).toHaveBeenCalledTimes(1);
    w.unmount();
  });
  it('keeps empty, fractional and out-of-range drafts local while saving another valid field',async()=>{
    const w=mount(MonitoringSettings,{props:{settings:{...stored}}});
    for (const value of ['', '1', '86401', '30.5']) {await w.findAll('input')[0].setValue(value);await settle();}
    expect(mocks.call).not.toHaveBeenCalled();expect(stored.pollSeconds).toBe(180);
    await w.findAll('input')[1].setValue('12');await settle();
    expect(mocks.call).toHaveBeenCalledWith('update_settings',{patch:{concurrency:12}});
    expect(w.get('[role="alert"]').text()).toContain('Server polling');
    await w.findAll('input')[0].setValue('900');await settle();expect(stored.pollSeconds).toBe(900);
    expect(w.find('[role="alert"]').exists()).toBe(false);w.unmount();
  });
  it('keeps editing enabled during a slow save and writes the newest value next',async()=>{
    let finish!:(settings:Settings)=>void;
    mocks.call.mockImplementationOnce(()=>new Promise<Settings>(resolve=>{finish=resolve;}));
    const w=mount(MonitoringSettings,{props:{settings:{...stored}}});
    await w.findAll('input')[0].setValue('300');await settle();
    expect(w.findAll('input')[0].attributes('disabled')).toBeUndefined();
    await w.findAll('input')[0].setValue('900');await settle();expect(mocks.call).toHaveBeenCalledTimes(1);
    stored={...stored,pollSeconds:300};finish({...stored});await flushPromises();
    expect(mocks.call).toHaveBeenCalledTimes(2);expect(stored.pollSeconds).toBe(900);
    expect((w.findAll('input')[0].element as HTMLInputElement).value).toBe('900');w.unmount();
  });
  it('shows write failures, does not retry unchanged values and allows correction',async()=>{
    mocks.call.mockRejectedValueOnce(new Error('The disk is full'));
    const w=mount(MonitoringSettings,{props:{settings:{...stored}}});
    await w.findAll('input')[0].setValue('300');await settle();
    expect(w.get('[role="alert"]').text()).toContain('The disk is full');
    await vi.advanceTimersByTimeAsync(3000);await w.findAll('input')[0].trigger('blur');await flushPromises();
    expect(mocks.call).toHaveBeenCalledTimes(1);expect(stored.pollSeconds).toBe(180);
    await w.findAll('input')[0].setValue('600');await settle();expect(stored.pollSeconds).toBe(600);w.unmount();
  });
  it('flushes pending valid edits on blur and navigation and notifies the app after unmount',async()=>{
    const observed=vi.fn(),off=onSettingsSaved(observed);
    const w=mount(MonitoringSettings,{props:{settings:{...stored}}});
    const concurrency = w.get('input[max="24"]');
    await concurrency.setValue('25');await settle();
    expect(mocks.call).not.toHaveBeenCalled();
    expect(w.get('[role="alert"]').text()).toContain('1 to 24');
    await concurrency.setValue('24');await concurrency.trigger('blur');await flushPromises();
    expect(stored.concurrency).toBe(24);
    await w.findAll('input')[0].setValue('600');w.unmount();await flushPromises();
    expect(stored.pollSeconds).toBe(600);expect(observed).toHaveBeenLastCalledWith(stored);off();
  });
});
