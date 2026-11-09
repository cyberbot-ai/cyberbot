// @vitest-environment happy-dom
import { mount, flushPromises } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AutomationMode from './AutomationMode.vue';
import type { Settings } from '../types';
const mocks = vi.hoisted(() => ({call:vi.fn()}));
vi.mock('../api', () => ({call:mocks.call}));
const settings: Settings = {mode:'manual',dailyRunLimit:4,dailyTokenLimit:200000,runTokenLimit:50000,autoAgent:'claude',pollSeconds:300,logPollSeconds:1200,concurrency:2,paused:true};
beforeEach(() => { vi.clearAllMocks(); mocks.call.mockImplementation(async (_command,args)=>({...settings,...args?.patch})); });

describe('AI mode control', () => {
  it('changes mode directly, preserves settings and does not start a model itself', async () => {
    const w = mount(AutomationMode, {props:{settings,compact:true}});
    expect(mocks.call).not.toHaveBeenCalled();
    expect(w.get('[role="switch"]').attributes('aria-checked')).toBe('false');
    expect(w.get('[role="switch"]').text()).toBe('AI');
    await w.get('[role="switch"]').trigger('click');
    await flushPromises();
    const next = {...settings,mode:'auto'};
    expect(mocks.call.mock.calls).toEqual([['update_settings',{patch:{mode:'auto'}}]]);
    expect(w.emitted('saved')).toEqual([[next]]);
    await w.setProps({settings:next as Settings});
    expect(w.get('[role="switch"]').attributes('aria-checked')).toBe('true');
    expect(w.get('[role="switch"]').text()).toBe('AI');
    expect(w.get('[role="status"]').attributes('aria-label')).toContain('pause');
    await w.get('[role="switch"]').trigger('click');
    await flushPromises();
    expect(mocks.call).toHaveBeenLastCalledWith('update_settings',{patch:{mode:'manual'}});
    w.unmount();
  });
  it('enables AUTO directly with the default unlimited budgets', async () => {
    const w = mount(AutomationMode,{props:{settings:{...settings,dailyRunLimit:0,dailyTokenLimit:0,runTokenLimit:0},compact:true}});
    await w.get('[role="switch"]').trigger('click');
    await flushPromises();
    expect(w.find('dialog').exists()).toBe(false);
    expect(mocks.call.mock.calls).toEqual([['update_settings',{patch:{mode:'auto'}}]]);
    w.unmount();
  });
  it('retains the saved mode when persistence fails and prevents double submissions', async () => {
    let fail!: (error: Error) => void;
    mocks.call.mockImplementation(() => new Promise((_resolve,reject)=>{fail=reject;}));
    const w = mount(AutomationMode,{props:{settings,compact:true}});
    const auto = w.get('[role="switch"]');
    await auto.trigger('click');
    await auto.trigger('click');
    expect(mocks.call).toHaveBeenCalledTimes(1);
    expect(auto.attributes('disabled')).toBeDefined();
    expect(w.get('[role="switch"]').attributes('aria-checked')).toBe('false');
    fail(new Error('Failure to maintain'));
    await flushPromises();
    expect(w.get('[role="alert"]').text()).toContain('Failure to maintain');
    expect(auto.attributes('aria-checked')).toBe('false');
    expect(auto.attributes('disabled')).toBeUndefined();
    expect(w.emitted('saved')).toBeUndefined();
    w.unmount();
  });
});
