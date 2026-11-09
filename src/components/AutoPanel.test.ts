// @vitest-environment happy-dom
import { mount, flushPromises } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import AutoPanel from './AutoPanel.vue';
import type { Settings } from '../types';

const mocks = vi.hoisted(() => ({ call: vi.fn() }));
vi.mock('./ActionApprovals.vue', () => ({ default: { template: '<div />' } }));
vi.mock('../api', () => ({ preview: false, call: mocks.call }));
const settings: Settings = { mode: 'manual', dailyRunLimit: null, dailyTokenLimit: null, runTokenLimit: 50000, autoAgent: 'codex', pollSeconds: 180, logPollSeconds: 600, concurrency: 4, paused: false };
const status = { day: 20000, runs: 1, actualTokens: 300, chargedTokens: 50000, reservedTokens: 0, uncertainRuns: 1, queued: 0, jobs: [], blockedReason: null, waitingReason: null };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.call.mockImplementation(async (command, args) => {
    if (command === 'update_settings') return { ...settings, ...args?.patch };
    if (command === 'ai_profiles') return { revision: 1, providers: {} };
    return status;
  });
});
afterEach(() => vi.useRealTimers());

describe('AI tabs', () => {
  it('loads each panel on first entry, moves keyboard focus, and stops polling hidden sessions', async () => {
    vi.useFakeTimers();
    const w = mount(AutoPanel, { props: { settings }, attachTo: document.body });
    await flushPromises();
    expect(mocks.call.mock.calls).toEqual([['auto_status']]);
    expect(w.text()).toContain('50,000');
    const sessions = w.get('#ai-sessions-tab');
    const settingsTab = w.get('#ai-settings-tab');
    await sessions.trigger('keydown', { key: 'End' });
    await flushPromises();
    expect(document.activeElement).toBe(settingsTab.element);
    expect(settingsTab.attributes('aria-selected')).toBe('true');
    expect(w.get('#ai-sessions-panel').isVisible()).toBe(false);
    expect(mocks.call.mock.calls).toEqual([['auto_status']]);
    const profiles = w.get<HTMLDetailsElement>('#ai-settings-panel .profiles');
    profiles.element.open = true;
    await profiles.trigger('toggle');
    await flushPromises();
    expect(mocks.call.mock.calls).toEqual([['auto_status'], ['ai_profiles']]);
    await vi.advanceTimersByTimeAsync(30000);
    expect(mocks.call.mock.calls).toHaveLength(2);
    await settingsTab.trigger('keydown', { key: 'ArrowRight' });
    await flushPromises();
    expect(document.activeElement).toBe(sessions.element);
    expect(mocks.call.mock.calls).toEqual([['auto_status'], ['ai_profiles'], ['auto_status']]);
    w.unmount();
  });

  it('opens the limits from the queue and autosaves edits after leaving settings', async () => {
    vi.useFakeTimers();
    mocks.call.mockResolvedValueOnce({ ...status, waitingReason: 'Exhausted the launch limit' });
    const w = mount(AutoPanel, { props: { settings }, attachTo: document.body });
    await flushPromises();
    await w.findAll('button').find(button => button.text() === 'Edit limits')!.trigger('click');
    await flushPromises();
    expect(w.get('#ai-settings-tab').attributes('aria-selected')).toBe('true');
    const limits = w.get<HTMLDetailsElement>('#ai-settings-panel details');
    expect(limits.element.open).toBe(true);
    expect(document.activeElement).toBe(limits.get('summary').element);
    await w.get('[data-test="daily-tokens"]').setValue('80000');
    await w.get('[data-test="daily-runs"]').setValue('2');
    await w.get('#ai-actions-tab').trigger('click');
    await w.setProps({ settings: { ...settings, mode: 'auto', pollSeconds: 600 } });
    await vi.advanceTimersByTimeAsync(250);
    expect(mocks.call).toHaveBeenCalledWith('update_settings', { patch: { dailyTokenLimit: 80000, dailyRunLimit: 2 } });
    await w.get('#ai-settings-tab').trigger('click');
    expect(limits.element.open).toBe(true);
    expect(w.get<HTMLInputElement>('[data-test="daily-tokens"]').element.value).toBe('80000');
    expect(mocks.call).not.toHaveBeenCalledWith('ai_profiles');
    w.unmount();
  });

  it('keeps all limits in one closed group and saves zero', async () => {
    vi.useFakeTimers();
    const w = mount(AutoPanel, { props: { tab: 'settings', settings: { ...settings, dailyRunLimit: 3, dailyTokenLimit: 200000 } } });
    await flushPromises();
    const limits = w.get<HTMLDetailsElement>('#ai-settings-panel details');
    expect(limits.get('summary').text()).toBe('Limits');
    expect(limits.element.open).toBe(false);
    expect(limits.findAll('input')).toHaveLength(3);
    const session = limits.get('[data-test="run-tokens"]');
    expect(session.attributes('min')).toBeUndefined();
    expect(session.attributes('max')).toBeUndefined();
    for (const input of limits.findAll('input')) await input.setValue('0');
    await vi.advanceTimersByTimeAsync(250);
    expect(mocks.call).toHaveBeenCalledWith('update_settings', { patch: { dailyTokenLimit: 0, dailyRunLimit: 0, runTokenLimit: 0 } });
    w.unmount();
  });

  it('shows unknown usage and requires explicit resume without resetting budget', async () => {
    mocks.call.mockResolvedValue({ ...status, blockedReason: 'Expenditure unknown' });
    const w = mount(AutoPanel, { props: { settings } });
    await flushPromises();
    expect(w.get('[role="status"]').text()).toContain('Expenditure unknown');
    expect(mocks.call).not.toHaveBeenCalledWith('resume_auto');
    await w.findAll('button').find(button => button.text().includes('Confirm usage and resume'))!.trigger('click');
    await flushPromises();
    expect(mocks.call).toHaveBeenCalledWith('resume_auto', undefined);
    expect(mocks.call.mock.calls.some(([command]) => command === 'update_settings')).toBe(false);
    w.unmount();
  });

  it('keeps edits during refresh and shows a backend refusal without retry', async () => {
    vi.useFakeTimers();
    const w = mount(AutoPanel, { props: { settings, tab: 'settings' } });
    await flushPromises();
    const limit = w.get<HTMLInputElement>('[data-test="daily-tokens"]');
    await limit.setValue('70000');
    await w.setProps({ settings: { ...settings, paused: true } });
    expect(limit.element.value).toBe('70000');
    mocks.call.mockRejectedValueOnce(new Error('Wrong budget'));
    await vi.advanceTimersByTimeAsync(250);
    expect(w.get('[role="alert"]').text()).toContain('Wrong budget');
    expect(mocks.call.mock.calls.filter(([command]) => command === 'update_settings')).toHaveLength(1);
    w.unmount();
  });

  it('preserves a limit while the input is empty', async () => {
    vi.useFakeTimers();
    const w = mount(AutoPanel, { props: { settings, tab: 'settings' } });
    await flushPromises();
    mocks.call.mockClear();
    const limit = w.get('[data-test="run-tokens"]');
    await limit.setValue('');
    await vi.advanceTimersByTimeAsync(250);
    expect(mocks.call).not.toHaveBeenCalled();
    await limit.setValue('1200000');
    await vi.advanceTimersByTimeAsync(250);
    expect(mocks.call).toHaveBeenCalledWith('update_settings', { patch: { runTokenLimit: 1200000 } });
    w.unmount();
  });

  it('allows dismissal of a queued episode and cancellation of an active run', async () => {
    const job = { id: 'episode', serverId: 'server', title: 'CPU', evidence: '95%', occurrences: 10, notBefore: 1, createdAt: 1 };
    mocks.call.mockResolvedValue({ ...status, queued: 1, jobs: [{ ...job, state: 'queued' }, { ...job, id: 'active', state: 'running', runId: 'run' }] });
    const w = mount(AutoPanel, { props: { settings } });
    await flushPromises();
    await w.findAll('button').find(button => button.text() === 'Skip')!.trigger('click');
    await flushPromises();
    expect(mocks.call).toHaveBeenCalledWith('dismiss_auto_job', { id: 'episode' });
    await w.findAll('button').find(button => button.text() === 'Stop')!.trigger('click');
    expect(mocks.call).toHaveBeenCalledWith('cancel_investigation', { id: 'run' });
    w.unmount();
  });
});
