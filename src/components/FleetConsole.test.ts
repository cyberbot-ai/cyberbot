// @vitest-environment happy-dom
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Server } from '../types';
import { serverDirectory, serverDirectoryKey } from '../serverDirectory';
import FleetConsole from './FleetConsole.vue';

const { call } = vi.hoisted(() => ({ call: vi.fn() }));
vi.mock('../api', () => ({ call, preview: false }));

const servers = Array.from({ length: 100 }, (_, i) => {
  const host = i < 30 ? `db-${i + 1}` : `web-${i + 1}`;
  return { id: String(i), name: host, endpoint: { host: `${host}.prod`, user: 'ops', port: 22, jumpHost: null } } as Server;
});
const row = { id: '0', name: 'db-1', address: 'ops@db-1.prod:22', status: 'ok', code: 0, durationMs: 200, reason: null };
beforeEach(() => {
  vi.clearAllMocks();
  call.mockImplementation(async (command, args) => {
    if (command === 'prepare_console_batch') return { ticket: 't', confirmAll: args.all, targets: [row] };
    if (command === 'start_console_batch') return { id: 't', revision: 0, active: false, rows: [row], command: 'df -h' };
    if (command === 'console_batch_output') return { stdout: 'Filesystem', stderr: '', truncated: false };
    return null;
  });
});

it('selects 30 matches, toggles a range with Shift and keeps explicit empty separate from all', async () => {
  const wrapper = mount(FleetConsole, { props: { servers, modelValue: null, 'onUpdate:modelValue': value => wrapper.setProps({ modelValue: value }) } });
  await wrapper.get('[aria-label="Selection of servers"]').trigger('click');
  await wrapper.get('input[role=combobox]').setValue('db');
  expect(wrapper.findAll('[role=option]')).toHaveLength(30);
  const options = wrapper.findAll('[role=option]');
  await options[1].trigger('click');
  await options[4].trigger('click', { shiftKey: true });
  expect(wrapper.props('modelValue')).toEqual(['1', '2', '3', '4']);
  await wrapper.get('input[role=combobox]').trigger('keydown', { key: 'ArrowDown' });
  await wrapper.get('input[role=combobox]').trigger('keydown', { key: ' ' });
  expect(wrapper.props('modelValue')).toContain('5');
  await wrapper.findAll('button').find(button => button.text() === 'Select found · 30')!.trigger('click');
  expect(wrapper.props('modelValue')).toHaveLength(30);
  expect(wrapper.text()).toContain('+27');
  await wrapper.setProps({ servers: servers.slice(30) });
  expect(wrapper.props('modelValue')).toEqual([]);
  await wrapper.get('textarea').setValue('df -h');
  await wrapper.get('textarea').trigger('keydown', { key: 'Enter' });
  expect(call).not.toHaveBeenCalledWith('prepare_console_batch', expect.anything());
  wrapper.unmount();
});

it('submits only on Enter, runs selected hosts immediately and loads output on expansion', async () => {
  const open = vi.fn();
  const directory = serverDirectory(servers);
  const wrapper = mount(FleetConsole, { props: { servers, modelValue: ['0'] }, global: { provide: { [serverDirectoryKey as symbol]: { current: () => directory, open } } } });
  const command = wrapper.get('textarea');
  await command.setValue('df -h');
  await command.trigger('keydown', { key: 'Enter', shiftKey: true });
  expect(call).not.toHaveBeenCalledWith('prepare_console_batch', expect.anything());
  await command.trigger('keydown', { key: 'Enter' });
  await flushPromises();
  expect(call).toHaveBeenCalledWith('prepare_console_batch', { serverIds: ['0'], command: 'df -h', all: false });
  expect(call).toHaveBeenCalledWith('start_console_batch', { ticket: 't', confirmed: false });
  expect(wrapper.text()).toContain('1 OK');
  expect(call).not.toHaveBeenCalledWith('console_batch_output', expect.anything());
  const host = wrapper.get('.result-row .server-link');
  expect(host.text()).toBe('db-1.prod');
  await host.trigger('click');
  expect(open).toHaveBeenCalledWith('0', undefined);
  expect(call).not.toHaveBeenCalledWith('console_batch_output', expect.anything());
  await wrapper.get('button.disclosure').trigger('click');
  await flushPromises();
  expect(wrapper.text()).toContain('Filesystem');
  wrapper.unmount();
});

it('shows the exact command before starting the whole fleet', async () => {
  const wrapper = mount(FleetConsole, { props: { servers, modelValue: null } });
  await wrapper.get('textarea').setValue('df -h\nprintf ready');
  await wrapper.get('textarea').trigger('keydown', { key: 'Enter' });
  await flushPromises();
  expect(wrapper.get('dialog pre').element.textContent).toBe('df -h\nprintf ready');
  expect(call).not.toHaveBeenCalledWith('start_console_batch', expect.anything());
  await wrapper.findAll('dialog button').find(button => button.text() === 'Confirm')!.trigger('click');
  await flushPromises();
  expect(call).toHaveBeenCalledWith('start_console_batch', { ticket: 't', confirmed: true });
  wrapper.unmount();
});
