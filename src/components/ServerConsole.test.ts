// @vitest-environment happy-dom
import { flushPromises, mount } from '@vue/test-utils';
import { beforeEach, expect, it, vi } from 'vitest';
import ServerConsole from './ServerConsole.vue';
import ServerDetail from './ServerDetail.vue';
import type { Server } from '../types';

const mocks = vi.hoisted(() => ({
  call: vi.fn(),
  dispose: vi.fn(),
  write: vi.fn((_bytes: Uint8Array, done: () => void) => done()),
}));

vi.mock('../api', () => ({ preview: false, call: mocks.call }));
vi.mock('@tauri-apps/api/core', () => ({
  Channel: class {
    constructor(public onmessage: (event: unknown) => void) {}
  },
}));
vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    cols = 80;
    rows = 24;
    options = { disableStdin: true };
    parser = { registerOscHandler: vi.fn() };
    dispose = mocks.dispose;
    write = mocks.write;
    loadAddon() {}
    open() {}
    focus() {}
    attachCustomKeyEventHandler() {}
    onData() {}
    onBinary() {}
  },
}));
vi.mock('@xterm/addon-fit', () => ({
  FitAddon: class { proposeDimensions() { return undefined; } },
}));

const server: Server = {
  id: 'server-1', sourceId: 'source', name: 'Test server',
  endpoint: { host: 'localhost', user: 'ops', port: 22, identityFile: null, jumpHost: null },
  observation: null, lastError: null, lastAttempt: null, nextCheck: 0, failures: 0,
};

function receive(event: unknown) {
  const args = mocks.call.mock.calls.find(([command]) => command === 'console_open')?.[1];
  args.onEvent.onmessage(event);
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.call.mockImplementation(async (command: string) => command === 'console_open' ? 'session-1' : []);
});

it('keeps the same terminal and SSH channel across tabs until the server closes', async () => {
  const view = mount(ServerDetail, { props: { server, now: 100, interval: 180 } });
  const tab = (name: string) => view.findAll('nav button').find(button => button.text() === name)!.trigger('click');
  await tab('Console');
  await vi.dynamicImportSettled();
  await flushPromises();
  expect(mocks.call).not.toHaveBeenCalledWith('console_open', expect.anything());
  await view.get('.toolbar button').trigger('click');
  await flushPromises();
  receive({ kind: 'ready' });
  await tab('Overview');
  receive({ kind: 'output', sequence: 1, bytes: [111, 107] });
  await flushPromises();
  expect(mocks.write).toHaveBeenCalledWith(Uint8Array.of(111, 107), expect.any(Function));
  expect(mocks.call).toHaveBeenCalledWith('console_send', {
    id: 'session-1', message: { kind: 'ack', sequence: 1 },
  });
  await tab('Console');
  expect(view.get('[role="status"]').text()).toBe('SSH connected');
  expect(mocks.call.mock.calls.filter(([command]) => command === 'console_open')).toHaveLength(1);
  expect(mocks.dispose).not.toHaveBeenCalled();
  view.unmount();
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('console_close', { id: 'session-1' });
  expect(mocks.dispose).toHaveBeenCalledOnce();
});

it('closes the session if the server page unmounts before registration returns', async () => {
  let register!: (id: string) => void;
  mocks.call.mockImplementationOnce(() => new Promise<string>(resolve => { register = resolve; }));
  const view = mount(ServerConsole, { props: { serverId: server.id } });
  await view.get('button').trigger('click');
  await flushPromises();
  view.unmount();
  register('pending-session');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('console_close', { id: 'pending-session' });
  receive({ kind: 'output', sequence: 1, bytes: [42] });
  expect(mocks.write).not.toHaveBeenCalled();
});

it('keeps the terminal after exit and replaces it on explicit reconnect', async () => {
  const view = mount(ServerConsole, { props: { serverId: server.id } });
  await view.get('button').trigger('click');
  await flushPromises();
  receive({ kind: 'end', code: 7, error: null });
  await flushPromises();
  expect(view.get('[role="status"]').text()).toBe('Session ended · exit code 7');
  expect(mocks.dispose).not.toHaveBeenCalled();
  await view.get('button').trigger('click');
  await flushPromises();
  expect(mocks.dispose).toHaveBeenCalledOnce();
  view.unmount();
});
