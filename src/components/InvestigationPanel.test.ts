// @vitest-environment happy-dom
import { mount, flushPromises } from '@vue/test-utils';
import { beforeEach, expect, it, vi } from 'vitest';
import InvestigationPanel from './InvestigationPanel.vue';
import type { Investigation } from '../types';

const mocks = vi.hoisted(() => ({ call: vi.fn(), off: vi.fn() }));
vi.mock('./ActionApprovals.vue', () => ({ default: { props: ['runId'], template: '<div class="action-stub">{{runId}}</div>' } }));
vi.mock('../api', () => ({ preview: false, call: mocks.call }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => mocks.off) }));

const run: Investigation = {
  id: 'run-1', agent: 'codex', serverIds: ['server-1'], question: 'Check the CPU',
  status: 'completed', startedAt: 10, endedAt: 20, text: '<script>unsafe()</script>',
  error: null, usage: { inputTokens: 2 }, audit: [], sessionId: null,
  chat: { id: 'chat-1', title: 'Check the CPU', turn: 1 },
};
let history: Investigation[];
let unavailable = false;
beforeEach(() => {
  vi.clearAllMocks();
  history = [];
  unavailable = false;
  mocks.call.mockImplementation(async (command: string, args) => {
    if (command === 'detect_agents') return [{ name: 'codex', ready: !unavailable, reason: 'Entrance required' }];
    if (command === 'investigations') return history.slice();
    if (command === 'investigation') return history.find(item => item.id === args.id);
    if (command === 'start_investigation' || command === 'start_console_chat') {
      const id = 'new-' + history.length;
      const previous = history.find(item => item.chat?.id === args.chatId);
      history.unshift({
        ...run, id, serverIds: args.serverIds, question: args.question, text: 'Response to the message',
        chat: { id: args.chatId ?? id, title: previous?.chat?.title ?? args.question, turn: previous ? 2 : 1, scope: command === 'start_console_chat' ? 'fleet' : undefined },
      });
      return id;
    }
  });
});

it('starts a chat only after sending a message and uses the three model aliases', async () => {
  const w = mount(InvestigationPanel, { props: { serverId: 'server-1' } });
  await flushPromises();
  expect(w.findAll('option').map(item => item.element.value)).toEqual(['low', 'medium', 'high']);
  expect(w.find('textarea').element.value).toBe('');
  expect(mocks.call.mock.calls.some(([command]) => command === 'start_investigation')).toBe(false);
  await w.get('select').setValue('low');
  await w.get('textarea').setValue('Check the CPU');
  await w.get('form').trigger('submit');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('start_investigation', {
    serverIds: ['server-1'], question: 'Check the CPU', modelAlias: 'low',
  });
  expect(w.get('.user-message').text()).toBe('Check the CPU');
  expect(w.get('.message-text').text()).toBe('Response to the message');
  w.unmount();
  expect(mocks.off).toHaveBeenCalledOnce();
});

it('groups persistent turns, sends follow-ups to the selected chat and starts a separate new chat', async () => {
  history = [run, { ...run, id: 'other', startedAt: 4, question: 'Check the disk', chat: null },
    { ...run, id: 'foreign', serverIds: ['server-2'], chat: { id: 'foreign', title: 'Another server', turn: 1 } }];
  const w = mount(InvestigationPanel, { props: { serverId: 'server-1' } });
  await flushPromises();
  expect(w.findAll('.chat-link').map(item => item.text())).toEqual(['Check the CPU', 'Check the disk']);
  expect(w.find('script').exists()).toBe(false);
  expect(w.get('.message-text').text()).toContain('<script>');
  await w.get('textarea').setValue('What next?');
  await w.get('form').trigger('submit');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('start_investigation', {
    serverIds: ['server-1'], question: 'What next?', modelAlias: 'medium', chatId: 'chat-1',
  });
  expect(w.findAll('.user-message').map(item => item.text())).toEqual(['Check the CPU', 'What next?']);
  await w.findAll('.chat-link').find(item => item.text() === 'Check the disk')!.trigger('click');
  expect(w.get('.user-message').text()).toBe('Check the disk');
  await w.get('.new-chat').trigger('click');
  expect(w.find('.user-message').exists()).toBe(false);
  expect(w.get('textarea').element.value).toBe('');
  w.unmount();
});

it('renders Markdown in assistant replies without inserting HTML or loading images', async () => {
  history = [{ ...run, question: '**Check the CPU**', text: [
    '## The result', '', '- **CPU** normally', '',
    '| Metrica | Meaning |', '| --- | --- |', '| CPU | 25% |', '',
    '[Documentation](https://example.test/docs) [Dangerous reference](javascript:alert%281%29)',
    '![Scheme](https://example.test/image.png)', '<script>unsafe()</script>', '',
    '```sh', 'uptime',
  ].join('\n') }];
  const w = mount(InvestigationPanel, { props: { serverId: 'server-1' } });
  await flushPromises();
  const reply = w.get('.message-text');
  expect(reply.get('h2').text()).toBe('The result');
  expect(reply.get('ul li strong').text()).toBe('CPU');
  expect(reply.get('table tbody').text()).toContain('25%');
  expect(reply.get('pre code').text()).toBe('uptime');
  expect(reply.findAll('a').map(link => link.attributes('href'))).toEqual(['https://example.test/docs']);
  expect(reply.find('img, script').exists()).toBe(false);
  expect(reply.text()).toContain('Scheme');
  expect(w.get('.user-message').text()).toBe('**Check the CPU**');
  w.unmount();
});

it('highlights fenced code and copies the original text from only the chosen block', async () => {
  const code = 'const message = "<img src=x>";\n  console.log(message);\n';
  history = [{ ...run, text: '```js\n' + code + '```\n\n```unknown\nplain code\n```' }];
  const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
  const w = mount(InvestigationPanel, { props: { serverId: 'server-1' } });
  await flushPromises();
  const [highlighted, plain] = w.findAll('.chat-code');
  expect(highlighted.get('.hljs-keyword').text()).toBe('const');
  expect(highlighted.find('img').exists()).toBe(false);
  expect(plain.get('code').element.textContent).toBe('plain code\n');
  await highlighted.get('button').trigger('click');
  await flushPromises();
  expect(writeText).toHaveBeenCalledExactlyOnceWith(code);
  expect(highlighted.get('button').text()).toBe('Copied');
  expect(plain.get('button').text()).toBe('Copy');
  w.unmount();
  writeText.mockRestore();
});

it('shows the setup screen as the only available action for an unavailable agent', async () => {
  unavailable = true;
  const w = mount(InvestigationPanel, { props: { serverId: 'server-1' } });
  await flushPromises();
  expect(w.text()).toContain('Entrance required');
  expect(w.find('textarea').exists()).toBe(false);
  expect(w.find('.chat-list').exists()).toBe(false);
  expect(w.findAll('button')).toHaveLength(1);
  expect(w.get('button').text()).toBe('Open AI settings');
  await w.get('button').trigger('click');
  expect(w.emitted('aiSettings')).toHaveLength(1);
  w.unmount();
});

it('cancels an active reply and keeps a question from another tab as a draft', async () => {
  history = [{ ...run, status: 'running' }];
  const w = mount(InvestigationPanel, { props: { serverId: 'server-1' } });
  await flushPromises();
  await w.findAll('button').find(item => item.text() === 'Stop it')!.trigger('click');
  expect(mocks.call).toHaveBeenCalledWith('cancel_investigation', { id: 'run-1' });
  await w.setProps({ ask: { id: 1, text: 'Whether CVE is dangerous?' } });
  await flushPromises();
  expect(w.get('textarea').element.value).toBe('Whether CVE is dangerous?');
  expect(w.get('[type="submit"]').attributes('disabled')).toBeDefined();
  expect(mocks.call.mock.calls.some(([command]) => command === 'start_investigation')).toBe(false);
  history = [{ ...run, status: 'cancelled' }];
  await w.findAll('button').find(item => item.text() === 'Stop current task')!.trigger('click');
  await flushPromises();
  expect(mocks.call.mock.calls.filter(([command]) => command === 'cancel_investigation'))
    .toEqual(Array(2).fill(['cancel_investigation', { id: 'run-1' }]));
  expect(w.get('[type="submit"]').attributes('disabled')).toBeUndefined();
  expect(w.get('textarea').element.value).toBe('Whether CVE is dangerous?');
  w.unmount();
});

it('unlocks a draft from Ask AI when the active session ends without an event', async () => {
  vi.useFakeTimers();
  history = [{ ...run, status: 'running', endedAt: null }];
  const w = mount(InvestigationPanel, { props: {
    serverId: 'server-1', ask: { id: 1, text: 'What to do after MCP rejection?' },
  } });
  try {
    await flushPromises();
    expect(w.get('[type="submit"]').attributes('disabled')).toBeDefined();
    history = [{ ...run, status: 'completed' }];
    await vi.advanceTimersByTimeAsync(3000);
    await flushPromises();
    expect(w.get('[type="submit"]').attributes('disabled')).toBeUndefined();
    expect(w.get('textarea').element.value).toBe('What to do after MCP rejection?');
    await w.get('form').trigger('submit');
    await flushPromises();
    expect(mocks.call).toHaveBeenCalledWith('start_investigation', {
      serverIds: ['server-1'], question: 'What to do after MCP rejection?', modelAlias: 'medium',
    });
  } finally {
    w.unmount();
    vi.useRealTimers();
  }
});

it('sends an explicit question from another tab once', async () => {
  const w = mount(InvestigationPanel, { props: { serverId: 'server-1', ask: { id: 1, text: 'Whether CVE is dangerous?' } } });
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('start_investigation', {
    serverIds: ['server-1'], question: 'Whether CVE is dangerous?', modelAlias: 'medium',
  });
  await w.setProps({ ask: { id: 1, text: 'Whether CVE is dangerous?' } });
  expect(mocks.call.mock.calls.filter(([command]) => command === 'start_investigation')).toHaveLength(1);
  w.unmount();
});

it('keeps the draft after a rejected send and offers no setup shortcut when the agent is ready', async () => {
  const respond = mocks.call.getMockImplementation()!;
  mocks.call.mockImplementation(async (command, args) => {
    if (command === 'start_investigation') throw new Error('Isolation not available');
    return respond(command, args);
  });
  const w = mount(InvestigationPanel, { props: { serverId: 'server-1' } });
  await flushPromises();
  await w.get('textarea').setValue('Check the network');
  await w.get('form').trigger('submit');
  await flushPromises();
  expect(w.get('[role="alert"]').text()).toContain('Isolation not available');
  expect(w.get('textarea').element.value).toBe('Check the network');
  expect(w.text()).not.toContain('Open AI settings');
  expect(mocks.call.mock.calls.filter(([command]) => command === 'start_investigation')).toHaveLength(1);
  w.unmount();
});

it('keeps fleet chats separate and resumes only with the original selected servers', async () => {
  history = [run, {
    ...run, id: 'fleet-run', serverIds: ['db-1', 'db-2'], question: 'Compare the discs',
    chat: { id: 'fleet-chat', title: 'Compare the discs', turn: 1, scope: 'fleet' },
  }];
  const w = mount(InvestigationPanel, { props: {
    fleetServerIds: ['db-3'], fleetServerNames: { 'db-1': 'db-1', 'db-2': 'db-2', 'db-3': 'db-3' },
  } });
  await flushPromises();
  expect(w.text()).toContain('Compare the discs');
  expect(w.text()).not.toContain('Check the CPU');
  expect(w.get('textarea').element.disabled).toBe(true);
  await w.findAll('button').find(button => button.text() === 'Use servers from this chat')!.trigger('click');
  expect(w.emitted('useServers')).toEqual([[['db-1', 'db-2']]]);
  await w.setProps({ fleetServerIds: ['db-2', 'db-1'] });
  await w.get('textarea').setValue('What’s next?');
  await w.get('form').trigger('submit');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('start_console_chat', {
    serverIds: ['db-2', 'db-1'], question: 'What’s next?', modelAlias: 'medium', chatId: 'fleet-chat',
  });
  await w.findAll('button').find(button => button.text() === 'New chat')!.trigger('click');
  await w.setProps({ fleetServerIds: ['db-3'] });
  await w.get('textarea').setValue('Check the db-3');
  await w.get('form').trigger('submit');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('start_console_chat', {
    serverIds: ['db-3'], question: 'Check the db-3', modelAlias: 'medium',
  });
  w.unmount();
});

it('keeps each action inside its chat turn and the composer free of action panels', async () => {
  history = [run, {...run, id: 'run-2', startedAt: 30, chat: {...run.chat!, turn: 2}}];
  const w = mount(InvestigationPanel, {props: {serverId: 'server-1'}});await flushPromises();
  expect(w.get('.messages').findAll('.action-stub').map(item => item.text())).toEqual(['run-1', 'run-2']);
  expect(w.get('.composer-area').find('.action-stub').exists()).toBe(false);
  w.unmount();
});
