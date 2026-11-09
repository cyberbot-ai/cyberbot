// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import ActionApprovals from './ActionApprovals.vue';
import {actionFixture} from '../test/actionFixture';
import type {ActionCard,ActionRequest} from '../types';
const mock=vi.hoisted(()=>({call:vi.fn(),off:vi.fn()}));
vi.mock('../api',()=>({preview:false,call:mock.call}));vi.mock('@tauri-apps/api/event',()=>({listen:vi.fn(async()=>mock.off)}));
let request:ActionRequest;
const card=():ActionCard=>({id:request.id,runId:request.runId,serverId:request.serverId,serverLabel:request.serverLabel,goal:request.artifact.spec.goal,state:request.state,createdAt:request.createdAt,expiresAt:request.expiresAt,action:request.artifact.spec.action,review:request.review,artifactHash:request.artifactHash,error:request.error,sessionGranted:false});
beforeEach(()=>{vi.useFakeTimers();mock.call.mockReset();request=actionFixture();mock.call.mockImplementation(async(command)=>{if(command==='action_requests')return [card()];if(command==='action_request')return structuredClone(request);});});afterEach(()=>vi.useRealTimers());
async function openAction(w: ReturnType<typeof mount<typeof ActionApprovals>>) {
  await flushPromises();
  await w.get('.request').trigger('click');
  await flushPromises();
}
it('opens a separate consent window without approving from the AI page', async () => {
  const w = mount(ActionApprovals);
  await openAction(w);
  expect(w.findAll('details[open]')).toHaveLength(0);
  expect(w.findAll('button').some(b => ['Allow once', 'Allow for this run', 'Decline'].includes(b.text()))).toBe(false);
  await w.get('.approval .primary').trigger('click');
  await flushPromises();
  expect(mock.call).toHaveBeenCalledWith('open_action_approval', { id: request.id });
  expect(mock.call.mock.calls.some(c => c[0] === 'decide_action')).toBe(false);
  w.unmount();
});
it('shows historical code safely without a remote request', async () => {
  request = actionFixture('succeeded');
  const w = mount(ActionApprovals);
  await openAction(w);
  expect(w.find('script').exists()).toBe(false);
  expect(w.get('.code pre').text()).toContain('<script>');
  expect(w.get('.code').attributes('open')).toBeUndefined();
  expect(mock.call.mock.calls.map(c => c[0])).toEqual(['action_requests', 'action_request']);
  w.unmount();
});
it('keeps a failed window opening visible without retry', async () => {
  const w = mount(ActionApprovals);
  await openAction(w);
  mock.call.mockRejectedValueOnce(new Error('Window unavailable'));
  await w.get('.approval .primary').trigger('click');
  await flushPromises();
  expect(w.get('[role=alert]').text()).toContain('Window unavailable');
  expect(mock.call.mock.calls.filter(c => c[0] === 'open_action_approval')).toHaveLength(1);
  w.unmount();
});
it('offers only an explicit saved receipt read for unknown effects', async () => {
  request = actionFixture('unknown');
  const w = mount(ActionApprovals);
  await openAction(w);
  await w.findAll('button').find(b => b.text() === 'Check saved result')!.trigger('click');
  await flushPromises();
  expect(mock.call).toHaveBeenCalledWith('refresh_action_result', { id: request.id });
  expect(mock.call.mock.calls.some(c => c[0] === 'decide_action' || c[0] === 'rollback_action')).toBe(false);
  w.unmount();
});
it('shows rollback only for a verified Nginx backup', async () => {
  request = actionFixture('succeeded');
  request.artifact.spec.action = { kind: 'nginx_workers', workerProcesses: '2', activation: 'reload' };
  request.result = { effect: { rollbackAvailable: true } };
  const w = mount(ActionApprovals);
  await openAction(w);
  await w.findAll('button').find(b => b.text() === 'Restore original configuration')!.trigger('click');
  expect(mock.call).toHaveBeenCalledWith('rollback_action', { id: request.id, artifactHash: request.artifactHash });
  await flushPromises();
  w.unmount();
});
it('does not poll while hidden',async()=>{const w=mount(ActionApprovals);await flushPromises();mock.call.mockClear();Object.defineProperty(document,'hidden',{value:true,configurable:true});await vi.advanceTimersByTimeAsync(60000);expect(mock.call).not.toHaveBeenCalled();delete (document as unknown as Record<string,unknown>).hidden;w.unmount();});
it('refreshes the visible tab and preserves its selected request when reopened', async () => {
  const older = actionFixture('succeeded');
  older.id = 'older';
  older.artifact.spec.goal = 'Completed action';
  mock.call.mockImplementation(async (command, args) => {
    if (command === 'action_requests') {
      return [card(), { ...card(), id: older.id, state: older.state, goal: older.artifact.spec.goal }];
    }
    if (command === 'action_request') return args.id === older.id ? older : request;
  });
  const w = mount(ActionApprovals, { props: { active: false } });
  await flushPromises();
  expect(mock.call).not.toHaveBeenCalled();
  await w.setProps({ active: true });
  await flushPromises();
  await w.findAll('.request')[1].trigger('click');
  await flushPromises();
  expect(w.get('.detail h2').text()).toBe('Completed action');
  await w.setProps({ active: false });
  mock.call.mockClear();
  await vi.advanceTimersByTimeAsync(30000);
  expect(mock.call).not.toHaveBeenCalled();
  await w.setProps({ active: true });
  await flushPromises();
  expect(mock.call.mock.calls).toEqual([
    ['action_requests', { runId: null, serverId: null }],
    ['action_request', { id: older.id }],
  ]);
  expect(w.get('.detail h2').text()).toBe('Completed action');
  w.unmount();
});

it('groups actions and returns to the same position and row without preloading details', async () => {
  mock.call.mockImplementation(async (command) => {
    if (command === 'action_requests') return [
      { ...card(), id: 'done', state: 'succeeded', goal: 'Completed action' },
      { ...card(), id: 'running', state: 'running', goal: 'Launched action' },
      card(),
    ];
    if (command === 'action_request') return request;
  });
  const panel = document.createElement('div');
  document.body.append(panel);
  const w = mount(ActionApprovals, { attachTo: panel });
  await flushPromises();
  expect(w.findAll('.action-group h3').map(heading => heading.text())).toEqual(['Awaiting decision 1', 'In progress 1', 'History 1']);
  expect(w.find('article').exists()).toBe(false);
  expect(mock.call.mock.calls.map(c => c[0])).toEqual(['action_requests']);
  const viewport = w.element.parentElement!;
  viewport.scrollTop = 100;
  const row = w.get('.request');
  await row.trigger('click');
  await flushPromises();
  expect(w.get('.action-list').isVisible()).toBe(false);
  expect(w.get('.detail h2').text()).toBe(request.artifact.spec.goal);
  expect(viewport.scrollTop).toBe(0);
  expect(document.activeElement).toBe(w.get('.back').element);
  await w.get('.back').trigger('click');
  await flushPromises();
  expect(w.get('.action-list').isVisible()).toBe(true);
  expect(w.find('article').exists()).toBe(false);
  expect(viewport.scrollTop).toBe(100);
  expect(document.activeElement).toBe(row.element);
  w.unmount();
  panel.remove();
});

it('replaces proposed effects with the recorded result when a shell action completes', async () => {
  request.artifact.spec.action = { kind: 'shell' };
  request.artifact.provider = 'claude';
  request.artifact.prepared = { user: 'root' };
  const w = mount(ActionApprovals);
  await openAction(w);
  expect(w.get('.facts').text()).toContain('Claude Code');
  expect(w.get('.impact').text()).toContain('No host writers');
  expect(w.get('.code summary').text()).toBe('Commands to run');
  request.state = 'succeeded';
  request.result = { result: { exitCode: 0, stdout: 'Packages updated', stderr: '', truncated: true } };
  await vi.advanceTimersByTimeAsync(15000);
  await flushPromises();
  expect(w.get('.impact').text()).toContain('Commands completed successfully (exit code 0).');
  expect(w.get('.impact').text()).not.toContain('No host writers');
  expect(w.get('.output').text()).toContain('Packages updated');
  expect(w.get('.output').text()).toContain('Output was truncated');
  expect(w.get('.code summary').text()).toBe('Executed commands');
  expect(w.find('.approval').exists()).toBe(false);
  await w.get('.back').trigger('click');
  expect(w.get('.action-group h3').text()).toBe('History 1');
  w.unmount();
});

it('ignores a detail response after returning to the list', async () => {
  const w = mount(ActionApprovals);
  await flushPromises();
  let resolve!: (value: ActionRequest) => void;
  mock.call.mockImplementationOnce(() => new Promise(done => { resolve = done; }));
  await w.get('.request').trigger('click');
  expect(w.get('[role=status]').text()).toBe('Loading action…');
  await w.get('.back').trigger('click');
  resolve(request);
  await flushPromises();
  expect(w.get('.action-list').isVisible()).toBe(true);
  expect(w.find('article').exists()).toBe(false);
  w.unmount();
});
it('keeps completed chat actions collapsed, loads details on demand and allows closing them',async()=>{
  request=actionFixture('succeeded');const w=mount(ActionApprovals,{props:{compact:true,runId:request.runId}});await flushPromises();
  expect(w.find('article').exists()).toBe(false);
  expect(w.find('pre').exists()).toBe(false);
  expect(w.get('.compact-toggle').text()).toContain('Completed');
  expect(mock.call.mock.calls.map(c=>c[0])).toEqual(['action_requests']);
  await w.get('.compact-toggle').trigger('click');await flushPromises();
  expect(w.find('article').exists()).toBe(true);
  expect(w.get('.code').attributes('open')).toBeUndefined();
  await w.get('.compact-toggle').trigger('click');await flushPromises();
  expect(w.find('article').exists()).toBe(false);
  expect(w.get('.compact-toggle').attributes('aria-expanded')).toBe('false');
  w.unmount();
});
it('reopens pending consent from a chat without relying on a notification',async()=>{
  const w=mount(ActionApprovals,{props:{compact:true,runId:request.runId}});await flushPromises();
  expect(w.find('pre').exists()).toBe(false);
  await w.get('.compact-row .primary').trigger('click');await flushPromises();
  expect(mock.call).toHaveBeenCalledWith('open_action_approval',{id:request.id});
  request.state='succeeded';await vi.advanceTimersByTimeAsync(15000);await flushPromises();
  expect(w.find('.compact-row .primary').exists()).toBe(false);
  expect(w.get('.compact-toggle').text()).toContain('Completed');
  expect(w.find('article').exists()).toBe(false);w.unmount();
});
it('does not reopen details when their response arrives after collapsing',async()=>{
  request=actionFixture('succeeded');const w=mount(ActionApprovals,{props:{compact:true,runId:request.runId}});await flushPromises();
  let resolve!:(value:ActionRequest)=>void;
  mock.call.mockImplementationOnce(()=>new Promise(done=>{resolve=done;}));
  await w.get('.compact-toggle').trigger('click');
  await w.get('.compact-toggle').trigger('click');
  resolve(request);await flushPromises();
  expect(w.find('article').exists()).toBe(false);
  expect(w.get('.compact-toggle').attributes('aria-expanded')).toBe('false');w.unmount();
});
