// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import ActivityLog from './ActivityLog.vue';
import type {ActivityPage} from '../types';
const mocks=vi.hoisted(()=>({call:vi.fn()}));
vi.mock('../api',()=>({call:mocks.call}));
const page=(action='SSH connection',next:string|null=null):ActivityPage=>({events:[{id:action,at:1700000000000,category:'ssh',action,phase:'completed',operationId:'op',target:'ops@host:22',runId:null,durationMs:230}],next,expired:false,skipped:0,storage:{bytes:2048,limitBytes:31457280,dropped:0,error:null}});
beforeEach(()=>{vi.clearAllMocks();mocks.call.mockResolvedValue(page());});
afterEach(()=>{vi.useRealTimers();});
describe('action journal',()=>{
 it('opens the exact monitoring definition and instance without remote work',async()=>{
  const result=page('Collect metrics');result.events[0].monitoring={definitionId:'redis',serverId:'one',instanceId:'cache',trigger:'schedule',version:'definition-v1',revision:1};mocks.call.mockResolvedValue(result);
  const w=mount(ActivityLog);await flushPromises();expect(w.text()).toContain('redis · scheduled');await w.get('.definition').trigger('click');expect(w.emitted('monitoring')).toEqual([[{definitionId:'redis',serverId:'one',instanceId:'cache'}]]);expect(mocks.call.mock.calls.every(c=>c[0]==='activity_log')).toBe(true);w.unmount();
 });
 it('shows the captured domain with its SSH address in the hint',async()=>{
  const result=page('poll');
  result.events[0]={...result.events[0],category:'server',target:'57add7696be9440cd8ef78b4',server:{name:'db.production',address:'ops@10.20.1.11:2222'}};
  mocks.call.mockResolvedValue(result);
  const w=mount(ActivityLog);await flushPromises();
  expect(w.get('.target').text()).toBe('db.production');
  expect(w.get('.target [title]').attributes('title')).toBe('db.production · ops@10.20.1.11:2222');
  expect(w.text()).not.toContain('57add7696be9440cd8ef78b4');
  expect(mocks.call.mock.calls.every(c=>c[0]==='activity_log')).toBe(true);w.unmount();
 });
 it('falls back to the recorded address and escapes server names',async()=>{
  const result=page();
  result.events[0]={...result.events[0],target:'57add7696be9440cd8ef78b4',server:{name:'',address:'root@[::1]:2222'}};
  mocks.call.mockResolvedValueOnce(result).mockResolvedValue({...result,events:[{...result.events[0],server:{name:'<script>host</script>',address:'ops@host:22'}}]});
  const w=mount(ActivityLog);await flushPromises();
  expect(w.get('.target').text()).toBe('::1');
  await w.findAll('button').find(b=>b.text()==='Refresh')!.trigger('click');await flushPromises();
  expect(w.get('.target').text()).toBe('host');expect(w.get('.target [title]').attributes('title')).toContain('<script>host</script>');expect(w.find('script').exists()).toBe(false);w.unmount();
 });
 it('shows relative dates from millisecond timestamps',async()=>{
  vi.useFakeTimers();vi.setSystemTime(1700000062000);
  const w=mount(ActivityLog);await flushPromises();
  expect(w.get('.at').text()).toBe('1 minute ago');
  expect(w.get('.at time').attributes('datetime')).toBe('2023-11-14T22:13:20.000Z');
  w.unmount();
 });
 it('reads structured events and applies filters without starting infrastructure work',async()=>{
  const w=mount(ActivityLog);await flushPromises();
  expect(mocks.call.mock.calls).toEqual([['activity_log',{query:{before:null,category:null,phase:null,search:null}}]]);
  expect(w.text()).toContain('SSH connection');expect(w.get('.target').text()).toBe('host');
  vi.useFakeTimers();await w.get('[aria-label="Action category"]').setValue('ai');await w.get('[aria-label="Action result"]').setValue('failed');await w.get('[aria-label="Search the activity log"]').setValue('host');await vi.advanceTimersByTimeAsync(251);await flushPromises();
  expect(mocks.call).toHaveBeenLastCalledWith('activity_log',{query:{before:null,category:'ai',phase:'failed',search:'host'}});
  expect(mocks.call.mock.calls.every(c=>c[0]==='activity_log')).toBe(true);w.unmount();
 });
 it('pages through stable cursors and refreshes an expired history',async()=>{
  mocks.call.mockResolvedValueOnce(page('new','10:500')).mockResolvedValueOnce({...page('old'),events:[],expired:true}).mockResolvedValue(page('fresh'));
  const w=mount(ActivityLog);await flushPromises();await w.findAll('button').find(b=>b.text()==='Older')!.trigger('click');await flushPromises();
  expect(mocks.call).toHaveBeenLastCalledWith('activity_log',{query:{before:'10:500',category:null,phase:null,search:null}});
  expect(w.text()).toContain('rotated');
  await w.findAll('button').find(b=>b.text()==='Refresh')!.trigger('click');await flushPromises();expect(w.text()).toContain('fresh');
  expect(w.findAll('button').find(b=>b.text()==='Newer')!.attributes('disabled')).toBeDefined();w.unmount();
 });
 it('shows journal gaps and errors while escaping event text',async()=>{
  mocks.call.mockRejectedValueOnce(new Error('No access to the journal')).mockResolvedValue({...page('<script>secret()</script>'),skipped:2,storage:{bytes:100,limitBytes:31457280,dropped:3,error:'Recording error'}});
  const w=mount(ActivityLog);await flushPromises();expect(w.get('[role="alert"]').text()).toContain('No access');
  await w.findAll('button').find(b=>b.text()==='Refresh')!.trigger('click');await flushPromises();
  expect(w.find('script').exists()).toBe(false);expect(w.text()).toContain('<script>');expect(w.text()).toContain('Events not recorded: 3');expect(w.text()).toContain('Corrupted entries skipped: 2');w.unmount();
 });
 it('ignores late replies and stops polling after unmount',async()=>{
  let finish!:(value:ActivityPage)=>void;mocks.call.mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));
  const w=mount(ActivityLog);vi.useFakeTimers();await w.get('[aria-label="Action category"]').setValue('ai');await vi.advanceTimersByTimeAsync(251);await flushPromises();
  expect(w.text()).toContain('SSH connection');finish(page('outdated'));await flushPromises();expect(w.text()).not.toContain('outdated');
  w.unmount();const count=mocks.call.mock.calls.length;await vi.advanceTimersByTimeAsync(30000);expect(mocks.call).toHaveBeenCalledTimes(count);
 });
});
