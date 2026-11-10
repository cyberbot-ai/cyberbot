// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import NginxPanel from './service-panels/NginxPanel.vue';
import {call} from '../api';
vi.mock('../api',()=>({call:vi.fn(),preview:false}));
const empty={summary:null,fresh:false,error:null,nextCheck:0,card:{detected:false,status:'unknown',rps:null}};
beforeEach(()=>{vi.clearAllMocks();vi.mocked(call).mockResolvedValue(empty);});
it('reads saved summary without starting SSH or AI',async()=>{const w=mount(NginxPanel,{props:{serverId:'s',now:100}});await flushPromises();expect(call).toHaveBeenCalledExactlyOnceWith('service_summary',{id:'s',kind:'nginx'});expect(w.text()).toContain('after the next scheduled check');w.unmount();});
it('shows a saved failure and reloads when the server poll finishes', async () => {
  const w = mount(NginxPanel, { props: { serverId: 's', now: 100, refreshKey: 'before' } });
  await flushPromises();
  expect(w.find('header button').exists()).toBe(false);
  vi.mocked(call).mockResolvedValue({ ...empty, error: 'No access' });
  await w.setProps({ refreshKey: 'after' });
  await flushPromises();
  expect(w.get('[role="alert"]').text()).toBe('No access');
  expect(vi.mocked(call).mock.calls).toEqual([
    ['service_summary', { id: 's', kind: 'nginx' }],
    ['service_summary', { id: 's', kind: 'nginx' }],
  ]);
  w.unmount();
});
it('renders unknown latency instead of zero and marks partial scope',async()=>{const timing={samples:0,sumMs:0,maxMs:0,slow:0,histogram:Array(14).fill(0)};vi.mocked(call).mockResolvedValue({...empty,card:{...empty.card,detected:true,status:'healthy'},fresh:true,summary:{detected:true,at:100,receivedAt:100,service:'active',windowSeconds:95,coverage:{complete:false,initial:false,gaps:[{source:'config',reason:'multiple_logs'}]},rps:null,rpsSource:'access_log',counts:{'4xx':1000,requests:1000},requestTime:timing,upstreamTime:timing,missing:['request_time'],examples:[],findings:[],bytesReceived:600,bytesRead:10000,durationMs:5}});const w=mount(NginxPanel,{props:{serverId:'s',now:100}});await flushPromises();expect(w.get('.meta .tag.ok').text()).toBe('No issues found');expect(w.text()).toContain('Requests for 1 min 35 s');expect(w.get('.metrics>div:nth-child(3)').text()).toContain('Request time');expect(w.get('.metrics>div:nth-child(3) strong').text()).toBe('no data');expect(w.text()).toContain('Multiple logs found');w.unmount();});
