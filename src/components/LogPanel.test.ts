// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import LogPanel from './LogPanel.vue';
const mocks=vi.hoisted(()=>({call:vi.fn()}));vi.mock('../api',()=>({preview:false,call:mocks.call}));
const end=new Date(2026,10,6,14,6,8).getTime()/1000;
const view={fresh:true,shortCheck:true,lastIncomplete:null,lastSuccess:end,nextCheck:700,error:null,summary:{id:'s',at:end,remoteAt:end,windowSeconds:12,coverage:{complete:false,initial:false,sources:['auth'],gaps:[{reason:'source_unavailable',source:'syslog'}]},counts:{ssh_failed:1000,ssh_banned:10},examples:[],findings:[],learning:true,bytesReceived:800,bytesRead:100000,durationMs:20}};
beforeEach(()=>{vi.clearAllMocks();mocks.call.mockResolvedValue(view);});
it('reads cached coverage without remote collection or AI and explains SSH noise',async()=>{const w=mount(LogPanel,{props:{serverId:'s',now:100}});await flushPromises();expect(mocks.call).toHaveBeenCalledWith('log_summary',{id:'s'});expect(mocks.call.mock.calls).toHaveLength(1);expect(w.get('.meta .tag.ok').text()).toBe('No problem found');expect(w.text()).toContain('11/06/2026, 14:05:56–14:06:08');expect(w.text()).toContain('do not create incidents');expect(w.text()).toContain('Journal unavailable');w.unmount();});
it('refreshes explicitly through the shared collector',async()=>{const w=mount(LogPanel,{props:{serverId:'s',now:100}});await flushPromises();await w.get('button').trigger('click');await flushPromises();expect(mocks.call).toHaveBeenCalledWith('diagnose',{id:'s',kind:'logs'});expect(w.emitted('updated')).toHaveLength(1);w.unmount();});
it('shows missing coverage and failure without a retry',async()=>{mocks.call.mockImplementation(async c=>{if(c==='diagnose')throw new Error('SSH unavailable');return {...view,error:'Position retained',fresh:false};});const w=mount(LogPanel,{props:{serverId:'s',now:100}});await flushPromises();expect(w.text()).toContain('Verification error');await w.get('button').trigger('click');await flushPromises();expect(w.get('[role="alert"]').text()).toContain('SSH unavailable');expect(mocks.call.mock.calls.filter(c=>c[0]==='diagnose')).toHaveLength(1);w.unmount();});

it('explains a Fail2ban finding and gives a read-only diagnostic step', async () => {
 mocks.call.mockResolvedValue({...view, summary:{...view.summary,
  counts:{protection_failure:1},
  findings:[{check:'logs:protection_failure',title:'SSH protection error',severity:'warning',count:1}],
  examples:[{at:end,category:'protection_failure',template:'Fail2ban log source missing'}],
 }});
 const w=mount(LogPanel,{props:{serverId:'s',now:end}});
 await flushPromises();
 expect(w.get('.finding').text()).toContain('Fail2ban Error');
 expect(w.text()).toContain('could not find its log');
 expect(w.text()).toContain('fail2ban-client status');
 expect(w.text()).toContain('journalctl -u fail2ban');
 w.unmount();
});

it('shows an SSH matching limit separately from successful reading', async () => {
 mocks.call.mockResolvedValue({
   ...view,
   summary: { ...view.summary, sshCorrelationLimited: true, coverage: { ...view.summary.coverage, complete: true, gaps: [] } },
 });
 const w = mount(LogPanel, { props: { serverId: 's', now: end } });
 await flushPromises();
 expect(w.get('.meta .tag.ok').text()).toBe('No problem found');
 expect(w.text()).toContain('part of the history of attempts is not involved');
 expect(w.text()).not.toContain('There are passes');
 expect(w.get('.tab-actions button').text()).toBe('Refresh');
 w.unmount();
});

it('shows the previous gap after a repeat within the same second',async()=>{
 const {remoteAt,windowSeconds,coverage} = view.summary;
 mocks.call.mockResolvedValue({...view,lastIncomplete:{remoteAt,windowSeconds:600,gaps:coverage.gaps},summary:{...view.summary,windowSeconds:0,coverage:{...coverage,complete:true,gaps:[]}}});
 const w=mount(LogPanel,{props:{serverId:'s',now:end}});await flushPromises();
 expect(w.get('.meta .tag.ok').text()).toBe('No problem found');
 expect(w.get('details').text()).toContain('Repeat the same second');
 expect(w.text()).toContain('Previous gaps · 11/06/2026, 13:56:08–14:06:08');
 expect(w.text()).toContain('Journal unavailable');
 w.unmount();
});

it('does not report a clean result without accessible journals or with an open finding', async () => {
 const unavailable = { ...view, summary: { ...view.summary, coverage: { ...view.summary.coverage, sources: [] } } };
 mocks.call.mockResolvedValue(unavailable);
 const w = mount(LogPanel, { props: { serverId: 's', now: end } });
 await flushPromises();
 expect(w.get('.meta .tag').text()).toBe('Journals are not available');
 mocks.call.mockResolvedValue({ ...view, severity: 'critical' });
 await w.setProps({ now: end + 1 });
 await flushPromises();
 expect(w.get('.meta .tag.crit').text()).toBe('Findings detected');
 expect(w.text()).toContain('Recovery confirmation expected');
 w.unmount();
});
