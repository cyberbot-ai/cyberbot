// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import LogPanel from './LogPanel.vue';
const mocks=vi.hoisted(()=>({call:vi.fn()}));vi.mock('../api',()=>({preview:false,call:mocks.call}));
const end=new Date(2026,10,6,14,6,8).getTime()/1000;
const view={fresh:true,shortCheck:true,lastIncomplete:null,lastSuccess:end,nextCheck:700,error:null,summary:{id:'s',at:end,remoteAt:end,windowSeconds:12,coverage:{complete:false,initial:false,sources:['auth'],gaps:[{reason:'source_unavailable',source:'syslog'}]},counts:{ssh_failed:1000,ssh_banned:10},examples:[],findings:[],learning:true,bytesReceived:800,bytesRead:100000,durationMs:20}};
beforeEach(()=>{vi.clearAllMocks();mocks.call.mockResolvedValue(view);});
it('reads cached coverage without remote collection or AI and explains SSH noise',async()=>{const w=mount(LogPanel,{props:{serverId:'s',now:100}});await flushPromises();expect(mocks.call).toHaveBeenCalledWith('log_summary',{id:'s'});expect(mocks.call.mock.calls).toHaveLength(1);expect(w.get('.meta .tag.ok').text()).toBe('No issues found');expect(w.text()).toContain('11/06/2026, 14:05:56–14:06:08');expect(w.text()).toContain('do not trigger incidents');expect(w.text()).toContain('Log source unavailable');w.unmount();});
it('reloads the saved logs after the server poll and shows a collection failure', async () => {
  const w = mount(LogPanel, { props: { serverId: 's', now: 100, refreshKey: 'before' } });
  await flushPromises();
  expect(w.find('.tab-actions button').exists()).toBe(false);
  mocks.call.mockResolvedValue({ ...view, error: 'SSH unavailable. Position retained.', fresh: false });
  await w.setProps({ refreshKey: 'after' });
  await flushPromises();
  expect(w.get('[role="alert"]').text()).toContain('SSH unavailable');
  expect(mocks.call.mock.calls).toEqual([['log_summary', { id: 's' }], ['log_summary', { id: 's' }]]);
  w.unmount();
});
it('explains a Fail2ban finding and gives a read-only diagnostic step', async () => {
 mocks.call.mockResolvedValue({...view, summary:{...view.summary,
  counts:{protection_failure:1},
  findings:[{check:'logs:protection_failure',title:'SSH protection error',severity:'warning',count:1}],
  examples:[{at:end,category:'protection_failure',template:'Fail2ban log source missing'}],
 }});
 const w=mount(LogPanel,{props:{serverId:'s',now:end}});
 await flushPromises();
 expect(w.get('.finding').text()).toContain('Fail2ban error');
 expect(w.text()).toContain('No log example was saved for this finding.');
 expect(w.text()).toContain('could not find its log');
 expect(w.text()).toContain('fail2ban-client status');
 expect(w.text()).toContain('journalctl -u fail2ban');
 w.unmount();
});

it('shows the matching log excerpt under each finding as plain text', async () => {
 const recurring = 'logs:new_error_pattern';
 const disk = 'logs:disk_io';
 const line = `<b>Error</b> ${'worker-failed-'.repeat(16)}`;
 mocks.call.mockResolvedValue({
  ...view,
  findingExamples: {
   [disk]: {at:end-1,source:'syslog',text:'I/O error on disk'},
   [recurring]: {at:end,source:'journal',text:line},
  },
  summary: {...view.summary, findings: [
   {check:recurring,title:'A new recurring error pattern',severity:'warning',count:231},
   {check:disk,title:'Disk or file system errors',severity:'critical',count:1},
  ]},
 });
 const w = mount(LogPanel,{props:{serverId:'s',now:end}});
 await flushPromises();
 const [first, second] = w.findAll('.finding-item');
 expect(first.get('.finding').text()).toContain('231 events');
 expect(first.get('.example-meta').text()).toContain('journal');
 expect(first.get('time').attributes('datetime')).toBe(new Date(end*1000).toISOString());
 expect(first.get('code').text()).toBe(line);
 expect(first.find('code b').exists()).toBe(false);
 expect(second.get('.example-meta').text()).toContain('syslog');
 expect(second.get('code').text()).toBe('I/O error on disk');
 w.unmount();
});

it('shows an SSH matching limit separately from successful reading', async () => {
 mocks.call.mockResolvedValue({
   ...view,
   summary: { ...view.summary, sshCorrelationLimited: true, coverage: { ...view.summary.coverage, complete: true, gaps: [] } },
 });
 const w = mount(LogPanel, { props: { serverId: 's', now: end } });
 await flushPromises();
 expect(w.get('.meta .tag.ok').text()).toBe('No issues found');
 expect(w.text()).toContain('Some failed attempts could not be correlated with successful logins');
 expect(w.text()).not.toContain('There are passes');
 expect(w.find('.tab-actions button').exists()).toBe(false);
 w.unmount();
});

it('shows the previous gap after a repeat within the same second',async()=>{
 const {remoteAt,windowSeconds,coverage} = view.summary;
 mocks.call.mockResolvedValue({...view,lastIncomplete:{remoteAt,windowSeconds:600,gaps:coverage.gaps},summary:{...view.summary,windowSeconds:0,coverage:{...coverage,complete:true,gaps:[]}}});
 const w=mount(LogPanel,{props:{serverId:'s',now:end}});await flushPromises();
 expect(w.get('.meta .tag.ok').text()).toBe('No issues found');
 expect(w.get('details').text()).toContain('Both checks ran in the same second');
 expect(w.text()).toContain('Previous gaps · 11/06/2026, 13:56:08–14:06:08');
 expect(w.text()).toContain('Log source unavailable');
 w.unmount();
});

it('does not report a clean result without accessible journals or with an open finding', async () => {
 const unavailable = { ...view, summary: { ...view.summary, coverage: { ...view.summary.coverage, sources: [] } } };
 mocks.call.mockResolvedValue(unavailable);
 const w = mount(LogPanel, { props: { serverId: 's', now: end } });
 await flushPromises();
 expect(w.get('.meta .tag').text()).toBe('No log sources available');
 mocks.call.mockResolvedValue({ ...view, severity: 'critical' });
 await w.setProps({ now: end + 1 });
 await flushPromises();
 expect(w.get('.meta .tag.crit').text()).toBe('Findings detected');
 expect(w.text()).toContain('Awaiting confirmation of recovery');
 w.unmount();
});
