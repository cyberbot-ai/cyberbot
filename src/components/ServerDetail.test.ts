// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {expect,it,vi} from 'vitest';
import ServerDetail from './ServerDetail.vue';
import { call } from '../api';
import type { Investigation, Observation, Server } from '../types';
vi.mock('../api',()=>({preview:true,call:vi.fn().mockResolvedValue([])}));
const server={id:'s',name:'db-01',sourceId:'source',endpoint:{host:'localhost',user:'ops',port:22,identityFile:null,jumpHost:null},observation:null,lastError:null,lastAttempt:null,nextCheck:0,failures:0};
const stateful={template:'<div class="module"><input aria-label="draft" /></div>'};
it('uses separate configured thresholds for CPU and disk pressure in the overview', () => {
 const observation: Observation = {
  at: 100, cpuPercent: 98, memoryPercent: 20, swapPercent: 0, load: 1, uptime: 1000,
  disks: [{ mount: '/', usedPercent: 98, inodePercent: null }], services: [], missing: [], bytesReceived: 100, durationMs: 10,
 };
 const monitoring = { enabled: true, intervalSeconds: 180, diagnosticEnabled: false, expectedPeers: 0, expectReplica: false,
  thresholds: { cpu: { warning: 99, critical: 100 }, disk: { warning: 95, critical: 99 } } };
 const w = mount(ServerDetail, { props: { server: { ...server, observation, monitoring }, now: 100, interval: 180 } });
 expect(w.get('.metrics > div:first-child').classes()).toEqual([]);
 expect(w.get('.disk .value').classes()).toContain('warning');
 expect(w.get('.status').classes()).toContain('warning');
 w.unmount();
});
it('plots CPU by timestamp, breaks missing and overdue samples, and refreshes after a background measurement', async () => {
 const sample = (at: number, cpuPercent: number | null): Observation => ({
  at, cpuPercent, memoryPercent: 20, swapPercent: 0, load: 1, uptime: 1000,
  disks: [], services: [], missing: [], bytesReceived: 100, durationMs: 10,
 });
 const history = [sample(100, 10), sample(200, null), sample(300, 20), sample(400, 0), sample(700, 30)];
 vi.mocked(call).mockImplementation(async command => command === 'history' ? [...history] as never : [] as never);
 const w = mount(ServerDetail, { props: { server: { ...server, observation: history[4] }, now: 700, interval: 90 } });
 try {
  await flushPromises();
  const path = () => w.get('.chart .chart-line').attributes('d');
  expect(path()).toBe('M0,90 L0,90 M200,80 L200,80 L300,100 M600,70 L600,70');
  history.push(sample(800, 40));
  await w.setProps({ server: { ...server, observation: history[5] }, now: 800 });
  await flushPromises();
  expect(path()).toContain('L600,60');
  expect(path()).not.toContain('L600,70');
 } finally {
  w.unmount();
  vi.mocked(call).mockResolvedValue([]);
 }
});
it('refreshes the service panel when one of several incidents is resolved',async()=>{
 const live={...server,services:[{kind:'cockroach',name:'CockroachDB',status:'warning',at:100,detected:true}]};
 const incident={id:'errors',episode:'errors-1',serverId:'s',check:'service:cockroach:errors',title:'SQL errors',severity:'warning',status:'open',openedAt:100,updatedAt:100,evidence:''};
 const other={...incident,id:'ranges',episode:'ranges-1',check:'service:cockroach:underreplicatedRanges'};
 const w=mount(ServerDetail,{props:{server:live,incidents:[incident,other],now:100,interval:180},
  global:{stubs:{ServiceInstances:{props:['refreshKey'],template:'<div :data-refresh-key="refreshKey"/>'}}}});
 await w.findAll('.detail-tabs button').find(b=>b.text()==='Services')!.trigger('click');await flushPromises();
 expect(w.get('[data-refresh-key]').attributes('data-refresh-key')).toContain('errors-1');
 await w.setProps({incidents:[{...incident,status:'resolved',resolvedByUserAt:101},other]});
 const key=w.get('[data-refresh-key]').attributes('data-refresh-key');
 expect(key).toContain('ranges-1');
 expect(key).not.toContain('errors-1');
 w.unmount();
});
it('keeps the server healthy during a partial CVE check and turns red for a finding', async () => {
 const observation: Observation = {at:100,cpuPercent:0,memoryPercent:10,swapPercent:0,load:0.02,uptime:100,disks:[{mount:'/',usedPercent:7,inodePercent:1}],services:[],missing:[],bytesReceived:600,durationMs:10};
 const live: Server = {...server,observation,vulnerabilities:{status:'unknown',affected:0,critical:0,at:100}};
 const w = mount(ServerDetail,{props:{server:live,now:100,interval:180}});
 await flushPromises();
 expect(w.get('.state').text()).toBe('Healthy');
 expect(w.find('.coverage-note').exists()).toBe(false);
 expect(w.get('.metrics').text()).toContain('0%');
 await w.setProps({server:{...live,vulnerabilities:{...live.vulnerabilities!,status:'warning',affected:1}}});
 expect(w.get('.state').text()).toBe('Critical');
 expect(w.get('.count').classes()).toContain('critical');
 expect(w.get('.count').text()).toBe('1');
 w.unmount();
});
it('keeps very large load compact in the server overview with the exact value available',async()=>{
 const observation={at:100,cpuPercent:1,memoryPercent:2,swapPercent:0,load:12884901888.5,uptime:100,disks:[],services:[],missing:[],bytesReceived:100,durationMs:10};
 const w=mount(ServerDetail,{props:{server:{...server,observation},now:100,interval:180}});await flushPromises();
 expect(w.get('.metrics>div:last-child .metric-value').text()).toBe('12.88B');
 expect(w.get('.metrics>div:last-child .metric-value').attributes('title')).toBe('12884901888.5');w.unmount();
});
it('shows a host added without a user as its name and SSH address',async()=>{
 const w=mount(ServerDetail,{props:{server:{...server,name:'10.20.1.10',endpoint:{...server.endpoint,host:'10.20.1.10',user:''}},now:100,interval:180}});await flushPromises();
 expect(w.get('.server-title h2').text()).toBe('10.20.1.10');
 expect(w.get('.server-title p').text()).toBe('10.20.1.10:22');
 w.unmount();
});
it('opens only the requested diagnostic module and preserves drafts between tabs',async()=>{
 const w=mount(ServerDetail,{props:{server,now:100,interval:180},global:{stubs:{PostgresqlPanel:stateful,NginxPanel:stateful,CheckPanel:stateful,LogPanel:stateful,VulnerabilityPanel:stateful,InvestigationPanel:stateful}}});await flushPromises();
 expect(w.find('.module').exists()).toBe(false);
 const tab=async(name:string)=>{await w.findAll('nav button').find(b=>b.text()===name)!.trigger('click');await flushPromises();};
 await tab('Checks');await w.get('input').setValue('unsaved');await tab('Logs');expect(w.get('input').element.value).toBe('');await tab('Checks');expect(w.get('input').element.value).toBe('unsaved');
 await w.get('[aria-label="Close server"]').trigger('click');expect(w.emitted('close')).toHaveLength(1);w.unmount();
});
it('shows unsupported distro capabilities without implying vulnerability coverage',async()=>{
 const observation={at:100,cpuPercent:1,memoryPercent:2,swapPercent:0,load:0,uptime:100,disks:[],services:[],missing:['services_adapter_unsupported'],bytesReceived:600,durationMs:200,platform:{version:1,distro:'alpine',release:'unknown',versionId:'3.21',idLike:[],family:'alpine',architecture:'aarch64',kernel:'6.1',procfs:true,initSystem:'openrc',serviceAdapter:'unsupported',journalAvailable:false,packageManager:'apk',packageAdapter:'unsupported',advisoryProvider:'unsupported'}};
 const w=mount(ServerDetail,{props:{server:{...server,observation},now:100,interval:180}});await flushPromises();expect(w.text()).toContain('alpine 3.21');expect(w.text()).toContain('the adapter is not yet supported');expect(w.text()).toContain('Package vulnerability checks are unavailable');w.unmount();
});
it('marks tabs and metrics that need attention without adding an overview problem list',async()=>{
 const observation={at:100,cpuPercent:1,memoryPercent:2,swapPercent:0,load:0,uptime:100,disks:[{mount:'/data',usedPercent:98,inodePercent:3}],services:[],missing:[],bytesReceived:100,durationMs:10};
 const w=mount(ServerDetail,{props:{server:{...server,observation,logStatus:'warning',vulnerabilities:{status:'critical',affected:2,critical:2,at:100}},now:100,interval:180},global:{stubs:{LogPanel:stateful,VulnerabilityPanel:stateful}}});await flushPromises();
 const tab=(name:string)=>w.findAll('nav button').find(b=>b.text().startsWith(name))!;
 expect(tab('Vulnerabilities').get('.count').text()).toBe('2');expect(tab('Logs').find('.mark.warning').exists()).toBe(true);expect(tab('Checks').find('.mark').exists()).toBe(false);
 expect(w.get('.disk .value').classes()).toContain('critical');
 expect(w.find('.problems').exists()).toBe(false);w.unmount();
});
it('opens the incidents tab on request, keeps resolved history and scopes it to the server',async()=>{
 const incident={id:'incident',episode:'episode',serverId:'s',check:'cpu',title:'CPU overload',severity:'warning',status:'open',openedAt:100,updatedAt:100,evidence:'95%'};
 const w=mount(ServerDetail,{props:{server,now:100,interval:180,initialSection:'incidents',initialShowResolved:true,incidents:[incident,{...incident,id:'resolved',status:'resolved',title:'Previously decided',resolvedByUserAt:101},{...incident,id:'foreign',serverId:'other',title:'Another server'}]}});await flushPromises();
 expect(w.get('.detail-tabs button.active').text()).toBe('Incidents');expect(w.find('.metrics').exists()).toBe(false);expect(w.findAll('.incident-row')).toHaveLength(2);expect(w.text()).toContain('Previously decided');expect(w.text()).not.toContain('Another server');
 await w.setProps({initialSection:'overview',initialShowResolved:false});
 expect(w.get('.detail-tabs button.active').text()).toBe('Overview');
 expect(w.find('.incident-row').exists()).toBe(false);
 await w.findAll('.detail-tabs button').find(button=>button.text()==='Incidents')!.trigger('click');
 expect(w.findAll('.incident-row')).toHaveLength(1);
 await w.get('.incident-history input').setValue(true);
 expect(w.findAll('.incident-row')).toHaveLength(2);w.unmount();
});
it('lists service ports in one row and opens the selected stable connection',async()=>{
 const w=mount(ServerDetail,{props:{server:{...server,services:[{kind:'redis',instanceId:'default',name:'Redis:6379',status:'healthy',at:100},{kind:'redis',instanceId:'second',name:'Redis:6380',status:'healthy',at:100}]},now:100,interval:180},global:{stubs:{ServiceInstances:{props:{kind:String,initialInstance:String,hideSelector:Boolean},template:'<div class="connection-panel"><slot name="before-content"/><span class="connection-id">{{kind}} {{initialInstance}} {{hideSelector}}</span></div>'}}}});await flushPromises();await w.findAll('nav button').find(b=>b.text()==='Services')!.trigger('click');await flushPromises();const tabs=w.findAll('.service-tabs button');expect(tabs.some(b=>b.text()==='Redis:6379')).toBe(true);await tabs.find(b=>b.text()==='Redis:6380')!.trigger('click');await flushPromises();expect(w.get('.connection-id').text()).toBe('redis second true');expect(w.find('.connections').exists()).toBe(false);w.unmount();
});
it('mutes both unreported and explicitly undetected services, including the selected one', async () => {
 const w = mount(ServerDetail, {
  props: {
   server: {...server, services: [
    {kind:'nginx', name:'Nginx', status:'healthy', at:100},
    {kind:'redis', name:'Redis', status:'not_detected', at:100},
    {kind:'mysql', name:'MySQL', status:'unknown', at:100},
   ]},
   now: 100, interval: 180,
  },
  global: {stubs: {ServiceInstances: {template:'<div><slot name="before-content"/></div>'}}},
 });
 await w.findAll('nav button').find(button => button.text() === 'Services')!.trigger('click');
 await w.get('.service-tabs .more').trigger('click');
 const tab = (name: string) => w.findAll('.service-tabs button').find(button => button.text() === name)!;

 expect(tab('Nginx').classes()).not.toContain('undetected');
 expect(tab('MySQL').classes()).not.toContain('undetected');
 expect(tab('Asterisk').classes()).toContain('undetected');
 expect(tab('Redis').classes()).toContain('undetected');
 await tab('Asterisk').trigger('click');
 expect(tab('Asterisk').classes()).toEqual(expect.arrayContaining(['active', 'undetected']));
 w.unmount();
});
it('switches to the AI tab and hands over a question asked on the vulnerabilities tab',async()=>{
 const vuln={emits:['ask'],template:`<button class="ask" @click="$emit('ask','Whether CVE-2025-1 is dangerous?')">ask</button>`};
 const ai={props:['ask','aiAgent'],template:'<div class="ai">{{ask?.id}}:{{ask?.text}}</div>'};
 const w=mount(ServerDetail,{props:{server,now:100,interval:180,aiAgent:'codex'},global:{stubs:{VulnerabilityPanel:vuln,InvestigationPanel:ai}}});await flushPromises();
 await w.findAll('nav button').find(b=>b.text().startsWith('Vulnerabilities'))!.trigger('click');await flushPromises();
 await w.get('.ask').trigger('click');await flushPromises();
 expect(w.get('nav button.active').text()).toBe('AI');expect(w.get('.ai').text()).toBe('1:Whether CVE-2025-1 is dangerous?');w.unmount();
});

it('scrolls the AI conversation to the end after loading and after returning to the tab', async () => {
 const history: Investigation[] = [{
  id: 'run', agent: 'codex', serverIds: [server.id], question: 'Check the CPU',
  status: 'completed', startedAt: 10, endedAt: 20, text: 'AI response',
  error: null, usage: null, audit: [], sessionId: null,
 }];
 const scrollHeight = vi.spyOn(Element.prototype, 'scrollHeight', 'get').mockImplementation(function (this: Element) {
  return this.isConnected && this.matches('.messages') && this.querySelector('.exchange') ? 1200 : 0;
 });
 try {
  await vi.mocked(call).withImplementation(async command => {
   if (command === 'detect_agents') return [{ name: 'codex', ready: true }];
   if (command === 'investigations') return history;
   return [];
  }, async () => {
   const w = mount(ServerDetail, { attachTo: document.body, props: { server, now: 100, interval: 180 } });
   try {
    const openTab = async (name: string) => {
     await w.findAll('.detail-tabs button').find(button => button.text() === name)!.trigger('click');
     await flushPromises();
    };
    await openTab('AI');
    const messages = w.get('.messages');
    expect(messages.text()).toContain('AI response');
    expect(messages.element.scrollTop).toBe(1200);

    messages.element.scrollTop = 100;
    await messages.trigger('scroll');
    await openTab('Overview');
    await openTab('AI');
    expect(w.get('.messages').element).toBe(messages.element);
    expect(messages.element.scrollTop).toBe(1200);
   } finally {
    w.unmount();
   }
  });
 } finally {
  scrollHeight.mockRestore();
 }
});

it('places refresh above overview and incident content and leaves chat entry in its tab', async () => {
 const w = mount(ServerDetail, { props: { server, now: 100, interval: 180 } });
 await flushPromises();
 expect(w.get('.detail-content').element.firstElementChild?.classList.contains('tab-bar')).toBe(true);
 expect(w.get('.tab-bar .tab-actions button').text()).toBe('Refresh');
 expect(w.text()).not.toContain('New dialogue');
 await w.findAll('.detail-tabs button').find(button => button.text() === 'Incidents')!.trigger('click');
 expect(w.get('.server-incidents').element.firstElementChild?.classList.contains('tab-bar')).toBe(true);
 expect(w.get('.tab-bar .tab-actions button').text()).toBe('Refresh');
 w.unmount();
});
