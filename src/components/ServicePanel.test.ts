// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import ServicePanel from './ServicePanel.vue';
import catalog from '../../collectors/connectors/catalog.json';
import {call} from '../api';
vi.mock('../api',()=>({call:vi.fn(),preview:false}));
const config={enabled:true,endpoint:'127.0.0.1',port:6379,user:'',intervalSeconds:180,expectedPeers:0,expectReplica:false};
const base={kind:'redis',config,summary:{id:'a',at:100,bytesReceived:100,data:{complete:false,issues:['partial_coverage'],metrics:{connections:4,blocked:null},durationMs:2},rates:{},findings:[]},evidence:[],fresh:true,error:null,status:'unknown'};
beforeEach(()=>{vi.clearAllMocks();vi.mocked(call).mockImplementation(async command=>command==='service_catalog'?catalog:structuredClone(base));});
it('keeps large service counters and byte metrics compact with original units available',async()=>{
 const huge=12884901888.5;
 vi.mocked(call).mockImplementation(async command=>command==='service_catalog'?catalog:{...structuredClone(base),summary:{...structuredClone(base.summary),data:{...base.summary.data,metrics:{connections:huge,memory:1048576,blocked:0}},rates:{}}});
 const w=mount(ServicePanel,{props:{serverId:'host',kind:'redis',now:100}});await flushPromises();
 expect(w.findAll('.metrics dd').some(d=>d.text()==='13B')).toBe(true);
 expect(w.findAll('.metric-value').find(v=>v.attributes('title')==='1048576 bytes')?.text()).toBe('1 MiB');
 expect(w.findAll('.metric-value').find(v=>v.attributes('title')===String(huge))).toBeDefined();
 w.unmount();
});
it('shows partial service coverage and only reads cached data',async()=>{const w=mount(ServicePanel,{props:{serverId:'host',kind:'redis',now:100}});await flushPromises();expect(w.text()).toContain('Incomplete coverage');expect(w.text()).toContain('Status unconfirmed');expect(w.text()).toContain('—');expect(call).toHaveBeenCalledWith('service_summary',{id:'host',kind:'redis'});expect(call).not.toHaveBeenCalledWith('refresh_service',expect.anything());w.unmount();});
it('refresh and configure always scope both server and service',async()=>{const w=mount(ServicePanel,{props:{serverId:'host',kind:'redis',now:100}});await flushPromises();await w.get('header button').trigger('click');await flushPromises();expect(call).toHaveBeenCalledWith('refresh_service',{id:'host',kind:'redis'});await w.get('form').trigger('submit');await flushPromises();expect(call).toHaveBeenCalledWith('configure_service',{id:'host',kind:'redis',config});expect(w.find('input[type=password]').exists()).toBe(false);w.unmount();});
it('a server with several services retains independent panels and profiles',async()=>{const a=mount(ServicePanel,{props:{serverId:'host',kind:'redis',now:100}});const b=mount(ServicePanel,{props:{serverId:'host',kind:'mysql',now:100}});await flushPromises();await a.get('header button').trigger('click');await flushPromises();expect(call).toHaveBeenCalledWith('service_summary',{id:'host',kind:'mysql'});expect(call).not.toHaveBeenCalledWith('refresh_service',{id:'host',kind:'mysql'});a.unmount();b.unmount();});
it('lets an automatic Redis profile switch to an explicit local IP and port', async () => {
 vi.mocked(call).mockImplementation(async command => command==='service_catalog' ? catalog : {...structuredClone(base), config:{...config, autoEndpoint:true}});
 const w = mount(ServicePanel, {props:{serverId:'host',kind:'redis',now:100}});
 await flushPromises();
 expect(w.find('input[list]').exists()).toBe(false);
 await w.findAll('form input[type=checkbox]')[1].setValue(false);
 await w.get('input[list]').setValue('10.23.7.1');
 await w.findAll('form input[type=number]')[0].setValue(16379);
 await w.get('form').trigger('submit');
 await flushPromises();
 expect(call).toHaveBeenCalledWith('configure_service', {id:'host',kind:'redis',config:{...config, autoEndpoint:false, endpoint:'10.23.7.1', port:16379}});
 w.unmount();
});

it('hides an unavailable counter rate and shows a computed zero',async()=>{
 let rates:Record<string,number|null>={queries:null};
 vi.mocked(call).mockImplementation(async command=>command==='service_catalog'?catalog:{
  ...base,summary:{...base.summary,rates,data:{...base.summary.data,metrics:{queries:203412580,errors:59813473}}},
 });
 const w=mount(ServicePanel,{props:{serverId:'host',kind:'cockroach',now:100}});
 await flushPromises();
 expect(w.findAll('.metrics small')).toHaveLength(0);
 rates={queries:null,errors:0};
 await w.setProps({now:101});await flushPromises();
 expect(w.get('.metrics small').text()).toBe('0 per 10 min');
 w.unmount();
});

it('shows the reason at first breach and removes it after resolution without a new sample',async()=>{
 const finding={key:'service:cockroach:errors',title:'CockroachDB: SQL errors',value:1214.93,severity:'warning'};
 let deviations=[{...finding,threshold:20,at:100,pending:true,recovering:false}];
 let findings:typeof finding[]=[];
 vi.mocked(call).mockImplementation(async command=>command==='service_catalog'?catalog:{
  ...base,status:deviations.length?'warning':'healthy',deviations,summary:{...base.summary,findings,rates:{errors:1214.93}},
 });
 const w=mount(ServicePanel,{props:{serverId:'host',kind:'cockroach',now:100}});
 await flushPromises();
 expect(w.get('.deviation').text()).toContain('SQL errors');
 expect(w.get('.deviation').text()).toContain('threshold 20 per 10 min');
 expect(w.get('.deviation').text()).toContain('Waiting for confirmation');
 deviations=[{...deviations[0],pending:false}];
 findings=[finding];
 await w.setProps({refreshKey:'confirmed'});await flushPromises();
 expect(w.findAll('.deviation')).toHaveLength(1);
 expect(w.get('.deviation').text()).not.toContain('Waiting for confirmation');
 deviations=[];
 await w.setProps({refreshKey:'resolved'});await flushPromises();
 expect(w.find('.deviation').exists()).toBe(false);
 expect(w.get('.tag').text()).toBe('No issues found');
 w.unmount();
});

it('shows Fail2ban availability when the background check updates the cached summary', async () => {
 let availability = 'unknown';
 vi.mocked(call).mockImplementation(async command => command === 'service_catalog' ? catalog : {
  ...base, kind:'fail2ban', availability, config:{...config, endpoint:'local', port:1},
  summary:availability === 'unknown' ? null : {
   ...base.summary, data:{...base.summary.data, connected:false, metrics:{jails:null, currentlyBanned:null, totalBanned:null}},
  },
 });
 const w = mount(ServicePanel, {props:{serverId:'host',kind:'fail2ban',now:100}});
 await flushPromises();
 expect(w.get('.tag').text()).toBe('Status unknown');
 availability = 'stopped';
 await w.setProps({refreshKey:'stopped'});
 await flushPromises();
 expect(w.get('.tag').text()).toBe('Stopped');
 expect(w.text()).toContain('Incomplete coverage');
 availability = 'running';
 await w.setProps({refreshKey:'running'});
 await flushPromises();
 expect(w.get('.tag').text()).toBe('Running');
 expect(call).not.toHaveBeenCalledWith('refresh_service',expect.anything());
 w.unmount();
});
