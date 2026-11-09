// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {expect,it,vi} from 'vitest';
import ServerDetail from './ServerDetail.vue';
import type {Incident,Server} from '../types';
const mocks=vi.hoisted(()=>({call:vi.fn(async()=>[])}));vi.mock('../api',()=>({preview:false,call:mocks.call}));
it('shows resolution in the server card even before metrics are available and scopes its incident list',async()=>{
 const server:Server={id:'s',name:'web',sourceId:'src',endpoint:{host:'host',user:'root',port:22,identityFile:null,jumpHost:null},observation:null,lastError:null,lastAttempt:null,nextCheck:0,failures:0};
 const i:Incident={id:'i',episode:'ep',serverId:'s',check:'logs:oom',title:'OOM',severity:'critical',status:'open',openedAt:100,updatedAt:100,evidence:'Summary'};
 const w=mount(ServerDetail,{props:{server,now:100,interval:180,incidents:[i,{...i,id:'other',serverId:'other'}]}});await flushPromises();expect(w.findAll('.incident-row')).toHaveLength(1);await w.get('[aria-label="Marking it up: OOM"]').trigger('click');await flushPromises();expect(mocks.call).toHaveBeenCalledWith('resolve_incident',{id:'i',episode:'ep'});expect(w.emitted('updated')).toHaveLength(1);await w.setProps({incidents:[{...i,status:'resolved',resolvedByUserAt:101}]});expect(w.find('.incident-row').exists()).toBe(false);expect(w.text()).toContain('No open incidents.');w.unmount();
});

it('marks only open incidents of the selected server, including legacy episodes',async()=>{
 const server:Server={id:'s',name:'web',sourceId:'src',endpoint:{host:'host',user:'root',port:22,identityFile:null,jumpHost:null},observation:null,lastError:null,lastAttempt:null,nextCheck:0,failures:0};
 const incident:Incident={id:'i',serverId:'s',check:'logs:oom',title:'OOM',severity:'critical',status:'open',openedAt:100,updatedAt:100,evidence:'Summary'};
 const incidents=[incident,{...incident,id:'other',serverId:'other'},{...incident,id:'closed',status:'resolved'}];
 mocks.call.mockClear();
 const w=mount(ServerDetail,{props:{server,now:100,interval:180,initialShowResolved:true,incidents}});
 await flushPromises();
 const button=w.get('.resolve-all');
 expect(button.text()).toBe('Mark everything resolved');
 await button.trigger('click');
 await flushPromises();
 expect(mocks.call).toHaveBeenCalledWith('resolve_incidents',{episodes:[{id:'i',episode:'i:100'}]});
 expect(w.emitted('updated')).toHaveLength(1);
 await w.setProps({incidents:incidents.slice(1)});
 expect(w.find('.resolve-all').exists()).toBe(false);
 w.unmount();
});
