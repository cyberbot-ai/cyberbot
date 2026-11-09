// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import { serverDirectory, serverDirectoryKey } from '../serverDirectory';
import IncidentList from './IncidentList.vue';
import ResolveIncidentButton from './ResolveIncidentButton.vue';
import type {Incident} from '../types';
const mocks=vi.hoisted(()=>({call:vi.fn()}));vi.mock('../api',()=>({preview:false,call:mocks.call}));
const incident:Incident={id:'i',episode:'ep',serverId:'s',check:'cpu',title:'High CPU loading',severity:'warning',status:'open',openedAt:100,updatedAt:120,evidence:'95%'};
beforeEach(()=>{vi.clearAllMocks();mocks.call.mockResolvedValue(undefined);});
it('resolves only the displayed episode without opening the server or launching AI',async()=>{
 let finish:()=>void=()=>{};mocks.call.mockImplementationOnce(()=>new Promise<void>(r=>{finish=r;}));
 const directory=serverDirectory([{id:'s',name:'web-01',endpoint:{host:'web.example.net',user:'ops',port:22,jumpHost:null}}]);const open=vi.fn();
 const w=mount(IncidentList,{props:{incidents:[incident],showServer:true},global:{provide:{[serverDirectoryKey as symbol]:{current:()=>directory,open}}}});expect(w.text()).toContain('web.example.net');expect(w.find('button button').exists()).toBe(false);
 const button=w.get('[aria-label="Mark resolved: High CPU loading"]');await button.trigger('click');await button.trigger('click');expect(mocks.call).toHaveBeenCalledExactlyOnceWith('resolve_incident',{id:'i',episode:'ep'});expect(w.emitted('open')).toBeUndefined();expect(open).not.toHaveBeenCalled();expect(button.attributes('disabled')).toBeDefined();finish();await flushPromises();expect(w.emitted('updated')).toHaveLength(1);w.unmount();
});
it('reports a stale episode or storage failure and leaves the incident visible',async()=>{
 mocks.call.mockRejectedValueOnce(new Error('The episode changed'));const w=mount(IncidentList,{props:{incidents:[incident]}});await w.get('.resolve').trigger('click');await flushPromises();expect(w.emitted('error')).toEqual([['The episode changed']]);expect(w.emitted('updated')).toBeUndefined();expect(w.text()).toContain(incident.title);w.unmount();
});
it('labels manual closure separately and supports legacy episode tokens',async()=>{
 const w=mount(ResolveIncidentButton,{props:{incident:{...incident,episode:undefined}}});await w.get('button').trigger('click');await flushPromises();expect(mocks.call).toHaveBeenCalledWith('resolve_incident',{id:'i',episode:'i:100'});w.unmount();
 const list=mount(IncidentList,{props:{incidents:[{...incident,status:'resolved',resolvedByUserAt:130}],openable:false}});expect(list.text()).toContain('Manually resolved');expect(list.find('button').exists()).toBe(false);list.unmount();
});
