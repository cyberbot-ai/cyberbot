// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import CheckPanel from './CheckPanel.vue';
import {call} from '../api';
vi.mock('../api',()=>({call:vi.fn(),preview:false}));
vi.mock('@tauri-apps/api/event',()=>({listen:vi.fn().mockResolvedValue(()=>{})}));
const spec={format:1,name:'Memory',description:'Memory check',intervalSeconds:180,badWindows:2,inputs:['memory_percent'],severity:'warning',condition:{op:'gt'},tests:[]};
const version={id:'version-one',spec,author:'codex',at:100,error:null,report:null};
const view={definitions:[{id:'check',name:'Memory',versions:[version],binding:null,events:[]}],fields:['memory_percent'],example:spec};
const result={token:'review-token',versionId:version.id,serverId:'s',input:{missing:[],values:{memory_percent:95}},response:{status:'warning',report:{passed:true,cases:[{name:'high',expected:'warning',actual:'warning',passed:true}]}},before:null,after:spec};
beforeEach(()=>{vi.clearAllMocks();vi.mocked(call).mockImplementation(async(cmd)=>{if(cmd==='preview_check_version')return result;if(cmd==='test_check_version')return {report:result.response.report};return structuredClone(view);});});
async function selected(){const w=mount(CheckPanel,{props:{serverId:'s',now:100}});await flushPromises();await w.findAll('.list button').find(b=>b.text()==='Memory')!.trigger('click');await flushPromises();return w;}
it('requires preview and explicit review before activation',async()=>{const w=await selected();expect(call).not.toHaveBeenCalledWith('create_check_with_agent',expect.anything());await w.findAll('button').find(b=>b.text()==='Trial launch and viewing')!.trigger('click');await flushPromises();const enable=w.findAll('button').find(b=>b.text()==='Insert the viewed version')!;expect(enable.attributes('disabled')).toBeDefined();await w.get('input[type="checkbox"]').setValue(true);await enable.trigger('click');await flushPromises();expect(call).toHaveBeenCalledWith('activate_check',{serverId:'s',versionId:'version-one',token:'review-token'});w.unmount();});
it('editing invalidates review and cannot activate unsaved changes',async()=>{const w=await selected();await w.findAll('button').find(b=>b.text()==='Trial launch and viewing')!.trigger('click');await flushPromises();await w.findAll('textarea').at(-1)!.setValue(JSON.stringify({...spec,name:'Changed'}));expect(w.text()).not.toContain('Insert the viewed version');expect(w.text()).toContain('Save the changes first');w.unmount();});
it('failed tests do not allow activation and switching servers clears review',async()=>{vi.mocked(call).mockImplementation(async(cmd)=>cmd==='preview_check_version'?{...result,response:{...result.response,report:{passed:false,cases:[]}}}:structuredClone(view));const w=await selected();await w.findAll('button').find(b=>b.text()==='Trial launch and viewing')!.trigger('click');await flushPromises();await w.get('input[type="checkbox"]').setValue(true);expect(w.findAll('button').find(b=>b.text()==='Insert the viewed version')!.attributes('disabled')).toBeDefined();await w.setProps({serverId:'other'});await flushPromises();expect(w.text()).not.toContain('Insert the viewed version');w.unmount();});

it('generates a check using the global agent without a provider argument',async()=>{
 const w=await selected();expect(w.find('option[value="codex"],option[value="claude"]').exists()).toBe(false);
 await w.findAll('button').find(b=>b.text().startsWith('Create a draft and tests'))!.trigger('click');await flushPromises();
 const request=vi.mocked(call).mock.calls.find(c=>c[0]==='create_check_with_agent');expect(request?.[1]).toMatchObject({serverId:'s',checkId:'check'});expect(request?.[1]).not.toHaveProperty('agent');w.unmount();
});
