// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,afterEach,expect,it,vi} from 'vitest';
import AiAgentSettings from './AiAgentSettings.vue';
import type {Settings} from '../types';
const call=vi.hoisted(()=>vi.fn());
vi.mock('../api',()=>({preview:false,call}));
const settings:Settings={mode:'manual',autoAgent:'claude',dailyTokenLimit:null,dailyRunLimit:null,runTokenLimit:50000,pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false, dockBadgeEnabled: true};
beforeEach(()=>{vi.useFakeTimers();call.mockReset();call.mockImplementation(async(_cmd,args)=>({...settings,...args.patch}));});
afterEach(()=>vi.useRealTimers());
it('preserves the saved global choice without starting a model and autosaves only the agent',async()=>{
 const w=mount(AiAgentSettings,{props:{settings}});expect(w.get<HTMLSelectElement>('select').element.value).toBe('claude');expect(call).not.toHaveBeenCalled();
 await w.get('select').setValue('codex');await vi.advanceTimersByTimeAsync(250);await flushPromises();
 expect(call.mock.calls).toEqual([['update_settings',{patch:{autoAgent:'codex'}}]]);expect(w.emitted('saved')?.[0]?.[0]).toMatchObject({autoAgent:'codex',mode:'manual',pollSeconds:180});w.unmount();
});
it('receives a global change from another window without overwriting it',async()=>{
 const w=mount(AiAgentSettings,{props:{settings}});await w.setProps({settings:{...settings,autoAgent:'codex',paused:true}});expect(w.get<HTMLSelectElement>('select').element.value).toBe('codex');expect(call).not.toHaveBeenCalled();w.unmount();
});
it('shows a persistence failure without silently selecting a different agent',async()=>{
 call.mockRejectedValueOnce(new Error('Recording error'));const w=mount(AiAgentSettings,{props:{settings}});await w.get('select').setValue('codex');await vi.advanceTimersByTimeAsync(250);await flushPromises();expect(w.get('[role="alert"]').text()).toContain('Recording error');expect(w.emitted('saved')).toBeUndefined();w.unmount();
});
