// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,afterEach,expect,it,vi} from 'vitest';
import ModelProfiles from './ModelProfiles.vue';
const call=vi.hoisted(()=>vi.fn());vi.mock('../api',()=>({preview:false,call}));
const factory=()=>({revision:1,providers:{codex:{low:{model:'gpt-6-luna',effort:'high'},medium:{model:'gpt-6.1-terra',effort:'high'},high:{model:'gpt-6.1-sol',effort:'high'}},claude:{low:{model:'haiku',effort:'high'},medium:{model:'sonnet',effort:'high'},high:{model:'opus',effort:'high'}}}});
beforeEach(()=>{vi.useFakeTimers();call.mockReset();call.mockImplementation(async(command,args)=>command==='ai_profiles'?factory():command==='configure_ai_profiles'?{...args.config,revision:args.config.revision+1}:[]);});afterEach(()=>vi.useRealTimers());
it('loads profiles without models and autosaves provider changes',async()=>{const w=mount(ModelProfiles);await flushPromises();expect(call).toHaveBeenCalledTimes(1);await w.get('[aria-label="claude low model"]').setValue('claude-haiku-5-5');await vi.advanceTimersByTimeAsync(400);expect(call.mock.calls.find(c=>c[0]==='configure_ai_profiles')?.[1].config.providers.codex).toEqual(factory().providers.codex);expect(w.text()).toContain('automatically');w.unmount();});
it('shows catalog errors without falling back or changing profiles',async()=>{const w=mount(ModelProfiles);await flushPromises();call.mockRejectedValueOnce(new Error('Authorization has expired'));await w.findAll('button')[1].trigger('click');await flushPromises();expect(w.get('[role=alert]').text()).toContain('Authorization has expired');expect(w.get<HTMLInputElement>('[aria-label="claude low model"]').element.value).toBe('haiku');w.unmount();});
