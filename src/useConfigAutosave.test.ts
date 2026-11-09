// @vitest-environment happy-dom
import {defineComponent,ref} from 'vue';
import {mount,flushPromises} from '@vue/test-utils';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {useConfigAutosave} from './useConfigAutosave';
const mocks=vi.hoisted(()=>({call:vi.fn()}));vi.mock('./api',()=>({preview:false,call:mocks.call}));
const Harness=defineComponent({props:{server:{type:String,default:'one'}},setup(props){const config=ref({port:6000}),dirty=ref(false),error=ref('');const auto=useConfigAutosave({command:'configure_service',scope:()=>({id:props.server,kind:'redis'}),value:()=>config.value,dirty,error,saved:vi.fn()});return {config,dirty,error,auto};},template:'<form @input="auto.edited"><input v-model.number="config.port" type="number" min="1" max="65535"><p>{{error}}</p></form>'});
beforeEach(()=>{vi.clearAllMocks();vi.useFakeTimers();mocks.call.mockResolvedValue(undefined);});afterEach(()=>vi.useRealTimers());
it('coalesces edits, validates the form and saves without a button',async()=>{
 const w=mount(Harness);await w.get('input').setValue('6001');await w.get('input').setValue('6002');await vi.advanceTimersByTimeAsync(351);await flushPromises();expect(mocks.call).toHaveBeenCalledExactlyOnceWith('configure_service',{id:'one',kind:'redis',config:{port:6002}});
 await w.get('input').setValue('999999');await vi.advanceTimersByTimeAsync(351);expect(mocks.call).toHaveBeenCalledTimes(1);expect(w.text()).toContain('Check the format and range of values.');w.unmount();
});
it('keeps queued snapshots attached to their original server and flushes on closing',async()=>{
 const w=mount(Harness);await w.get('input').setValue('6001');await w.setProps({server:'two'});await w.get('input').setValue('6002');w.unmount();await flushPromises();expect(mocks.call.mock.calls).toEqual([['configure_service',{id:'one',kind:'redis',config:{port:6001}}],['configure_service',{id:'two',kind:'redis',config:{port:6002}}]]);
});
it('reports errors and does not overwrite a newer edit after a delayed save',async()=>{
 let finish:(v:unknown)=>void=()=>{};mocks.call.mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));const w=mount(Harness);await w.get('input').setValue('6001');await vi.advanceTimersByTimeAsync(351);await w.get('input').setValue('6002');mocks.call.mockRejectedValueOnce(new Error('No access'));finish(undefined);await flushPromises();expect(mocks.call.mock.calls[1][1]).toEqual({id:'one',kind:'redis',config:{port:6002}});expect(w.text()).toContain('No access');w.unmount();
});
