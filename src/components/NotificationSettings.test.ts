// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import NotificationSettings from './NotificationSettings.vue';
const mocks=vi.hoisted(()=>({call:vi.fn()}));
vi.mock('../api',()=>({preview:false,call:mocks.call}));
const state={enabled:true,permission:'authorized',error:null,queued:0,overflow:0};
beforeEach(()=>{vi.clearAllMocks();mocks.call.mockImplementation(async(c,a)=>c==='configure_notifications'?{...state,enabled:a.enabled}:state);});
it('loads OS permission and autosaves the switch without sending a notification',async()=>{const w=mount(NotificationSettings);await flushPromises();expect(w.text()).toContain('Allowed by macOS');await w.get('input').setValue(false);await flushPromises();expect(mocks.call).toHaveBeenCalledWith('configure_notifications',{enabled:false});expect(w.get('button').attributes('disabled')).toBeDefined();expect(mocks.call.mock.calls.some(c=>c[0]==='test_notification')).toBe(false);w.unmount();});
it('sends only the fixed test command on an explicit click and shows denial/failure',async()=>{mocks.call.mockResolvedValueOnce({...state,permission:'denied'});const w=mount(NotificationSettings);await flushPromises();expect(w.text()).toContain('Allow Cyberbot notifications in system settings');mocks.call.mockRejectedValueOnce(new Error('Notification permission is required'));await w.get('button').trigger('click');await flushPromises();expect(w.get('[role="alert"]').text()).toContain('Notification permission is required');expect(mocks.call).toHaveBeenCalledWith('test_notification');expect(mocks.call.mock.calls.every(c=>['notification_status','test_notification'].includes(c[0]))).toBe(true);w.unmount();});
