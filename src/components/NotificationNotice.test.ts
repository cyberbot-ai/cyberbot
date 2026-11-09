// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import NotificationNotice from './NotificationNotice.vue';
const mocks=vi.hoisted(()=>({call:vi.fn()}));
vi.mock('../api',()=>({preview:false,call:mocks.call}));
const state={enabled:true,permission:'notDetermined',error:null,queued:0,overflow:0};
beforeEach(()=>{vi.clearAllMocks();mocks.call.mockResolvedValue({...state});});
it('explains missing access at startup and only asks the OS after a click',async()=>{const w=mount(NotificationNotice);await flushPromises();expect(w.text()).toContain('Allow notices');expect(mocks.call.mock.calls.map(c=>c[0])).toEqual(['notification_status']);mocks.call.mockResolvedValueOnce({...state,permission:'authorized'});await w.get('button').trigger('click');await flushPromises();expect(mocks.call).toHaveBeenCalledWith('request_notification_permission');expect(w.find('aside').exists()).toBe(false);w.unmount();});
it('opens only the fixed OS settings command after denial, then refreshes on focus',async()=>{mocks.call.mockResolvedValue({...state,permission:'denied'});const w=mount(NotificationNotice);await flushPromises();expect(w.text()).toContain('System settings');await w.get('button').trigger('click');await flushPromises();expect(mocks.call).toHaveBeenCalledWith('open_notification_settings');expect(mocks.call.mock.calls.some(c=>c[0]==='request_notification_permission')).toBe(false);mocks.call.mockResolvedValue({...state,permission:'authorized'});window.dispatchEvent(new Event('focus'));await flushPromises();expect(w.find('aside').exists()).toBe(false);w.unmount();});
it('does not nag when notifications are disabled and does not poll after unmount',async()=>{mocks.call.mockResolvedValue({...state,enabled:false});const w=mount(NotificationNotice);await flushPromises();expect(w.find('aside').exists()).toBe(false);w.unmount();const n=mocks.call.mock.calls.length;window.dispatchEvent(new Event('focus'));await flushPromises();expect(mocks.call).toHaveBeenCalledTimes(n);});
