// @vitest-environment happy-dom
import {mount,flushPromises} from '@vue/test-utils';
import {beforeEach,expect,it,vi} from 'vitest';
import NotificationSettings from './NotificationSettings.vue';
const mocks=vi.hoisted(()=>({call:vi.fn()}));
vi.mock('../api',()=>({preview:false,call:mocks.call}));
const state={enabled:true,badgeAllowed:true,permission:'authorized',error:null,queued:0,overflow:0};
beforeEach(()=>{vi.clearAllMocks();mocks.call.mockImplementation(async(c,a)=>c==='configure_notifications'?{...state,enabled:a.enabled}:state);});
it('loads OS permission and autosaves the switch without sending a notification',async()=>{const w=mount(NotificationSettings);await flushPromises();expect(w.text()).toContain('Allowed by macOS');await w.get('input').setValue(false);await flushPromises();expect(mocks.call).toHaveBeenCalledWith('configure_notifications',{enabled:false});expect(w.get('button').attributes('disabled')).toBeDefined();expect(mocks.call.mock.calls.some(c=>c[0]==='test_notification')).toBe(false);w.unmount();});
it('sends only the fixed test command on an explicit click and shows denial/failure',async()=>{mocks.call.mockResolvedValueOnce({...state,permission:'denied'});const w=mount(NotificationSettings);await flushPromises();expect(w.text()).toContain('Allow Cyberbot notifications in system settings');mocks.call.mockRejectedValueOnce(new Error('Notification permission is required'));await w.get('button').trigger('click');await flushPromises();expect(w.get('[role="alert"]').text()).toContain('Notification permission is required');expect(mocks.call).toHaveBeenCalledWith('test_notification');expect(mocks.call.mock.calls.every(c=>['notification_status','test_notification'].includes(c[0]))).toBe(true);w.unmount();});

it('saves the Dock badge preference when macOS permission is denied and rolls back on failure', async () => {
  mocks.call.mockResolvedValueOnce({...state, enabled: false, badgeAllowed: false, permission: 'denied'});
  const wrapper = mount(NotificationSettings, {props: {dockBadgeEnabled: true}});
  await flushPromises();
  const badge = wrapper.get<HTMLInputElement>('input[aria-describedby="dock-badge-description"]');
  expect(badge.element.disabled).toBe(false);
  expect(badge.element.checked).toBe(true);

  mocks.call.mockRejectedValueOnce(new Error('Could not save settings'));
  await badge.setValue(false);
  await flushPromises();
  expect(badge.element.checked).toBe(true);
  expect(wrapper.get('[role="alert"]').text()).toBe('Could not save settings');

  mocks.call.mockResolvedValueOnce({dockBadgeEnabled: false});
  await badge.setValue(false);
  await flushPromises();
  await wrapper.setProps({dockBadgeEnabled: false});
  expect(badge.element.checked).toBe(false);
  expect(wrapper.find('[role="alert"]').exists()).toBe(false);
  expect(mocks.call.mock.calls.slice(1)).toEqual([
    ['update_settings', {patch: {dockBadgeEnabled: false}}],
    ['update_settings', {patch: {dockBadgeEnabled: false}}],
  ]);
  wrapper.unmount();
});

it('requests badge permission on demand with incident notifications off', async () => {
  mocks.call.mockResolvedValueOnce({...state, enabled: false, badgeAllowed: false, permission: 'notDetermined'});
  const wrapper = mount(NotificationSettings, {props: {dockBadgeEnabled: true}});
  await flushPromises();
  const allow = wrapper.findAll('button').find(button => button.text() === 'Allow Dock badge');
  expect(allow).toBeDefined();
  mocks.call.mockResolvedValueOnce({...state, enabled: false});
  await allow!.trigger('click');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('request_notification_permission');
  expect(wrapper.text()).not.toContain('Allow Dock badge');
  wrapper.unmount();
});
