// @vitest-environment happy-dom
import { mount, flushPromises } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import DependenciesPanel from './DependenciesPanel.vue';
import type { ServerDependencies } from '../types';
const mocks = vi.hoisted(() => ({ call: vi.fn(), preview: false }));
vi.mock('../api', () => ({ get preview() { return mocks.preview; }, call: mocks.call }));
const dependencies = (): ServerDependencies => ({ available: [{ id: 'db', name: 'Database' }, { id: 'cache', name: 'Cache' }], dependsOn: ['db'] });
const writes = () => mocks.call.mock.calls.filter(c => c[0] === 'save_server_dependencies');
beforeEach(() => {
  vi.clearAllMocks(); mocks.preview = false;
  mocks.call.mockImplementation(async command => command === 'server_dependencies' ? dependencies() : null);
});

describe('server dependencies editor', () => {
  it('shows existing checkboxes and autosaves selecting and removing links without a save button', async () => {
    const w = mount(DependenciesPanel, { props: { serverId: 'web' } }); await flushPromises();
    expect(mocks.call).toHaveBeenCalledWith('server_dependencies', { id: 'web' });
    expect(w.find('select').exists()).toBe(false); expect(w.findAll('button')).toHaveLength(0);
    expect(w.findAll('.server-option').map(row => row.text())).toEqual(['Database', 'Cache']);
    expect((w.get('input[value="db"]').element as HTMLInputElement).checked).toBe(true);
    await w.get('input[value="cache"]').setValue(true); await flushPromises();
    expect(writes().at(-1)).toEqual(['save_server_dependencies', { id: 'web', dependsOn: ['db', 'cache'] }]);
    await w.get('input[value="db"]').setValue(false); await flushPromises();
    expect(w.findAll('.server-option').map(row => row.text())).toEqual(['Database', 'Cache']);
    await w.get('input[value="cache"]').setValue(false); await flushPromises();
    expect(writes().at(-1)).toEqual(['save_server_dependencies', { id: 'web', dependsOn: [] }]);
    expect(w.text()).toContain('Save');
    expect(mocks.call.mock.calls.every(c => ['server_dependencies', 'save_server_dependencies'].includes(c[0]))).toBe(true); w.unmount();
  });
  it('searches case insensitively without losing selected servers outside the results', async () => {
    const w = mount(DependenciesPanel, { props: { serverId: 'web' } }); await flushPromises();
    await w.get('input[type="search"]').setValue(' CACHE ');
    expect(w.findAll('input[type="checkbox"]')).toHaveLength(1);
    await w.get('input[value="cache"]').setValue(true); await flushPromises();
    expect(writes()[0][1].dependsOn).toEqual(['db', 'cache']);
    await w.get('input[type="search"]').setValue('not found'); expect(w.text()).toContain('No servers found');
    await w.get('input[type="search"]').setValue('');
    expect((w.get('input[value="db"]').element as HTMLInputElement).checked).toBe(true); w.unmount();
  });
  it('drains newer edits after an in-flight write even when the panel closes', async () => {
    let complete!: () => void;
    mocks.call.mockImplementation(command => command === 'server_dependencies' ? Promise.resolve(dependencies()) : writes().length === 1 ? new Promise<void>(resolve => { complete = resolve; }) : Promise.resolve(null));
    const w = mount(DependenciesPanel, { props: { serverId: 'web' } }); await flushPromises();
    await w.get('input[value="cache"]').setValue(true);
    expect(w.text()).toContain('Saving…');
    expect(w.get('input[value="db"]').attributes('disabled')).toBeUndefined();
    await w.get('input[value="db"]').setValue(false);
    expect(writes()).toHaveLength(1); w.unmount(); complete(); await flushPromises();
    expect(writes()).toEqual([
      ['save_server_dependencies', { id: 'web', dependsOn: ['db', 'cache'] }],
      ['save_server_dependencies', { id: 'web', dependsOn: ['cache'] }],
    ]);
  });
  it('shows a save failure and retries only after an explicit action', async () => {
    const w = mount(DependenciesPanel, { props: { serverId: 'web' } }); await flushPromises();
    mocks.call.mockRejectedValueOnce(new Error('The server is remote'));
    await w.get('input[value="cache"]').setValue(true); await flushPromises();
    expect(w.get('[role="alert"]').text()).toContain('Links not maintained: The server is remote');
    await flushPromises(); expect(writes()).toHaveLength(1);
    await w.get('button').trigger('click'); await flushPromises();
    expect(writes()).toHaveLength(2); expect(w.find('[role="alert"]').exists()).toBe(false);
    expect(w.text()).toContain('Save'); w.unmount();
  });
  it('separates loading failures from an empty inventory and can reload', async () => {
    mocks.call.mockRejectedValueOnce(new Error('I couldn’t read the database'));
    const w = mount(DependenciesPanel, { props: { serverId: 'web' } }); await flushPromises();
    expect(w.findAll('input[type="checkbox"]')).toHaveLength(0);
    expect(w.get('[role="alert"]').text()).toContain('Couldn’t download the link');
    expect(w.text()).not.toContain('Add another one');
    await w.get('button').trigger('click'); await flushPromises();
    expect(w.findAll('input[type="checkbox"]')).toHaveLength(2); expect(writes()).toHaveLength(0); w.unmount();
    mocks.call.mockResolvedValueOnce({ available: [], dependsOn: [] });
    const empty = mount(DependenciesPanel, { props: { serverId: 'alone' } }); await flushPromises();
    expect(empty.text()).toContain('Add another server'); expect(empty.find('button').exists()).toBe(false); empty.unmount();
  });
  it('ignores a late load for the previous server and excludes self links', async () => {
    let complete!: (value: ServerDependencies) => void;
    mocks.call.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }))
      .mockResolvedValueOnce({ available: [{ id: 'other', name: 'Self' }, { id: 'db', name: 'Database' }], dependsOn: [] });
    const w = mount(DependenciesPanel, { props: { serverId: 'web' } });
    expect(w.text()).toContain('Loading servers');
    await w.setProps({ serverId: 'other' }); await flushPromises(); complete(dependencies()); await flushPromises();
    expect(w.find('input[value="other"]').exists()).toBe(false); expect(w.find('input[value="cache"]').exists()).toBe(false);
    await w.get('input[value="db"]').setValue(true); await flushPromises();
    expect(writes()[0]).toEqual(['save_server_dependencies', { id: 'other', dependsOn: ['db'] }]); w.unmount();
  });
  it('keeps the existing 64-link limit while allowing removal', async () => {
    const available = Array.from({ length: 65 }, (_, i) => ({ id: `s${i}`, name: `Server ${i}` }));
    mocks.call.mockResolvedValueOnce({ available, dependsOn: available.slice(0, 64).map(s => s.id) });
    const w = mount(DependenciesPanel, { props: { serverId: 'web' } }); await flushPromises();
    expect(w.get('input[value="s64"]').attributes('disabled')).toBeDefined();
    await w.get('input[value="s0"]').setValue(false); await flushPromises();
    expect(w.get('input[value="s64"]').attributes('disabled')).toBeUndefined();
    await w.get('input[value="s64"]').setValue(true); await flushPromises();
    expect(writes().at(-1)![1].dependsOn).toHaveLength(64); w.unmount();
  });
  it('shows preview selections and escapes names without permitting writes', async () => {
    mocks.preview = true;
    mocks.call.mockResolvedValueOnce({ available: [{ id: 'db', name: '<script>Database</script>' }], dependsOn: ['db'] });
    const w = mount(DependenciesPanel, { props: { serverId: 'web' } }); await flushPromises();
    expect(w.text()).toContain('<script>Database</script>'); expect(w.find('script').exists()).toBe(false);
    expect(w.get('input[type="checkbox"]').attributes('disabled')).toBeDefined();
    await w.get('input[type="checkbox"]').trigger('change'); await flushPromises(); expect(writes()).toHaveLength(0); w.unmount();
  });
});
