// @vitest-environment happy-dom
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { beforeEach, expect, it, vi } from 'vitest';
import { serverDirectory, serverDirectoryKey } from '../serverDirectory';
import CheckPanel from './CheckPanel.vue';
import MonitoringLibrary from './MonitoringLibrary.vue';
import type { MonitoringDefinition, MonitoringLibraryEntry, MonitoringOverrides, MonitoringPolicy, MonitoringScope, Server } from '../types';

const mocks = vi.hoisted(() => ({ call: vi.fn() }));
vi.mock('../api', () => ({ preview: false, call: mocks.call }));

const metrics: MonitoringDefinition = {
  id: 'metrics', name: 'OS resources', category: 'System system', runner: 'metrics', place: 'On the server',
  purpose: 'CPU and memory', reads: '/proc', commands: 'python3 -I <collector>', writes: 'Assembler’s catalog',
  rights: 'Reading', limits: '8 KiB', schedule: 'Every 3 min', configurable: true, intervalEditable: true,
  diagnostics: false, replication: false, factoryInterval: 180, version: 'version-hash',
};
const definitions = [
  metrics,
  { ...metrics, id: 'redis', name: 'Redis', category: 'Services', runner: 'service', diagnostics: true, replication: true },
  { ...metrics, id: 'transport', name: 'SSH and delivery', runner: 'local', configurable: false, intervalEditable: false },
  { ...metrics, id: 'custom', runner: 'custom', configurable: false, intervalEditable: false },
];
const defaults = { enabled: true, intervalSeconds: 180, diagnosticEnabled: false, expectedPeers: 0, expectReplica: false };
const origins = { enabled: 'factory', intervalSeconds: 'factory', diagnosticEnabled: 'factory', expectedPeers: 'factory', expectReplica: 'factory' };
const endpoint = { user: 'ops', port: 22, identityFile: null, jumpHost: null };
const servers = [{ id: 'a', name: 'one' }, { id: 'b', name: 'two' }].map(server => ({ ...server, endpoint: { ...endpoint, host: server.name + '.example' } })) as Server[];
const mountLibrary = (initial?: { definitionId: string; serverId?: string; instanceId?: string }) =>
  mount(MonitoringLibrary, { props: { servers, now: 100, initial }, global: { stubs: { ServicePanel: true, PostgresqlPanel: true, CheckPanel: true } } });
const selector = (wrapper: VueWrapper) => wrapper.get('select[aria-label="Servers"]');
const row = (wrapper: VueWrapper, name: string) => wrapper.findAll('.row').find(item => item.get('th').text() === name)!;
const interval = (wrapper: VueWrapper) => wrapper.get('input[aria-label="Check interval"]');
const openInterval = (wrapper: VueWrapper) => wrapper.get('.interval-button').trigger('click');
const openTab = (wrapper: VueWrapper, name: string) => wrapper.findAll('.tabs button').find(item => item.text() === name)!.trigger('click');
const key = (scope: MonitoringScope) => [scope.definitionId, scope.serverId ?? '', scope.instanceId ?? ''].join('/');
let overrides: Map<string, MonitoringOverrides>;
let revision: number;
function policy(scope: MonitoringScope): MonitoringPolicy {
  const base = { ...defaults, diagnosticEnabled: scope.definitionId === 'redis' };
  const inherited = { ...base };
  const resultOrigins = { ...origins };
  const layers = [
    { ...scope, serverId: null, instanceId: null },
    ...(scope.serverId ? [{ ...scope, instanceId: null }] : []),
    ...(scope.instanceId ? [scope] : []),
  ];
  const values = { ...base };
  for (const layer of layers) {
    if (key(layer) === key(scope)) Object.assign(inherited, values);
    const update = overrides.get(key(layer)) ?? {};
    for (const field of Object.keys(update) as (keyof typeof values)[]) {
      if (update[field] == null) continue;
      Object.assign(values, { [field]: update[field] });
      resultOrigins[field] = layer.instanceId ? 'instance' : layer.serverId ? 'server' : 'global';
    }
  }
  return { values, inherited, origins: resultOrigins, overrides: overrides.get(key(scope)) ?? {}, revision };
}
beforeEach(() => {
  vi.clearAllMocks();
  overrides = new Map([['redis//', { intervalSeconds: 300 }]]);
  revision = 1;
  mocks.call.mockImplementation(async (command, args) => {
    if (command === 'monitoring_catalog') return definitions;
    if (command === 'monitoring_library') {
      return Object.fromEntries(definitions.filter(item => item.configurable).map(item => {
        const scope = { definitionId: item.id, serverId: args.serverId, instanceId: null };
        const instanceOverrides = Object.fromEntries(['default', 'second'].flatMap(instanceId => {
          const instance = { ...scope, instanceId };
          return args.serverId && overrides.has(key(instance)) ? [[instanceId, policy(instance).values]] : [];
        }));
        const entry: MonitoringLibraryEntry = {
          values: policy(scope).values, serverOverride: !!args.serverId && overrides.has(key(scope)), instanceOverrides,
        };
        return [item.id, entry];
      }));
    }
    if (command === 'monitoring_policy') return policy(args.scope);
    if (command === 'list_service_instances') return [{ id: 'default', kind: 'redis', name: 'Redis:6379' }, { id: 'second', kind: 'redis', name: 'Redis:6380' }];
    if (command === 'activity_log') return { events: [] };
    if (command === 'monitoring_sources') return [{ name: 'actual.py', text: '<script>untrusted</script>' }];
    if (command === 'configure_monitoring') {
      const update = Object.fromEntries(Object.entries(args.overrides).filter(([, value]) => value != null));
      if (Object.keys(update).length) overrides.set(key(args.scope), update);
      else overrides.delete(key(args.scope));
      revision++;
      return policy(args.scope);
    }
    throw new Error(command);
  });
});

it('opens the CVE catalog independently and keeps all server links under a filtered result', async () => {
  const open = vi.fn();
  const catalogRow = {
    cve: 'CVE-2026-1000', title: 'Discussion error', publishedOn: '2026-10-21',
    firstPackage: 'openssl', packageCount: 2, firstServer: 'one.example', serverCount: 2,
  };
  const baseCall = mocks.call.getMockImplementation()!;
  mocks.call.mockImplementation(async (command, args) => {
    if (command === 'monitoring_catalog') throw new Error('Inspections not available');
    if (command === 'vulnerability_catalog') {
      return {
        rows: [catalogRow], offset: args.query.offset, total: args.query.status ? 1 : 21, partial: false,
      };
    }
    if (command === 'vulnerability_catalog_detail') {
      return {
        packages: ['openssl', 'libssl3'],
        servers: servers.map((server, index) => ({
          serverId: server.id, name: server.name, address: `ops@${server.endpoint.host}:22`,
          findings: [{ package: 'openssl', status: index ? 'resolved' : 'hidden' }],
        })),
        partial: false,
      };
    }
    return baseCall(command, args);
  });
  const wrapper = mount(MonitoringLibrary, {
    props: { servers, now: 100 },
    global: { provide: { [serverDirectoryKey as symbol]: { current: () => serverDirectory(servers), open } } },
  });
  try {
    await flushPromises();
    expect(wrapper.text()).toContain('Inspections not available');
    await openTab(wrapper, 'Vulnerabilities');
    await flushPromises();
    expect(wrapper.text()).toContain('21.10.2026');
    await wrapper.findAll('footer button').find(button => button.text() === 'Next')!.trigger('click');
    await flushPromises();
    expect(mocks.call).toHaveBeenLastCalledWith('vulnerability_catalog', {
      query: { search: '', serverId: null, status: null, offset: 20 },
    });
    await selector(wrapper).setValue('a');
    await wrapper.get('select[aria-label="Finding status"]').setValue('hidden');
    await flushPromises();
    expect(mocks.call).toHaveBeenLastCalledWith('vulnerability_catalog', {
      query: { search: '', serverId: 'a', status: 'hidden', offset: 0 },
    });
    const button = wrapper.get('.cve-button');
    await button.trigger('click');
    await flushPromises();
    expect(button.attributes('aria-expanded')).toBe('true');
    expect(wrapper.get('.expanded').text()).toContain('Hidden manually');
    expect(wrapper.get('.expanded').text()).toContain('No longer detected');
    const links = wrapper.findAll('.expanded .server-link');
    expect(links.map(link => link.text())).toEqual(['one.example', 'two.example']);
    await links[1].trigger('click');
    expect(open).toHaveBeenCalledWith('b', undefined);
    await button.trigger('click');
    expect(wrapper.find('.expanded').exists()).toBe(false);
  } finally {
    wrapper.unmount();
  }
});

it('starts at common settings and reads a selected server without per-row calls', async () => {
  overrides.set('redis/a/', { intervalSeconds: 120 });
  const wrapper = mountLibrary();
  await flushPromises();
  expect(selector(wrapper).get('option').text()).toBe('All servers');
  expect(selector(wrapper).element).toHaveProperty('value', '');
  expect(wrapper.findAll('thead th').map(item => item.text())).toEqual(['Check', 'Schedule']);
  expect(row(wrapper, 'Redis').text()).toContain('5 min');
  expect(mocks.call.mock.calls).toEqual([['monitoring_catalog'], ['monitoring_library', { serverId: null }]]);
  await selector(wrapper).setValue('a');
  await flushPromises();
  expect(wrapper.findAll('.row')).toHaveLength(1);
  expect(row(wrapper, 'Redis').text()).toContain('2 min');
  await selector(wrapper).setValue('b');
  await flushPromises();
  expect(wrapper.text()).toContain('This server uses global settings for all checks');
  expect(wrapper.find('.row').exists()).toBe(false);
  await wrapper.findAll('button').find(button => button.text() === 'Show all server checks')!.trigger('click');
  expect(row(wrapper, 'Redis').text()).toContain('5 min');
  expect(mocks.call.mock.calls.map(([command]) => command)).toEqual(['monitoring_catalog', 'monitoring_library', 'monitoring_library', 'monitoring_library']);
  wrapper.unmount();
});

it('validates an inline edit and saves only the selected connection with full second precision', async () => {
  overrides.set('redis/a/second', { diagnosticEnabled: false });
  const wrapper = mountLibrary({ definitionId: 'redis', serverId: 'a', instanceId: 'second' });
  await flushPromises();
  expect(wrapper.get('.interval-button').text()).toBe('5 min');
  await openInterval(wrapper);
  await interval(wrapper).setValue('2 s');
  await interval(wrapper).trigger('keydown.enter');
  expect(wrapper.text()).toContain('Enter an interval');
  expect(mocks.call.mock.calls.some(([command]) => command === 'configure_monitoring')).toBe(false);
  await interval(wrapper).setValue('90 s');
  await interval(wrapper).trigger('keydown.enter');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('configure_monitoring', {
    scope: { definitionId: 'redis', serverId: 'a', instanceId: 'second' },
    overrides: { diagnosticEnabled: false, intervalSeconds: 90 }, expectedRevision: 1,
  });
  expect(wrapper.get('.interval-button').text()).toBe('90 s');
  expect(row(wrapper, 'Redis').text()).toContain('6 h');
  wrapper.unmount();
});

it('opens an instance-only exception and removes the row when the last override is reset', async () => {
  overrides.set('redis/a/second', { intervalSeconds: 120 });
  const wrapper = mountLibrary();
  await flushPromises();
  await selector(wrapper).setValue('a');
  await flushPromises();
  expect(row(wrapper, 'Redis').text()).toContain('2 min');
  expect(row(wrapper, 'Redis').text()).toContain('Connection override');
  await row(wrapper, 'Redis').get('button').trigger('click');
  await flushPromises();
  expect(wrapper.get('select[aria-label="Service connection"]').element).toHaveProperty('value', 'second');
  await wrapper.findAll('button').find(button => button.text() === 'Use server settings')!.trigger('click');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('configure_monitoring', {
    scope: { definitionId: 'redis', serverId: 'a', instanceId: 'second' },
    overrides: { intervalSeconds: null }, expectedRevision: 1,
  });
  expect(wrapper.text()).toContain('This server uses global settings for all checks');
  expect(wrapper.find('.row').exists()).toBe(false);
  wrapper.unmount();
});

it('lets a single connection and the whole server be edited independently', async () => {
  const original = mocks.call.getMockImplementation()!;
  mocks.call.mockImplementation((command, args) => command === 'list_service_instances'
    ? Promise.resolve([{ id: 'default', kind: 'redis', name: 'Redis:6379' }]) : original(command, args));
  const wrapper = mountLibrary({ definitionId: 'redis', serverId: 'a' });
  await flushPromises();
  const connection = wrapper.get('select[aria-label="Service connection"]');
  expect(connection.element).toHaveProperty('value', '');
  await connection.setValue('default');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('monitoring_policy', {
    scope: { definitionId: 'redis', serverId: 'a', instanceId: 'default' },
  });
  wrapper.unmount();
});

it('shows a write error and does not publish an uncommitted edit', async () => {
  const wrapper = mountLibrary({ definitionId: 'metrics' });
  await flushPromises();
  mocks.call.mockRejectedValueOnce(new Error('Settings changed in another window'));
  await openInterval(wrapper);
  await interval(wrapper).setValue('2 min');
  await interval(wrapper).trigger('keydown.enter');
  await flushPromises();
  expect(wrapper.text()).toContain('Settings changed in another window');
  expect(row(wrapper, 'OS resources').text()).toContain('Every 3 min');
  expect(wrapper.emitted('updated')).toBeUndefined();
  expect(interval(wrapper).element).toHaveProperty('value', '2 min');
  await interval(wrapper).trigger('keydown.esc');
  expect(wrapper.get('.interval-button').text()).toBe('3 min');
  wrapper.unmount();
});

it('keeps technical details lazy and separates custom checks and service jobs', async () => {
  const wrapper = mountLibrary({ definitionId: 'metrics' });
  await flushPromises();
  expect(wrapper.text()).toContain('/proc');
  expect(mocks.call.mock.calls.some(([command]) => command === 'monitoring_sources' || command === 'activity_log')).toBe(false);
  const source = wrapper.findAll('details').find(item => item.get('summary').text().startsWith('Sources'))!;
  (source.element as HTMLDetailsElement).open = true;
  await source.trigger('toggle');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('monitoring_sources', { definitionId: 'metrics' });
  expect(wrapper.get('pre').text()).toContain('<script>');
  expect(wrapper.find('script').exists()).toBe(false);
  await openTab(wrapper, 'Overrides');
  await row(wrapper, 'SSH and delivery').get('button').trigger('click');
  expect(wrapper.find('.interval-button').exists()).toBe(false);
  await openTab(wrapper, 'My checks');
  await selector(wrapper).setValue('b');
  expect(wrapper.getComponent(CheckPanel).props('serverId')).toBe('b');
  wrapper.unmount();
});

it('keeps the 500-server selector read-only without fetching when its options update', async () => {
  const wrapper = mountLibrary();
  await flushPromises();
  mocks.call.mockClear();
  await wrapper.setProps({ servers: Array.from({ length: 500 }, (_, i) => ({ id: String(i), name: `server-${i}`, endpoint: { ...endpoint, host: `server-${i}.example` } })) as Server[] });
  await flushPromises();
  expect(selector(wrapper).findAll('option')).toHaveLength(501);
  expect(mocks.call).not.toHaveBeenCalled();
  wrapper.unmount();
});
