// @vitest-environment happy-dom
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { beforeEach, expect, it, vi } from 'vitest';
import { serverDirectory, serverDirectoryKey } from '../serverDirectory';
import CheckPanel from './CheckPanel.vue';
import MonitoringLibrary from './MonitoringLibrary.vue';
import type { ActivityEvent, MonitoringDefinition, MonitoringLibraryEntry, MonitoringOverrides, MonitoringPolicy, MonitoringScope, MonitoringValues, Server } from '../types';

const mocks = vi.hoisted(() => ({ call: vi.fn() }));
vi.mock('../api', () => ({ preview: false, call: mocks.call }));

const metrics: MonitoringDefinition = {
  id: 'metrics', name: 'OS resources', category: 'System system', runner: 'metrics', place: 'On the server',
  purpose: 'CPU and memory', reads: '/proc', commands: 'python3 -I <collector>', writes: 'Assembler’s catalog',
  rights: 'Reading', limits: '8 KiB', schedule: 'Every 3 min', configurable: true, intervalEditable: false,
  diagnostics: false, replication: false, factoryInterval: 180, version: 'version-hash',
};
const definitions = [
  metrics,
  { ...metrics, id: 'redis', name: 'Redis', category: 'Services', runner: 'service', diagnostics: true, replication: true,
    thresholds: [{
      key: 'memoryUsage', label: 'Memory limit usage',
      fields: [
        { key: 'warning', label: 'Warning', unit: '%', default: 90, min: 0, max: Number.MAX_SAFE_INTEGER, integer: false },
        { key: 'critical', label: 'Critical', unit: '%', default: 98, min: 0, max: Number.MAX_SAFE_INTEGER, integer: false },
      ],
    }],
  },
  { ...metrics, id: 'transport', name: 'SSH and delivery', runner: 'local', configurable: false, intervalEditable: false },
  { ...metrics, id: 'custom', runner: 'custom', configurable: false, intervalEditable: false },
];
const defaults = { enabled: true, intervalSeconds: 300, diagnosticEnabled: false, expectedPeers: 0, expectReplica: false };
const origins = { enabled: 'factory', intervalSeconds: 'factory', diagnosticEnabled: 'factory', expectedPeers: 'factory', expectReplica: 'factory' };
const endpoint = { user: 'ops', port: 22, identityFile: null, jumpHost: null };
const servers = [{ id: 'a', name: 'one' }, { id: 'b', name: 'two' }].map(server => ({ ...server, endpoint: { ...endpoint, host: server.name + '.example' } })) as Server[];
const mountLibrary = (initial?: { definitionId: string; serverId?: string; instanceId?: string }, attachTo?: HTMLElement) =>
  mount(MonitoringLibrary, { attachTo, props: { servers, now: 100, initial }, global: { stubs: { ServicePanel: true, PostgresqlPanel: true, CheckPanel: true } } });
const serverPicker = (wrapper: VueWrapper) => wrapper.get('.server-picker button');
async function selectServer(wrapper: VueWrapper, host: string) {
  await serverPicker(wrapper).trigger('click');
  await wrapper.findAll('[role="option"]').find(option => option.get('.option-label > span').text() === host)!.trigger('click');
}
const row = (wrapper: VueWrapper, name: string) => wrapper.findAll('.row').find(item => item.get('th').text() === name)!;
const openTab = (wrapper: VueWrapper, name: string) => wrapper.findAll('.tabs button').find(item => item.text() === name)!.trigger('click');
const key = (scope: MonitoringScope) => [scope.definitionId, scope.serverId ?? '', scope.instanceId ?? ''].join('/');
let overrides: Map<string, MonitoringOverrides>;
let revision: number;
function policy(scope: MonitoringScope): MonitoringPolicy {
  const base: MonitoringValues = {
    ...defaults, diagnosticEnabled: scope.definitionId === 'redis',
    thresholds: scope.definitionId === 'redis' ? { memoryUsage: { warning: 90, critical: 98 } } : {},
  };
  const inherited = { ...base };
  const resultOrigins = { ...origins };
  const thresholdOrigins: Record<string, string> = {};
  const layers = [
    { ...scope, serverId: null, instanceId: null },
    ...(scope.serverId ? [{ ...scope, instanceId: null }] : []),
    ...(scope.instanceId ? [scope] : []),
  ];
  const values = { ...base };
  for (const layer of layers) {
    if (key(layer) === key(scope)) Object.assign(inherited, values);
    const update = overrides.get(key(layer)) ?? {};
    const origin = layer.instanceId ? 'instance' : layer.serverId ? 'server' : 'global';
    for (const field of Object.keys(origins) as (keyof typeof origins)[]) {
      if (update[field] == null) continue;
      Object.assign(values, { [field]: update[field] });
      resultOrigins[field] = origin;
    }
    values.thresholds = { ...values.thresholds, ...update.thresholds };
    for (const rule of Object.keys(update.thresholds ?? {})) thresholdOrigins[rule] = origin;
  }
  return { values, inherited, origins: resultOrigins, thresholdOrigins, overrides: overrides.get(key(scope)) ?? {}, revision };
}
beforeEach(() => {
  vi.clearAllMocks();
  overrides = new Map();
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
      const update = Object.fromEntries(Object.entries(args.overrides).filter(([key, value]) =>
        value != null && (key !== 'thresholds' || Object.keys(value).length)));
      if (Object.keys(update).length) overrides.set(key(args.scope), update);
      else overrides.delete(key(args.scope));
      revision++;
      return policy(args.scope);
    }
    throw new Error(command);
  });
});

it('saves a threshold pair above 100% and resets only that rule at a connection', async () => {
  overrides.set('redis/a/second', { diagnosticEnabled: false });
  const wrapper = mountLibrary({ definitionId: 'redis', serverId: 'a', instanceId: 'second' });
  await flushPromises();
  const rule = wrapper.get('.threshold');
  const warning = rule.get<HTMLInputElement>('[aria-label="Memory limit usage Warning"]');
  const critical = rule.get<HTMLInputElement>('[aria-label="Memory limit usage Critical"]');
  expect(wrapper.text()).toContain('Alert thresholds');
  expect(warning.element.value).toBe('90');
  await warning.setValue('101');
  await rule.trigger('submit');
  expect(rule.get('[role="alert"]').text()).toContain('Critical must be higher');
  expect(mocks.call.mock.calls.some(([name]) => name === 'configure_monitoring')).toBe(false);
  await critical.setValue('102');
  await rule.trigger('submit');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('configure_monitoring', {
    scope: { definitionId: 'redis', serverId: 'a', instanceId: 'second' },
    overrides: { diagnosticEnabled: false, thresholds: { memoryUsage: { warning: 101, critical: 102 } } },
    expectedRevision: 1,
  });
  expect(rule.text()).toContain('Connection override');
  await rule.get('button[type="button"]').trigger('click');
  await flushPromises();
  expect(warning.element.value).toBe('90');
  expect(critical.element.value).toBe('98');
  expect(overrides.get('redis/a/second')).toEqual({ diagnosticEnabled: false });
  wrapper.unmount();
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
    await serverPicker(wrapper).trigger('click');
    await wrapper.get('input[aria-label="Find a server"]').setValue('OPS@ONE.EXAMPLE:22');
    expect(mocks.call).toHaveBeenLastCalledWith('vulnerability_catalog', {
      query: { search: '', serverId: null, status: null, offset: 20 },
    });
    await wrapper.get('[role="option"]').trigger('click');
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
  overrides.set('redis/a/', { diagnosticEnabled: false });
  const wrapper = mountLibrary();
  await flushPromises();
  expect(serverPicker(wrapper).text()).toBe('All servers');
  expect(wrapper.findAll('thead th').map(item => item.text())).toEqual(['Check', 'Schedule']);
  expect(row(wrapper, 'Redis').text()).toContain('5 min');
  expect(mocks.call.mock.calls).toEqual([['monitoring_catalog'], ['monitoring_library', { serverId: null }]]);
  await selectServer(wrapper, 'one.example');
  await flushPromises();
  expect(wrapper.findAll('.row')).toHaveLength(1);
  expect(row(wrapper, 'Redis').text()).toContain('5 min');
  await selectServer(wrapper, 'two.example');
  await flushPromises();
  expect(wrapper.text()).toContain('This server uses global settings for all checks');
  expect(wrapper.find('.row').exists()).toBe(false);
  await wrapper.findAll('button').find(button => button.text() === 'Show all server checks')!.trigger('click');
  expect(row(wrapper, 'Redis').text()).toContain('5 min');
  expect(mocks.call.mock.calls.map(([command]) => command)).toEqual(['monitoring_catalog', 'monitoring_library', 'monitoring_library', 'monitoring_library']);
  wrapper.unmount();
});

it('shows the shared interval as read-only for a service connection', async () => {
  overrides.set('redis/a/second', { diagnosticEnabled: false });
  const wrapper = mountLibrary({ definitionId: 'redis', serverId: 'a', instanceId: 'second' });
  await flushPromises();
  expect(wrapper.text()).toContain('Server polling interval · 5 min');
  expect(wrapper.find('input[aria-label="Check interval"]').exists()).toBe(false);
  expect(row(wrapper, 'Redis').text()).toContain('5 min');
  wrapper.unmount();
});

it('opens an instance-only exception and removes the row when the last override is reset', async () => {
  overrides.set('redis/a/second', { diagnosticEnabled: false });
  const wrapper = mountLibrary();
  await flushPromises();
  await selectServer(wrapper, 'one.example');
  await flushPromises();
  expect(row(wrapper, 'Redis').text()).toContain('5 min');
  expect(row(wrapper, 'Redis').text()).toContain('Connection override');
  await row(wrapper, 'Redis').get('button').trigger('click');
  await flushPromises();
  expect(wrapper.get('select[aria-label="Service connection"]').element).toHaveProperty('value', 'second');
  await wrapper.findAll('button').find(button => button.text() === 'Use server settings')!.trigger('click');
  await flushPromises();
  expect(mocks.call).toHaveBeenCalledWith('configure_monitoring', {
    scope: { definitionId: 'redis', serverId: 'a', instanceId: 'second' },
    overrides: { diagnosticEnabled: null }, expectedRevision: 1,
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
  const toggle = wrapper.get('input[type="checkbox"]');
  await toggle.setValue(false);
  await flushPromises();
  expect(wrapper.text()).toContain('Settings changed in another window');
  expect(row(wrapper, 'OS resources').text()).toContain('Every 5 min');
  expect(wrapper.emitted('updated')).toBeUndefined();
  expect(toggle.element).toHaveProperty('checked', true);
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
  await selectServer(wrapper, 'two.example');
  expect(wrapper.getComponent(CheckPanel).props('serverId')).toBe('b');
  wrapper.unmount();
});

it('shows legacy and grouped runs for the selected service instance', async () => {
  const previous = mocks.call.getMockImplementation()!;
  const legacy: ActivityEvent = {
    id: 'old', at: 1700000000000, category: 'server', action: 'Server poll result', phase: 'completed',
    operationId: 'old-poll', target: 'a', runId: null, durationMs: null,
    monitoring: { definitionId: 'redis', instanceId: 'second', serverId: 'a', trigger: 'schedule', version: 'old-hash', revision: 1 },
  };
  const combined: ActivityEvent = {
    ...legacy, id: 'new', action: 'poll', phase: 'failed', monitoring: undefined,
    poll: { version: 'new-hash', revision: 2, trigger: 'after_action', transport: 'completed', checks: [
      { definitionId: 'redis', instanceId: 'default', succeeded: true },
      { definitionId: 'redis', instanceId: 'second', succeeded: false },
      { definitionId: 'metrics', succeeded: true },
    ] },
  };
  mocks.call.mockImplementation((command, args) => command === 'activity_log' ? Promise.resolve({ events: [combined, legacy] }) : previous(command, args));
  const wrapper = mountLibrary({ definitionId: 'redis', serverId: 'a', instanceId: 'second' });
  await flushPromises();
  const recent = wrapper.findAll('details').find(details => details.get('summary').text() === 'Recent runs')!;
  (recent.element as HTMLDetailsElement).open = true;
  await recent.trigger('toggle');
  await flushPromises();
  expect(recent.findAll('tbody tr').map(record => record.findAll('td').slice(2).map(cell => cell.text())))
    .toEqual([['After an action', 'Failed'], ['On schedule', 'Finished']]);
  wrapper.unmount();
});

it('searches 500 servers locally and changes scope only after a selection', async () => {
  const wrapper = mountLibrary(undefined, document.body);
  try {
    await flushPromises();
    mocks.call.mockClear();
    await wrapper.setProps({ servers: Array.from({ length: 500 }, (_, i) => ({ id: String(i), name: `server-${i}`, endpoint: { ...endpoint, host: `server-${i}.example` } })) as Server[] });
    const trigger = serverPicker(wrapper);
    await trigger.trigger('click');
    expect(wrapper.findAll('[role="option"]')).toHaveLength(501);
    const search = wrapper.get('input[aria-label="Find a server"]');
    expect(document.activeElement).toBe(search.element);
    await search.setValue('missing');
    expect(wrapper.get('[role="status"]').text()).toBe('No servers found');
    await search.trigger('keydown', { key: 'Enter' });
    expect(mocks.call).not.toHaveBeenCalled();
    await search.setValue('SERVER-49  .EXAMPLE');
    expect(wrapper.findAll('[role="option"]')).toHaveLength(11);
    await search.trigger('keydown', { key: 'ArrowDown' });
    await search.trigger('keydown', { key: 'Enter' });
    expect(trigger.text()).toBe('server-490.example');
    expect(document.activeElement).toBe(trigger.element);
    expect(mocks.call.mock.calls).toEqual([['monitoring_library', { serverId: '490' }]]);
    await trigger.trigger('click');
    const reopened = wrapper.get<HTMLInputElement>('input[aria-label="Find a server"]');
    expect(reopened.element.value).toBe('');
    await reopened.setValue('missing');
    await reopened.trigger('keydown', { key: 'Escape' });
    expect(trigger.text()).toBe('server-490.example');
    expect(document.activeElement).toBe(trigger.element);
    await selectServer(wrapper, 'All servers');
    expect(mocks.call).toHaveBeenLastCalledWith('monitoring_library', { serverId: null });
  } finally {
    wrapper.unmount();
  }
});
