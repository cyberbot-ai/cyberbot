import { expect, it } from 'vitest';
import { activityServerReference, serverAddress, serverDirectory, serverDisplayHost, serverLabel } from './serverDirectory';
import type { ActivityEvent } from './types';

const endpoint = { host: '2001:db8::1', user: 'ops', port: 2222, jumpHost: 'bastion' };
const first = { id: '2c9d9fc4-8d97-4c5c-b119-cec1ae464e5d', name: 'inventory-primary', endpoint };
const second = { ...first, id: 'second', name: 'inventory-secondary' };
const address = 'ops@[2001:db8::1]:2222 via bastion';
const event: ActivityEvent = { id: 'log', at: 1, category: 'ssh', action: 'connect', phase: 'completed',
  operationId: 'op', target: address, runId: null, durationMs: 1 };

it.each([
  ['proxy.example.com', '192.0.2.7', 'proxy.example.com'],
  ['DB.internal.', '2001:db8::1', 'DB.internal.'],
  ['proxy.example.com', 'ssh.example.net', 'proxy.example.com'],
  ['proxy', 'ssh.example.net', 'ssh.example.net'],
  ['192.0.2.7', '192.0.2.7', '192.0.2.7'],
  ['192.0.2.7', '192.0.2.8', '192.0.2.8'],
  ['ops@proxy.example.com:22', '192.0.2.7', '192.0.2.7'],
])('displays %s at %s as %s', (name, host, expected) => {
  expect(serverDisplayHost(name, host)).toBe(expected);
});

it('resolves an old SSH address only when the full endpoint is unique', () => {
  expect(serverAddress(endpoint)).toBe(address);
  const unique = serverDirectory([first]);
  const reference = activityServerReference(event, unique)!;
  expect(unique.resolve(reference)).toBe(first);
  expect(unique.resolve({ address: 'ops@[2001:db8::1]:22 via bastion' })).toBeUndefined();
  const duplicate = serverDirectory([first, second]);
  expect(duplicate.resolve(reference)).toBeUndefined();
  expect(duplicate.resolve({ id: second.id, address })).toBe(second);
  expect(serverLabel(reference, first)).toEqual({ host: endpoint.host, hint: first.name + ' · ' + address });
});

it('keeps saved identity ahead of matching endpoints and preserves the historical host', () => {
  const directory = serverDirectory([second]);
  const historic = activityServerReference({ ...event, server: { id: first.id, name: first.name, address } }, directory)!;
  expect(directory.resolve(historic)).toBeUndefined();
  expect(serverLabel(historic).host).toBe(endpoint.host);
  const idOnly = activityServerReference({ ...event, target: first.id }, directory)!;
  expect(serverLabel(idOnly).host).toBe('Server unavailable');
  expect(activityServerReference({ ...event, target: 'inventory.yml', category: 'app' }, directory)).toBeUndefined();
});
