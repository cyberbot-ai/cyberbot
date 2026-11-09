import { describe, expect, it } from 'vitest';
import { sortFleet, type FleetSort } from './fleetSort';
import type { Observation, Server } from './types';

const now = 1000;
const interval = 180;

function server(host: string, metrics: Partial<Observation> = {}): Server {
  return {
    id: host, name: 'Inventory alias', sourceId: 'fixture',
    endpoint: { host, user: 'ops', port: 22, identityFile: null, jumpHost: null },
    observation: {
      at: now, cpuPercent: 10, memoryPercent: 10, swapPercent: 0, load: 0.5, uptime: 100,
      disks: [], services: [], missing: [], bytesReceived: 100, durationMs: 10, ...metrics,
    },
    lastError: null, lastAttempt: now, nextCheck: now + interval, failures: 0,
  };
}

function ids(servers: Server[], key: FleetSort['key'], direction: FleetSort['direction'] = 'ascending') {
  return sortFleet(servers, { key, direction }, now, interval).map(row => row.id);
}

describe('fleet sorting', () => {
  it('groups domains and subdomains, compares numbers naturally, and preserves address part order', () => {
    const expected = [
      '::ffff:10.0.0.10', '::ffff:10.0.1.2', '10.0.0.10', '10.0.1.2',
      'z.alpha.com', 'example.com', 'S2.App.Example.Com.', 's10.app.example.com', 's1.db.example.com', 'a.alpha.net',
    ];
    const input = [...expected].reverse().map(host => server(host));
    expect(ids(input, 'host')).toEqual(expected);
    expect(ids(input, 'host', 'descending')).toEqual([...expected].reverse());
    expect(input.map(row => row.id)).toEqual([...expected].reverse());
  });

  it('breaks ties between equivalent hostnames by server ID', () => {
    const input = [{ ...server('host.example.com'), id: 'b' }, { ...server('HOST.example.com.'), id: 'a' }];
    expect(ids(input, 'host', 'descending')).toEqual(['a', 'b']);
    expect(ids(input, 'cpu', 'descending')).toEqual(['a', 'b']);
  });

  it.each([
    ['cpu', 'cpuPercent'], ['load', 'load'], ['ram', 'memoryPercent'], ['swap', 'swapPercent'],
  ] as const)('sorts %s by the raw reading and keeps unavailable values last', (key, field) => {
    const rows = [
      server('s1', { [field]: 9.11 }), server('s2', { [field]: 9.14 }), server('zero', { [field]: 0 }),
      server('invalid', { [field]: Infinity }), server('missing', { [field]: null }),
      { ...server('none'), observation: null }, { ...server('offline'), networkOffline: true },
      { ...server('pending'), awaitingFirstCheck: true }, server('stale', { at: now - interval * 3 }),
      { ...server('unreachable'), lastError: 'SSH timeout' },
    ];
    const unavailable = ['invalid', 'missing', 'none', 'offline', 'pending', 'stale', 'unreachable'];
    expect(ids(rows, key)).toEqual(['zero', 's1', 's2', ...unavailable]);
    expect(ids(rows, key, 'descending')).toEqual(['s2', 's1', 'zero', ...unavailable]);
  });

  it('ranks disk space and inode usage by their respective maximum across mounts', () => {
    const rows = [
      server('a', { disks: [{ mount: '/', usedPercent: 2, inodePercent: null }, { mount: '/data', usedPercent: 99, inodePercent: 10 }] }),
      server('b', { disks: [{ mount: '/', usedPercent: 20, inodePercent: 30 }, { mount: '/logs', usedPercent: NaN, inodePercent: 80 }] }),
      server('c', { disks: [{ mount: '/', usedPercent: 0, inodePercent: null }] }),
      server('d'),
    ];
    expect(ids(rows, 'disk', 'descending')).toEqual(['a', 'b', 'c', 'd']);
    expect(ids(rows, 'disk')).toEqual(['c', 'b', 'a', 'd']);
    expect(ids(rows, 'inodes', 'descending')).toEqual(['b', 'a', 'c', 'd']);
    expect(ids(rows, 'inodes')).toEqual(['a', 'b', 'c', 'd']);
  });
});
