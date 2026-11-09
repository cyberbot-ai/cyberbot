import { health, ribbonMetricsUnavailable } from './health';
import type { Disk, Observation, Server } from './types';

export const fleetSortColumns = [
  { key: 'host', label: 'Host', hint: 'Compare hostname parts starting with the domain suffix' },
  { key: 'cpu', label: 'CPU', hint: 'CPU usage' },
  { key: 'load', label: 'Load', hint: '1-minute load average' },
  { key: 'ram', label: 'RAM', hint: 'Memory usage' },
  { key: 'swap', label: 'Swap', hint: 'Swap usage' },
  { key: 'disk', label: 'Disk', hint: 'Highest disk space usage across mount points' },
  { key: 'inodes', label: 'Inodes', hint: 'Highest inode usage across mount points' },
] as const;

export type FleetSortKey = typeof fleetSortColumns[number]['key'];
export type FleetSort = { key: FleetSortKey; direction: 'ascending' | 'descending' };

const hostCollator = new Intl.Collator('en-US', { numeric: true, sensitivity: 'base' });

function hostParts(host: string): string[] {
  const name = host.replace(/\.$/, '');
  const parts = name.split('.');
  const ipv4 = parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  return name.includes(':') || ipv4 ? [name] : parts.reverse();
}

function compareHosts(left: string[], right: string[]): number {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    const order = hostCollator.compare(left[index], right[index]);
    if (order) return order;
  }
  return left.length - right.length;
}

function highestUsage(disks: Disk[], key: 'usedPercent' | 'inodePercent'): number | null {
  let highest: number | null = null;
  for (const disk of disks) {
    const value = disk[key];
    if (value != null && Number.isFinite(value) && (highest == null || value > highest)) highest = value;
  }
  return highest;
}

const metricValue: Record<Exclude<FleetSortKey, 'host'>, (observation: Observation) => number | null> = {
  cpu: observation => observation.cpuPercent,
  load: observation => observation.load,
  ram: observation => observation.memoryPercent,
  swap: observation => observation.swapPercent,
  disk: observation => highestUsage(observation.disks, 'usedPercent'),
  inodes: observation => highestUsage(observation.disks, 'inodePercent'),
};

export function sortFleet(servers: Server[], { key, direction }: FleetSort, now: number, interval: number): Server[] {
  const sign = direction === 'ascending' ? 1 : -1;
  const rows = servers.map(server => {
    const observation = server.observation;
    const value = key !== 'host' && observation && !ribbonMetricsUnavailable(server, health(server, now, interval))
      ? metricValue[key](observation) : null;
    return { server, host: hostParts(server.endpoint.host), value: Number.isFinite(value) ? value : null };
  });

  rows.sort((left, right) => {
    if (left.value == null && right.value != null) return 1;
    if (right.value == null && left.value != null) return -1;
    const byMetric = left.value != null && right.value != null ? sign * (left.value - right.value) : 0;
    return byMetric || (key === 'host' ? sign : 1) * compareHosts(left.host, right.host)
      || left.server.id.localeCompare(right.server.id);
  });
  return rows.map(({ server }) => server);
}
