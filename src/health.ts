import type { Health, Server } from './types';
export const healthLabel: Record<Health,string> = { healthy: 'Healthy', warning: 'Needs attention', critical: 'Critical', unknown: 'No data', stale: 'Stale', unreachable: 'Poll failed' };

function hasPartialData(server: Server, state: Health): boolean {
  if (state !== 'unknown' || server.networkOffline || server.awaitingFirstCheck || server.monitoring?.enabled === false) return false;
  const o = server.observation;
  return Boolean(o && (o.disks.length || o.services.length ||
    [o.cpuPercent, o.memoryPercent, o.load, o.uptime, o.swapPercent].some(Number.isFinite)));
}

export function serverHealthLabel(server: Server, state: Health): string {
  if (server.networkOffline) return healthLabel.unknown;
  if (server.awaitingFirstCheck) {
    return state === 'unknown' ? 'Awaiting first check' : `${healthLabel[state]} · awaits a metric survey`;
  }
  if (state === 'unknown' && server.monitoring?.enabled === false) return 'Poll metrics off';
  return hasPartialData(server, state) ? 'Incomplete data' : healthLabel[state];
}

function hasCoreMetrics(o: NonNullable<Server['observation']>): boolean {
  return Number.isFinite(o.cpuPercent) && Number.isFinite(o.memoryPercent)
    && o.disks.some(disk => Number.isFinite(disk.usedPercent));
}

export function partialHealthReason(server: Server, state: Health): string | undefined {
  if (!hasPartialData(server, state)) return undefined;
  return 'Server responds. Part of the basic metrics are unavailable.';
}
export function health(server: Server, now = Date.now()/1000, interval = 180): Health {
  if (server.networkOffline) return 'unknown';
  const states = [...(server.services ?? []).map(s => s.status), server.checkStatus, server.logStatus];
  const known = (server.vulnerabilities?.affected ?? 0) > 0 || states.includes('critical') ? 'critical'
    : states.includes('warning') ? 'warning' : 'unknown';
  if (server.awaitingFirstCheck || server.monitoring?.enabled === false) return known;
  if (server.lastError) return 'unreachable';
  const o = server.observation;
  if (!o) return known;
  interval = server.monitoring?.intervalSeconds ?? interval;
  if (now-o.at > interval*2+30) return 'stale';
  const values = [o.cpuPercent, o.memoryPercent, ...o.disks.map(d=>d.usedPercent)].filter((v): v is number => v !== null);
  if (known === 'critical' || values.some(v=>v>=97)) return 'critical';
  if (known === 'warning' || values.some(v=>v>=90) || o.services.some(s=>s.state==='failed')) return 'warning';
  return hasCoreMetrics(o) ? 'healthy' : 'unknown';
}
export function percent(value: number | null | undefined): string { return value==null ? '—' : `${Math.round(value)}%`; }
