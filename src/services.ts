import catalog from '../collectors/connectors/catalog.json';
import type { ConnectorSpec, Health, Server, ServiceAvailability, ServiceCard } from './types';

export const serviceCatalog: Record<string, ConnectorSpec> = catalog;

const reportedStates = ['critical', 'warning', 'healthy'];
// A systemd unit alone cannot identify a particular instance of a multi-instance connector.
const singleServiceUnits = new Map<string, string>();
for (const [kind, spec] of Object.entries(serviceCatalog)) {
  if (spec.multiple) continue;
  for (const alias of spec.units ?? []) singleServiceUnits.set(`${alias}.service`, kind);
}

export const serviceAvailabilityLabels: Record<ServiceAvailability, string> = {
  running: 'Running',
  stopped: 'Stopped',
  unknown: 'Status unknown',
};

export function isServiceDetected(service: ServiceCard): boolean {
  return service.detected ?? (service.at != null && reportedStates.includes(service.status));
}

type DashboardConnector = Pick<ServiceCard, 'kind' | 'instanceId' | 'name' | 'status' | 'availability' | 'metric'> & {
  state: string;
  unitFailure?: string;
};

export function dashboardConnectors(server: Server, health: Health): DashboardConnector[] {
  const cards = (server.services ?? []).filter(isServiceDetected)
    .map<DashboardConnector>(card => ({ ...card, state: card.status }));
  // Only these health states can include a failure from the current OS observation.
  if (server.awaitingFirstCheck || server.monitoring?.enabled === false ||
      (health !== 'warning' && health !== 'critical')) return cards;

  for (const unit of server.observation?.services ?? []) {
    if (unit.state !== 'failed') continue;
    const kind = singleServiceUnits.get(unit.name);
    if (!kind) continue;

    const unitFailure = `Systemd service error (${unit.name})`;
    const card = cards.find(card => card.kind === kind);
    if (card) {
      if (card.state !== 'critical') card.state = 'warning';
      card.unitFailure ??= unitFailure;
    } else {
      cards.push({ kind, name: serviceCatalog[kind].name, status: 'unknown', state: 'warning', unitFailure });
    }
  }
  return cards;
}

export function hideServiceUnit(name: string, detected: ReadonlySet<string>): boolean {
  const unit = name.replace(/\.service$/, '');
  return Object.entries(serviceCatalog).some(([kind, spec]) => {
    const aliases = spec.units ?? [kind];
    if (spec.reportsAvailability) return aliases.includes(unit);
    return (spec.hideUnits || detected.has(kind)) && aliases.some(alias => unit === alias ||
      unit.startsWith(alias + '@') || unit.startsWith(alias + '-') || unit.startsWith(alias + '.'));
  });
}

export function servicePriority(status: string): number {
  const rank = reportedStates.indexOf(status);
  return rank === -1 ? reportedStates.length : rank;
}
