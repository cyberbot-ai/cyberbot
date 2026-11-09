import type { InjectionKey } from 'vue';
import type { ActionRequest, ActivityEvent, Endpoint, Server } from './types';

export type ServerIdentity = Pick<Server, 'id' | 'name'> & {
  endpoint: Pick<Endpoint, 'host' | 'user' | 'port' | 'jumpHost'>;
};
export type ServerReference = { id?: string | null; address?: string | null; name?: string | null };
export type ServerSection = 'incidents';

const dnsLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export function serverDisplayHost(name: string | null | undefined, host: string) {
  if (!name || name === host || !name.includes('.')) return host;
  const labels = name.replace(/\.$/, '').split('.');
  const suffix = labels[labels.length - 1];
  return labels.length > 1 && /[a-z]/i.test(suffix) && labels.every(label => dnsLabel.test(label)) ? name : host;
}

export function serverAddress({ host, user, port, jumpHost }: ServerIdentity['endpoint']) {
  return `${user ? user + '@' : ''}${host.includes(':') ? '[' + host + ']' : host}:${port}${jumpHost ? ' via ' + jumpHost : ''}`;
}

export function serverHint(server: ServerIdentity) {
  return serverLabel({}, server).hint;
}

export function isInternalId(value: string) {
  return /^(?:[0-9a-f]{24}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$/i.test(value);
}

function parseAddress(address: string) {
  const match = /^(?:[^@\s]+@)?(?:\[([^\]\s]+)\]|([^:@\s]+)):(\d{1,5})(?: via .+)?$/.exec(address);
  const host = match?.[1] ?? match?.[2];
  if (!host || isInternalId(host) || Number(match?.[3]) < 1 || Number(match?.[3]) > 65535) return undefined;
  return host;
}

export function serverDirectory(servers: ServerIdentity[]) {
  const byId = new Map(servers.map(server => [server.id, server]));
  const byAddress = new Map<string, ServerIdentity | null>();
  for (const server of byId.values()) {
    const address = serverAddress(server.endpoint);
    byAddress.set(address, byAddress.has(address) ? null : server);
  }
  return {
    byId,
    resolve({ id, address }: ServerReference) {
      return id ? byId.get(id) : address ? byAddress.get(address) ?? undefined : undefined;
    },
  };
}

export const serverDirectoryKey: InjectionKey<{
  current: () => ReturnType<typeof serverDirectory>;
  open: (id: string, section?: ServerSection) => void | Promise<void>;
}> = Symbol('server directory');

export function serverLabel(reference: ServerReference, server?: ServerIdentity) {
  const recordedHost = reference.address && parseAddress(reference.address);
  const name = server?.name ?? (reference.name && !isInternalId(reference.name) ? reference.name : undefined);
  const connectionHost = server?.endpoint.host || recordedHost;
  const host = serverDisplayHost(name, connectionHost || 'Server unavailable');
  const address = server ? serverAddress(server.endpoint) : recordedHost && reference.address;
  const hint = [name === connectionHost ? undefined : name, address].filter(Boolean).join(' · ');
  return { host, hint };
}

export function activityServerReference(event: ActivityEvent, directory?: ReturnType<typeof serverDirectory>): ServerReference | undefined {
  const { target, server, monitoring } = event;
  const id = monitoring?.serverId || server?.id || (target && directory?.byId.has(target) ? target : undefined);
  const serverEvent = event.category === 'ssh' || event.category === 'server' || !!event.aiAction;
  if (id || server || (target && serverEvent && (isInternalId(target) || parseAddress(target)))) {
    return {
      id: id || (target && isInternalId(target) ? target : undefined),
      address: server?.address || (target && parseAddress(target) ? target : undefined),
      name: server?.name,
    };
  }
  return undefined;
}

function capturedAddress(value?: string) {
  if (!value) return undefined;
  try {
    const { host, user, port, jumpHost } = JSON.parse(value);
    if (typeof host === 'string' && host && typeof user === 'string' && Number.isInteger(port)) {
      return serverAddress({ host, user, port, jumpHost: typeof jumpHost === 'string' ? jumpHost : null });
    }
  } catch {
    // Older or malformed records may have only the server ID.
  }
}

export function capturedActionServers(request?: ActionRequest) {
  if (!request) return [];
  const { name } = actionLabelReference(request.serverLabel);
  return Object.entries(request.artifact.scopeEndpoints ?? {}).map(([id, value]) => ({
    id, name: id === request.serverId ? name : undefined, address: capturedAddress(value),
  }));
}

export function actionLabelReference(label: string): Pick<ServerReference, 'name' | 'address'> {
  const separator = label.lastIndexOf(' · ');
  const address = separator < 0 ? label : label.slice(separator + 3);
  if (!parseAddress(address)) return {};
  return { address, name: separator < 0 ? undefined : label.slice(0, separator) };
}

export function actionRequestReference(request?: ActionRequest): ServerReference {
  if (!request) return {};
  const recorded = actionLabelReference(request.serverLabel);
  const address = capturedAddress(request.artifact.endpoint)
    ?? capturedAddress(request.artifact.scopeEndpoints?.[request.serverId])
    ?? recorded.address;
  return { id: request.serverId, name: recorded.name, address };
}
