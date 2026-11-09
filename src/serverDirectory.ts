import type { InjectionKey } from 'vue';
import type { ActionRequest, ActivityEvent, Endpoint, Server } from './types';

export type ServerIdentity = Pick<Server, 'id' | 'name'> & {
  endpoint: Pick<Endpoint, 'host' | 'user' | 'port' | 'jumpHost'>;
};
export type ServerReference = { id?: string | null; address?: string | null; name?: string | null };
export type ServerSection = 'incidents';

export function serverAddress({ host, user, port, jumpHost }: ServerIdentity['endpoint']) {
  return `${user ? user + '@' : ''}${host.includes(':') ? '[' + host + ']' : host}:${port}${jumpHost ? ' via ' + jumpHost : ''}`;
}

export function serverHint(server: ServerIdentity) {
  const { host } = server.endpoint;
  return [server.name === host ? '' : server.name, serverAddress(server.endpoint)].filter(Boolean).join(' · ');
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
  const host = server?.endpoint.host || (reference.address && parseAddress(reference.address)) || 'Server unavailable';
  const hint = server ? serverHint(server) : [reference.name && !isInternalId(reference.name) ? reference.name : '', host !== 'Server unavailable' ? reference.address : ''].filter(Boolean).join(' · ');
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

export function capturedActionServers(endpoints: Record<string, string>) {
  return Object.entries(endpoints).map(([id, value]) => ({ id, address: capturedAddress(value) }));
}

export function actionLabelAddress(label: string) {
  const separator = label.lastIndexOf(' · ');
  const address = separator < 0 ? label : label.slice(separator + 3);
  return parseAddress(address) ? address : undefined;
}

export function actionRequestAddress(request?: ActionRequest) {
  if (!request) return undefined;
  return capturedAddress(request.artifact.endpoint)
    ?? capturedAddress(request.artifact.scopeEndpoints?.[request.serverId])
    ?? actionLabelAddress(request.serverLabel);
}
