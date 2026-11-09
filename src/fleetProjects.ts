import { getDomain } from 'tldts';
import type { Server, Source } from './types';

function hostnameDomain(host: string) {
  if (/[\s/@?#]/.test(host)) return null;
  return getDomain(host, { allowPrivateDomains: true });
}

export function groupFleetProjects(ordered: Server[], sources: Source[]) {
  const inventories = new Map(sources.filter(source => source.kind === 'ansible').map(source => [source.id, source]));
  const ungrouped: Server[] = [];
  const groups = new Map<string, { title: string; servers: Server[] }>();
  for (const server of ordered) {
    const source = inventories.get(server.sourceId);
    if (!source) {
      ungrouped.push(server);
      continue;
    }

    const domain = hostnameDomain(server.endpoint.host) ?? hostnameDomain(server.name);
    const key = JSON.stringify([source.id, domain]);
    let group = groups.get(key);
    if (!group) {
      const directory = source.location.split('/').filter(Boolean).at(-2);
      group = { title: domain ?? (directory || source.name || 'Ansible inventory'), servers: [] };
      groups.set(key, group);
    }
    group.servers.push(server);
  }

  const servers = [...ungrouped];
  const projectStarts = new Map<string, string>();
  for (const group of groups.values()) {
    projectStarts.set(group.servers[0].id, group.title);
    for (const server of group.servers) servers.push(server);
  }
  return { servers, projectStarts };
}
