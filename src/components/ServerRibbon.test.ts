// @vitest-environment happy-dom
import { mount } from '@vue/test-utils';
import { describe, it, expect } from 'vitest';
import ServerRibbon from './ServerRibbon.vue';
import ServerCard from './ServerCard.vue';
import type { Server } from '../types';

const base: Server = { id: 'a', sourceId: 's', name: 'web-01', endpoint: { host: '10.0.0.1', user: 'ops', port: 22, identityFile: null, jumpHost: null }, observation: { at: 1000, cpuPercent: 15, memoryPercent: 60, swapPercent: 0, load: 1.4, uptime: 100, disks: [{ mount: '/', usedPercent: 35, inodePercent: 5 }, { mount: '/data', usedPercent: 98, inodePercent: null }], services: [], missing: [], bytesReceived: 100, durationMs: 20 }, lastError: null, lastAttempt: 1000, nextCheck: 1180, failures: 0 };
const render = (server: Server = base, now = 1000) => mount(ServerRibbon, { props: { server, now, interval: 180 } });

describe('server ribbon', () => {
  it('abbreviates extreme LA and RPS while retaining their exact values', () => {
    const value=12884901888.5;
    const row=render({...base,observation:{...base.observation!,load:value},services:[{kind:'nginx',name:'Nginx',detected:true,status:'healthy',metric:{value,unit:'rps'},at:1000}]});
    const load=row.get('[data-metric="load"]');
    expect(load.text()).toBe('LA12.9B');
    expect(load.attributes('title')).toBe('Load average per minute: 12884901888.5');
    expect(load.attributes('aria-label')).toBe('Load average per minute: 12884901888.5');
    expect(row.get('[data-service="nginx:default"]').text()).toBe('Nginx12.9B rps');
    expect(row.get('[data-service="nginx:default"]').attributes('title')).toContain('12884901888.5 rps');
    expect(row.get('[data-service="nginx:default"]').classes()).toContain('with-value');
    row.unmount();
  });
  it('does not expose invalid numbers or cached measurements in tooltips', () => {
    const row=render({...base,observation:{...base.observation!,load:NaN}});
    expect(row.get('[data-metric="load"]').text()).toBe('LA—');
    expect(row.get('[data-metric="load"]').classes()).toContain('unknown');row.unmount();
    const stale=render({...base,observation:{...base.observation!,load:12884901888.5}},2000);
    expect(stale.get('[data-metric="load"]').attributes('title')).not.toContain('12884901888.5');stale.unmount();
  });
  it('centres real resource indicators and highlights the failing disk independently', async () => {
    const row = render();
    expect(row.classes()).toContain('critical');
    expect(row.get('[data-metric="cpu"]').text()).toBe('CPU15%');
    expect(row.get('[data-metric="load"]').text()).toBe('LA1.4');
    expect(row.get('[data-metric="disk:/data"]').classes()).toContain('critical');
    expect(row.get('[data-metric="cpu"]').classes()).toContain('healthy');
    expect(row.text()).not.toMatch(/backwards|Critical|deviation/);
    await row.trigger('click');
    expect(row.emitted('select')?.[0]).toEqual([base]);
  });
  it('uses a healthy green row for complete normal observations, unknown for missing data', () => {
    const normal = { ...base, observation: { ...base.observation!, disks: [base.observation!.disks[0]] } };
    expect(render(normal).classes()).toContain('healthy');
    const unknown = render({ ...normal, observation: { ...normal.observation!, cpuPercent: null, missing: ['cpu'] } });
    expect(unknown.classes()).toContain('unknown');
    expect(unknown.get('[data-metric="cpu"]').text()).toContain('—');
    expect(unknown.get('.coverage').attributes('title')).toContain('cpu');
  });
  it('red stale and failed rows hide cached measurements without claiming proven offline', () => {
    const stale = render(base, 2000);
    expect(stale.classes()).toContain('stale');
    expect(stale.get('[data-metric="cpu"]').text()).toBe('CPU—');
    expect(stale.attributes('title')).toContain('server availability unconfirmed');
    const failed = render({ ...base, lastError: 'SSH: connection rejected' });
    expect(failed.classes()).toContain('unreachable');
    expect(failed.attributes('title')).toContain('SSH: connection rejected');
    expect(failed.get('[data-metric="disk:/data"]').text()).toBe('/data—');
  });
  it('lists only detected services, with active services before unknown ones', async () => {
    const server: Server = { ...base, services: [
      { kind: 'mysql', name: 'MySQL · Basic', status: 'unknown', at: 1000, detected: false },
      { kind: 'mongodb', name: 'MongoDB', status: 'unknown', at: 1000 },
      { kind: 'redis', instanceId: 'report', name: 'Redis · Report', status: 'unknown', at: 1000, detected: true },
      { kind: 'redis', instanceId: 'unverified', name: 'Redis · Unverified', status: 'unknown', at: null, detected: false },
      { kind: 'redis', instanceId: 'cache', name: 'Redis · Cache', status: 'healthy', at: 1000 },
      { kind: 'redis', instanceId: 'queue', name: 'Redis · Queue', status: 'critical', at: 1000 },
      { kind: 'docker', name: 'Docker', status: 'healthy', at: 1000 },
      { kind: 'postgresql', name: 'PostgreSQL', status: 'unknown', at: 1000, detected: false },
    ], observation: { ...base.observation!, services: [{ name: 'nginx.service', state: 'active' }, { name: 'postgresql.service', state: 'active' }] } };
    const row = render(server);
    const names = () => row.findAll('.service').map(chip => chip.text());
    expect(names()).toEqual(['Redis · Queue', 'Redis · Cache', 'Docker', 'nginx', 'Redis · Report']);
    expect(row.get('[data-service="redis:queue"]').classes()).toContain('critical');

    await row.setProps({server: {...server, services: server.services!.map(service =>
      service.kind === 'postgresql' ? {...service, status: 'healthy', detected: true} : service,
    )}});
    expect(names()).toEqual(['Redis · Queue', 'Redis · Cache', 'Docker', 'PostgreSQL', 'nginx', 'Redis · Report']);
    row.unmount();
  });
  it('deduplicates discovery and Nginx diagnostics while keeping available RPS', () => {
    const server = { ...base, services: [{ kind: 'nginx', instanceId: 'default', name: 'Nginx · Basic', status: 'healthy', metric: {value:120.4,unit:'rps'}, at: 1000 }], observation: { ...base.observation!, services: [{ name: 'nginx.service', state: 'active' }, { name: 'sshd.service', state: 'active' }] } };
    const row = render(server);
    expect(row.findAll('.service')).toHaveLength(2);
    expect(row.get('[data-service="nginx:default"]').text()).toContain('120.4 rps');
    expect(render(server, 2000).text()).not.toContain('120.4');
    expect(render({ ...server, services: [{ ...server.services[0], status: 'stale' }] }).text()).not.toContain('120.4');
  });
});

it('highlights the failed Fail2ban service alongside a neutral running Twemproxy', async () => {
  const server: Server = {
    ...base,
    observation: {
      ...base.observation!,
      disks: [base.observation!.disks[0]],
      services: [{name: 'fail2ban.service', state: 'failed'}, {name: 'nutcracker.service', state: 'active'}],
    },
    services: [{kind: 'twemproxy', name: 'Twemproxy', detected: true, availability: 'running', status: 'unknown', at: 1000}],
  };
  const ribbon = render(server);
  const tile = mount(ServerCard, {props: {server, now: 1000, interval: 180}});
  const fail2ban = () => ribbon.get('[data-service="fail2ban:default"]');
  const tileFailure = () => tile.get('.services span[title*="fail2ban.service"]');
  expect(ribbon.classes()).toContain('warning');
  expect(tile.classes()).toContain('warning');
  expect(fail2ban().text()).toBe('Fail2ban');
  expect(fail2ban().classes()).toContain('warning');
  expect(fail2ban().attributes('title')).toContain('service error');
  expect(tileFailure().classes()).toContain('warning');

  const updated: Server = {
    ...server,
    services: [...server.services!, {kind: 'fail2ban', name: 'Fail2ban', detected: true, availability: 'stopped', status: 'unknown', at: 1000}],
  };
  await ribbon.setProps({server: updated});
  await tile.setProps({server: updated});
  expect(ribbon.findAll('.service').map(chip => chip.text())).toEqual(['Fail2banStopped', 'TwemproxyRunning']);
  expect(fail2ban().classes()).toContain('warning');
  expect(fail2ban().attributes('title')).toContain('fail2ban.service');
  expect(ribbon.get('[data-service="twemproxy:default"]').classes()).toContain('unknown');
  expect(tileFailure().classes()).toContain('warning');
  expect(tileFailure().attributes('title')).toContain('Stopped');

  await ribbon.setProps({now: 2000});
  await tile.setProps({now: 2000});
  expect(ribbon.classes()).toContain('stale');
  expect(fail2ban().classes()).not.toContain('warning');
  expect(tile.find('.services .warning').exists()).toBe(false);

  const recovered = {
    ...updated,
    observation: {...server.observation!, services: [{name: 'fail2ban.service', state: 'active'}]},
    services: updated.services!.map(card => card.kind === 'fail2ban' ? {...card, availability: 'running' as const} : card),
  };
  await ribbon.setProps({server: recovered, now: 1000});
  await tile.setProps({server: recovered, now: 1000});
  expect(ribbon.classes()).toContain('healthy');
  expect(fail2ban().text()).toBe('Fail2banRunning');
  expect(fail2ban().classes()).not.toContain('warning');
  expect(tile.find('.services .warning').exists()).toBe(false);
  ribbon.unmount();
  tile.unmount();
});

it('does not attribute another unit failure to Fail2ban or treat an inactive unit as failed', async () => {
  const server: Server = {
    ...base,
    observation: {...base.observation!, disks: [base.observation!.disks[0]], services: [
      {name: 'fail2ban.service', state: 'inactive'}, {name: 'fail2ban-exporter.service', state: 'failed'},
    ]},
    services: [{kind: 'fail2ban', name: 'Fail2ban', detected: true, availability: 'stopped', status: 'unknown', at: 1000}],
  };
  const ribbon = render(server);
  expect(ribbon.classes()).toContain('warning');
  expect(ribbon.get('[data-service="systemd:fail2ban-exporter.service"]').classes()).toContain('critical');
  const fail2ban = ribbon.get('[data-service="fail2ban:default"]');
  expect(fail2ban.classes()).toContain('unknown');
  expect(fail2ban.text()).toBe('Fail2banStopped');

  await ribbon.setProps({server: {...server, observation: {...server.observation!, services: [{name: 'fail2ban.service', state: 'inactive'}]}}});
  expect(ribbon.classes()).toContain('healthy');
  expect(fail2ban.classes()).toContain('unknown');
  ribbon.unmount();
});

it('keeps critical diagnostics above the systemd warning for the same service', () => {
  const ribbon = render({
    ...base,
    observation: {...base.observation!, services: [{name: 'nginx.service', state: 'failed'}]},
    services: [{kind: 'nginx', name: 'Nginx', status: 'critical', at: 1000}],
  });
  const chip = ribbon.get('[data-service="nginx:default"]');
  expect(chip.classes()).toContain('critical');
  expect(chip.attributes('title')).toContain('nginx.service');
  expect(ribbon.findAll('.service')).toHaveLength(1);
  ribbon.unmount();
});

it('shows confirmed service problems while hiding cached resource measurements before the first check',async()=>{
 const row=render({...base,awaitingFirstCheck:true,lastError:'old SSH failure',services:[{kind:'redis',name:'Redis',status:'critical',at:1000},{kind:'nginx',name:'Nginx',detected:true,status:'healthy',metric:{value:123,unit:'rps'},at:1000}]},10000);
 expect(row.classes()).toContain('critical');
 expect(row.attributes('aria-label')).toContain('Critical · awaits a metric survey');
 expect(row.attributes('title')).not.toContain('old SSH failure');
 expect(row.get('[data-service="redis:default"]').classes()).toContain('critical');
 expect(row.get('[data-service="nginx:default"]').classes()).toContain('unknown');
 expect(row.get('[data-metric="cpu"]').text()).toBe('CPU—');
 expect(row.text()).not.toContain('123');
 await row.setProps({server:{...base,awaitingFirstCheck:false,lastError:'new SSH failure'}});
 expect(row.classes()).toContain('unreachable');
 row.unmount();
});
