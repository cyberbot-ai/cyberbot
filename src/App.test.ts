// @vitest-environment happy-dom
import { mount, flushPromises } from '@vue/test-utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App.vue';
import FleetList from './components/FleetList.vue';
import AutomationMode from './components/AutomationMode.vue';
import { appearanceKey } from './appearance';
import { cliChecksKey } from './aiNavigation';
import { listen } from '@tauri-apps/api/event';
import type { Incident, LogView, Observation, Server, ServiceCard, Settings } from './types';

const apiState = vi.hoisted(()=>({preview:true}));
vi.mock('./api', () => ({ get preview(){return apiState.preview;}, call: vi.fn() }));
vi.mock('@tauri-apps/api/event',()=>({listen:vi.fn(async()=>vi.fn())}));
import { call } from './api';

describe('fleet ribbon integration', () => {
  afterEach(() => { apiState.preview=true; localStorage.removeItem(cliChecksKey); vi.unstubAllGlobals(); vi.clearAllMocks(); vi.useRealTimers(); });
  it('shows the offline notice and hides cached live values in the fleet and server overview', async () => {
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
    const at = Date.now() / 1000;
    const server: Server = {
      id:'node', name:'node', sourceId:'fixture',
      endpoint:{host:'node.invalid',user:'ops',port:22,identityFile:null,jumpHost:null},
      observation:{at,cpuPercent:98,memoryPercent:20,swapPercent:0,load:4,uptime:100,
        disks:[{mount:'/',usedPercent:35,inodePercent:1}],services:[],missing:[],bytesReceived:100,durationMs:10},
      lastError:'SSH: timeout', lastAttempt:at, nextCheck:at+180, failures:2,
    };
    vi.mocked(call).mockImplementation(async command => command === 'snapshot' ? {
      offline:true, servers:[server], sources:[], incidents:[], logStatus:{node:'critical'},
      settings:{mode:'manual',dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false},
      collectedAt:at,
    } : command === 'history' ? [] : {});
    const app = mount(App,{attachTo:document.body});
    await flushPromises();
    expect(app.get('main .connectivity-notice').text()).toContain('No internet connection');
    expect(app.get('.ribbon.unknown').attributes('aria-label')).toContain('No data');
    expect(app.get('[data-metric="cpu"]').text()).toBe('CPU—');
    expect(app.get('.ribbon').find('.service').exists()).toBe(false);
    await app.get('.ribbon').trigger('click');
    await flushPromises();
    expect(app.get('.detail .connectivity-notice').text()).toContain('No internet connection');
    expect(app.get('.detail .state').text()).toBe('No data');
    expect(app.get('.detail .metrics').text()).not.toContain('98%');
    expect(app.find('.detail .alert').exists()).toBe(false);
    app.unmount();
  });
  it('refreshes during a burst of events and queues just one read while IPC is busy', async () => {
    vi.useFakeTimers();
    apiState.preview = false;
    let changed!: () => void;
    vi.mocked(listen).mockImplementation(async (name, handler) => {
      if (name === 'state-changed') changed = () => handler({ event: name, id: 0, payload: undefined as never });
      return vi.fn();
    });
    const snapshot = () => vi.mocked(call).mock.calls.filter(([command]) => command === 'snapshot');
    vi.mocked(call).mockResolvedValue(undefined);
    const app = mount(App);
    try {
      await flushPromises();
      expect(snapshot()).toHaveLength(1);
      let finish!: () => void;
      vi.mocked(call).mockImplementation(async (command) => {
        if (command === 'snapshot' && snapshot().length === 2) {
          await new Promise<void>(resolve => { finish = resolve; });
        }
        return undefined as never;
      });
      for (let i = 0; i < 8; i++) {
        changed();
        await vi.advanceTimersByTimeAsync(200);
      }
      expect(snapshot()).toHaveLength(2);
      finish();
      await flushPromises();
      expect(snapshot()).toHaveLength(3);
      await vi.advanceTimersByTimeAsync(500);
      expect(snapshot()).toHaveLength(3);
    } finally {
      app.unmount();
      vi.mocked(listen).mockImplementation(async () => vi.fn());
    }
  });
  it('cycles the sidebar theme without leaving the current page', async () => {
    const previous = localStorage.getItem(appearanceKey);
    const appearance = { mode: 'auto', nightStart: '21:00', nightEnd: '08:00' };
    localStorage.setItem(appearanceKey, JSON.stringify(appearance));
    vi.mocked(call).mockResolvedValue(undefined);
    const app = mount(App);
    try {
      await flushPromises();
      await app.get('.console-link').trigger('click');
      for (const mode of ['light', 'dark', 'auto']) {
        await app.get('.theme-shortcut').trigger('click');
        expect(app.get('h1').text()).toBe('Console');
        expect(JSON.parse(localStorage.getItem(appearanceKey)!)).toEqual({ ...appearance, mode });
        if (mode !== 'auto') expect(app.get('.app').attributes('data-theme')).toBe(mode);
      }
    } finally {
      app.unmount();
      if (previous === null) localStorage.removeItem(appearanceKey);
      else localStorage.setItem(appearanceKey, previous);
    }
  });
  it('defaults to the ribbon, puts stale data in problems and preserves search and view switching', async () => {
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
    const now = Date.now()/1000;
    const server = (id: string, at: number): Server => ({ id, name: id, sourceId: 's', endpoint: {host:id,user:'ops',port:22,identityFile:null,jumpHost:null}, observation: {at,cpuPercent:10,memoryPercent:20,swapPercent:0,load:0.4,uptime:100,disks:[{mount:'/',usedPercent:30,inodePercent:1}],services:[],missing:[],bytesReceived:100,durationMs:10},lastError:null,lastAttempt:at,nextCheck:0,failures:0,...{project:'legacy-project',groups:['legacy-tag']} });
    vi.mocked(call).mockImplementation(async command => command === 'snapshot' ? {
      servers: [server('current', now), server('stale', now - 1000), {...server('new',now),observation:null}, server('partial', now)],
      sources: [], incidents: [], nginx: {}, logStatus: {current:'healthy',stale:'healthy',new:'unknown',partial:'healthy'},
      vulnerabilities: {partial:{status:'unknown',affected:0,critical:0,at:now}},
      settings:{mode:'manual',dailyTokenLimit:null,dailyRunLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,paused:false,concurrency:4},collectedAt:now,
    } : {});
    const app = mount(App, {attachTo:document.body});
    await flushPromises();
    expect(app.find('[aria-label="Project"]').exists()).toBe(false);
    const fleetList = () => app.getComponent(FleetList);
    const modeControl = app.getComponent(AutomationMode);
    expect(modeControl.props('compact')).toBe(true);
    expect(modeControl.get('[role="switch"]').attributes('aria-checked')).toBe('false');
    expect(modeControl.get('[role="switch"]').text()).toBe('AI');
    expect(app.get('.sidebar .monitor-full').text()).toBe('Polling every 3 min');
    expect(app.find('.bottom-bar').exists()).toBe(false);
    expect(app.text()).not.toContain('Locally');
    expect(app.find('.mode-link').exists()).toBe(false);
    const attention = app.findAll('.fleet-filters button').find(b => b.text().startsWith('Needs attention'))!;
    await attention.trigger('click');
    expect(fleetList().props('servers').map((s:Server)=>s.id)).toEqual(['stale']);
    await app.findAll('.fleet-filters button').find(b => b.text().startsWith('Insufficient data'))!.trigger('click');
    expect(fleetList().props('servers').map((s:Server)=>s.id)).toEqual(['new']);
    await app.findAll('.fleet-filters button').find(b => b.text().startsWith('Healthy'))!.trigger('click');
    expect(fleetList().props('servers').map((s:Server)=>s.id)).toEqual(['current','partial']);
    await app.findAll('.fleet-filters button')[0].trigger('click');
    expect(app.find('input[aria-label="Search servers"]').exists()).toBe(false);
    expect(app.get('.head-actions .primary').text()).toBe('Add server');
    await app.get('button[aria-label="Search servers"]').trigger('click');
    const search = app.get('input[aria-label="Search servers"]');
    expect(document.activeElement).toBe(search.element);
    await search.setValue('legacy-tag');
    expect(app.findComponent(FleetList).exists()).toBe(false);
    await search.setValue('legacy-project');
    expect(app.findComponent(FleetList).exists()).toBe(false);
    await search.setValue('current');
    expect(fleetList().props('servers').map((s:Server)=>s.id)).toEqual(['current']);
    await search.trigger('keydown',{key:'Escape'});
    expect(app.find('input[aria-label="Search servers"]').exists()).toBe(false);
    expect(fleetList().props('servers')).toHaveLength(4);
    expect(document.activeElement).toBe(app.get('button[aria-label="Search servers"]').element);
    await app.get('button[aria-label="Search servers"]').trigger('click');
    await app.get('input[aria-label="Search servers"]').setValue('stale');
    await app.get('button[aria-label="Close search"]').trigger('click');
    expect(fleetList().props('servers')).toHaveLength(4);
    app.unmount();
  });
  it('keeps a failed manual poll in the server details and clears it after recovery', async () => {
    apiState.preview = false;
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
    const now = Date.now() / 1000;
    const observation: Observation = {
      at: now - 1000, cpuPercent: 0, memoryPercent: 10, swapPercent: 0, load: 0.02, uptime: 1000,
      disks: [{ mount: '/', usedPercent: 7, inodePercent: 1 }], services: [], missing: [], bytesReceived: 100, durationMs: 10,
    };
    const server: Server = {
      id: 'vpn', name: 'VPN', sourceId: 's',
      endpoint: { host: 'vpn.invalid', user: 'root', port: 22, identityFile: null, jumpHost: null },
      observation, lastError: null, lastAttempt: observation.at, nextCheck: 0, failures: 0,
    };
    const settings: Settings = {mode:'manual',dailyTokenLimit:0,dailyRunLimit:0,runTokenLimit:0,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,paused:false,concurrency:4, dockBadgeEnabled: true};
    const logs: LogView = {
      fresh: true, shortCheck: false, lastIncomplete: null, lastSuccess: now, nextCheck: now + 600, error: null,
      summary: {
        id: 'logs', at: now, remoteAt: now, windowSeconds: 600,
        coverage: { complete: false, initial: false, sources: ['auth'], gaps: [{ reason: 'source_unavailable', source: 'syslog' }] },
        counts: {}, examples: [], findings: [], learning: true, bytesRead: 100, bytesReceived: 100, durationMs: 10,
      },
    };
    const failure = 'Checking the SSH connection: Resource temporarily unavailable';
    let failPoll: () => void = () => { throw new Error('No poll in progress'); };
    vi.mocked(call).mockImplementation(async command => {
      if (command === 'poll_server') {
        if (!server.lastError) {
          return new Promise((_resolve, reject) => {
            failPoll = () => {
              server.lastError = failure;
              reject(new Error(failure));
            };
          });
        }
        observation.at = now;
        server.lastError = null;
        return { updated: 4, failed: [] };
      }
      if (command === 'history') return [];
      if (command === 'log_summary') return logs;
      if (command === 'snapshot') return {
        servers: [{ ...server, observation: { ...observation } }], sources: [], incidents: [], nginx: {},
        logStatus: { vpn: 'unknown' }, vulnerabilities: { vpn: { status: 'unknown', affected: 0, critical: 0, at: null } },
        settings, collectedAt: now,
      };
      return {};
    });
    const app = mount(App, { attachTo: document.body });
    await flushPromises();
    await app.get('button.ribbon.stale').trigger('click');
    await flushPromises();
    const refresh = () => app.findAll('.detail-dialog button').find(button => button.text() === 'Refresh server')!;
    await refresh().trigger('click');
    await flushPromises();
    expect(app.get('.detail-dialog button[aria-busy="true"]').text()).toBe('Refreshing…');
    expect(app.find('.detail-dialog [role="alert"]').exists()).toBe(false);
    failPoll();
    await flushPromises();
    expect(app.findAll('.detail-dialog [role="alert"]').map(alert => alert.text())).toEqual([failure]);
    expect(app.find('main > .error').exists()).toBe(false);
    await refresh().trigger('click');
    await flushPromises();
    expect(call).toHaveBeenCalledWith('poll_server', { id: 'vpn' });
    expect(app.find('.detail-dialog [role="alert"]').exists()).toBe(false);
    expect(app.get('.detail-dialog .status.healthy .state').text()).toBe('Healthy');
    expect(app.get('button.ribbon.healthy').text()).toContain('Logs');
    await app.findAll('.detail-dialog .detail-tabs button').find(button => button.text() === 'Logs')!.trigger('click');
    await flushPromises();
    expect(app.get('.detail-dialog .logs .meta .tag.ok').text()).toBe('No issues found');
    expect(app.get('.detail-dialog .logs').text()).toContain('Log source unavailable');
    await app.get('[aria-label="Close server"]').trigger('click');
    await app.findAll('.fleet-filters button').find(button => button.text().startsWith('Healthy'))!.trigger('click');
    app.unmount();
  });
  it('shows a confirmed Fail2ban stop in the fleet and server details until a poll confirms recovery', async () => {
    apiState.preview = false;
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
    const at = Date.now() / 1000;
    const server: Server = {
      id: 'node', name: 'node', sourceId: 'fixture',
      endpoint: { host: 'node.invalid', user: 'ops', port: 22, identityFile: null, jumpHost: null },
      observation: {
        at, cpuPercent: 10, memoryPercent: 20, swapPercent: 0, load: 0.4, uptime: 100,
        disks: [{ mount: '/', usedPercent: 30, inodePercent: 1 }],
        services: [{ name: 'fail2ban.service', state: 'inactive' }], missing: [], bytesReceived: 100, durationMs: 10,
      },
      lastError: null, lastAttempt: at, nextCheck: at + 180, failures: 0,
    };
    const settings: Settings = {
      mode: 'manual', dailyTokenLimit: null, dailyRunLimit: null, runTokenLimit: 50000, autoAgent: 'codex',
      pollSeconds: 180, logPollSeconds: 600, paused: false, concurrency: 4, dockBadgeEnabled: true,
    };
    let fail2ban: ServiceCard = { kind: 'fail2ban', name: 'Fail2ban', detected: true, availability: 'stopped', status: 'warning', at };
    vi.mocked(call).mockImplementation(async command => {
      if (command === 'poll_server') {
        fail2ban = { ...fail2ban, availability: 'running', status: 'unknown' };
        return { updated: 2, failed: [] };
      }
      if (command === 'snapshot') return {
        servers: [server], services: { node: [fail2ban] }, sources: [], incidents: [], logStatus: {}, settings, collectedAt: at,
      };
      return command === 'history' ? [] : {};
    });

    const app = mount(App, { attachTo: document.body });
    try {
      await flushPromises();
      const filter = (label: string) => app.findAll('.fleet-filters button').find(button => button.text().startsWith(label))!;
      expect(filter('Needs attention').text()).toBe('Needs attention 1');
      await filter('Needs attention').trigger('click');
      const ribbon = app.get('button.ribbon.warning');
      expect(ribbon.get('[data-service="fail2ban:default"]').text()).toBe('Fail2banStopped');
      await ribbon.trigger('click');
      expect(app.get('.detail-dialog .state').text()).toBe('Needs attention');

      await app.get('.detail-dialog .server-heading button').trigger('click');
      await flushPromises();
      expect(app.get('.detail-dialog .state').text()).toBe('Healthy');
      expect(filter('Needs attention').text()).toBe('Needs attention 0');
      expect(app.find('button.ribbon').exists()).toBe(false);

      await app.get('[aria-label="Close server"]').trigger('click');
      await filter('Healthy').trigger('click');
      expect(app.get('button.ribbon.healthy [data-service="fail2ban:default"]').text()).toBe('Fail2banRunning');
    } finally {
      app.unmount();
    }
  });
  it('sorts the fleet by hostname suffix or metric, including after polling', async () => {
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
    const now = Date.now() / 1000;
    const server = (id: string, host: string, rootUsage: number, dataUsage: number): Server => ({
      id, name: id, sourceId: 'fixture', endpoint: { host, user: 'ops', port: 22, identityFile: null, jumpHost: null },
      observation: {
        at: now, cpuPercent: 10, memoryPercent: 20, swapPercent: 0, load: 0.4, uptime: 100,
        disks: [{ mount: '/', usedPercent: rootUsage, inodePercent: 1 }, { mount: '/data', usedPercent: dataUsage, inodePercent: 2 }],
        services: [], missing: [], bytesReceived: 100, durationMs: 10,
      },
      lastError: null, lastAttempt: now, nextCheck: 0, failures: 0,
    });
    const db = server('db', 's1.db.example.com', 98, 20);
    const app2 = server('app2', 's2.app.example.com', 30, 99);
    const app10 = server('app10', 's10.app.example.com', 70, 10);
    const other = server('other', 'a.app.example.net', 80, 50);
    let nodes = [other, db, app10, app2];
    vi.mocked(call).mockImplementation(async command => command === 'snapshot' ? {
      servers: nodes, sources: [], incidents: [], logStatus: {}, collectedAt: now,
      settings: { mode: 'manual', dailyRunLimit: null, dailyTokenLimit: null, runTokenLimit: 50000, autoAgent: 'codex', pollSeconds: 180, logPollSeconds: 600, paused: false, concurrency: 4 },
    } : {});
    const app = mount(App, { attachTo: document.body });
    try {
      await flushPromises();
      const rowIds = () => app.getComponent(FleetList).findAll('[data-id]').map(row => row.attributes('data-id'));
      const sort = app.get('[aria-label="Sort servers"]');
      const button = (label: string) => sort.findAll('button').find(item => item.text().split(/\s+/)[0] === label)!;
      expect(rowIds()).toEqual(['app2', 'app10', 'db', 'other']);
      expect(button('Host').text()).toContain('↑');
      expect(sort.get('[aria-pressed="true"]').attributes('aria-label')).toBe('Host, ascending');

      await button('Disk').trigger('click');
      expect(rowIds()).toEqual(['app2', 'db', 'other', 'app10']);
      expect(button('Disk').text()).toContain('↓');
      expect(sort.get('[aria-pressed="true"]').attributes('aria-label')).toBe('Disk, descending');
      await button('Disk').trigger('click');
      expect(rowIds()).toEqual(['app10', 'other', 'db', 'app2']);

      await app.get('button[aria-label="Search servers"]').trigger('click');
      await app.get('input[aria-label="Search servers"]').setValue('example.com');
      expect(rowIds()).toEqual(['app10', 'db', 'app2']);
      await app.findAll('.fleet-filters button').find(item => item.text().startsWith('Needs attention'))!.trigger('click');
      expect(rowIds()).toEqual(['db', 'app2']);

      nodes = [other, db, app10, server('app2', app2.endpoint.host, 30, 97)];
      window.dispatchEvent(new Event('focus'));
      await flushPromises();
      expect(rowIds()).toEqual(['app2', 'db']);
      await button('Host').trigger('click');
      expect(sort.get('[aria-pressed="true"]').attributes('aria-label')).toBe('Host, ascending');
      await button('Host').trigger('click');
      expect(rowIds()).toEqual(['db', 'app2']);
    } finally {
      app.unmount();
    }
  });
  it('shows separate domain projects within each inventory and moves the heading when filtering', async () => {
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
    const server = (id: string, host: string, sourceId = 'production', name = host): Server => ({
      id, name, sourceId, endpoint: { host, user: 'ops', port: 22, identityFile: null, jumpHost: null },
      observation: null, lastError: null, lastAttempt: null, nextCheck: 0, failures: 0,
    });
    const servers = [
      server('api', 'api.ops.example.com'),
      server('db', 'ssh.example.net', 'production', 'db.example.com'),
      server('proxy', '192.0.2.7', 'production', 'proxy.example.com'),
      server('uk', 'worker.example.co.uk'),
      server('bare', 'worker'),
      server('ipv6', '2001:db8::10'),
      server('staging', 'metrics.example.com', 'staging'),
      server('manual', 'lab.example.org', 'manual'),
    ];
    const sources = [
      { id: 'production', name: 'hosts.ini', kind: 'ansible', location: '/ops/prod/hosts.ini' },
      { id: 'staging', name: 'hosts.ini', kind: 'ansible', location: '/ops/stage/hosts.ini' },
      { id: 'manual', name: 'Manual list', kind: 'manual', location: 'lab.example.org' },
    ].map(source => ({ ...source, lastSync: null, error: null }));
    vi.mocked(call).mockImplementation(async command => command === 'snapshot' ? {
      servers, sources, incidents: [], logStatus: {}, collectedAt: Date.now() / 1000,
      settings: { mode: 'manual', dailyRunLimit: null, dailyTokenLimit: null, runTokenLimit: 50000, autoAgent: 'codex', pollSeconds: 180, logPollSeconds: 600, paused: false, concurrency: 4 },
    } : command === 'history' ? [] : {});
    const app = mount(App);
    try {
      await flushPromises();
      const rows = () => app.getComponent(FleetList).findAll('[data-id]');
      const projects = () => app.findAll('.ribbon-project').map(heading => heading.text());
      const ids = rows().map(row => row.attributes('data-id'));
      expect([...projects()].sort()).toEqual(['example.co.uk', 'example.com', 'example.com', 'prod']);
      expect(ids.slice(ids.indexOf('db'), ids.indexOf('db') + 3)).toEqual(['db', 'api', 'proxy']);
      expect(app.get('[data-id="db"] .ribbon strong').text()).toBe('db.example.com');
      const proxy = app.get('[data-id="proxy"] .ribbon');
      expect(proxy.get('strong').text()).toBe('proxy.example.com');
      expect(proxy.attributes('aria-label')).toContain('proxy.example.com');
      expect(proxy.attributes('title')).toContain('ops@192.0.2.7:22');
      expect(app.get('[data-id="manual"]').find('h2').exists()).toBe(false);

      await app.get('button[aria-label="Search servers"]').trigger('click');
      await app.get('input[aria-label="Search servers"]').setValue('db.example.com');
      expect(app.get('[data-id="db"] h2').text()).toBe('example.com');
      expect(rows()).toHaveLength(1);

      await app.get('input[aria-label="Search servers"]').setValue('192.0.2.7');
      expect(rows().map(row => row.attributes('data-id'))).toEqual(['proxy']);
      expect(app.get('[data-id="proxy"] h2').text()).toBe('example.com');
      await app.get('[data-id="proxy"] .ribbon').trigger('click');
      await flushPromises();
      expect(app.get('.detail-dialog .server-title h2').text()).toBe('proxy.example.com');
      expect(app.get('.detail-dialog .server-title p').text()).toBe('ops@192.0.2.7:22');
      await app.get('[aria-label="Close server"]').trigger('click');

      await app.get('button[aria-label="Close search"]').trigger('click');
      await app.findAll('.fleet-sort button').find(button => button.text() === 'CPU')!.trigger('click');
      expect(projects()).toEqual([]);
      expect(rows()).toHaveLength(servers.length);
    } finally {
      app.unmount();
    }
  });
  it('updates the attention indicator with the worst fleet state and hides it after recovery',async()=>{
    vi.stubGlobal('ResizeObserver',class{observe(){}unobserve(){}disconnect(){}});
    const now=Date.now()/1000;
    const base:Server={id:'warning',name:'warning',sourceId:'s',endpoint:{host:'web',user:'ops',port:22,identityFile:null,jumpHost:null},observation:{at:now,cpuPercent:92,memoryPercent:20,swapPercent:0,load:0.4,uptime:100,disks:[{mount:'/',usedPercent:30,inodePercent:1}],services:[],missing:[],bytesReceived:100,durationMs:10},lastError:null,lastAttempt:now,nextCheck:0,failures:0};
    let nodes:Server[]=[];
    vi.mocked(call).mockImplementation(async command=>command==='snapshot'?{
      servers:[...nodes],sources:[],incidents:[],nginx:{},logStatus:Object.fromEntries(nodes.map(s=>[s.id,'healthy'])),settings:{mode:'manual',dailyTokenLimit:null,dailyRunLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,paused:false,concurrency:4},collectedAt:now,
    }:{});
    const app=mount(App);await flushPromises();
    const attention=()=>app.findAll('.fleet-filters button').find(b=>b.text().startsWith('Needs attention'))!;
    const update=async(servers:Server[])=>{nodes=servers;window.dispatchEvent(new Event('focus'));await flushPromises();};
    expect(attention().text()).toBe('Needs attention 0');
    expect(attention().find('.dot').exists()).toBe(false);
    await update([base]);
    expect(attention().text()).toBe('Needs attention 1');
    expect(attention().get('.dot').classes()).not.toContain('critical');
    await update([base,{...base,id:'critical',name:'critical',observation:{...base.observation!,cpuPercent:99}}]);
    expect(attention().text()).toBe('Needs attention 2');
    expect(attention().get('.dot').classes()).toContain('critical');
    await app.get('button[aria-label="Search servers"]').trigger('click');
    await app.get('input[aria-label="Search servers"]').setValue('warning');
    expect(app.getComponent(FleetList).props('servers')).toHaveLength(1);
    expect(attention().get('.dot').classes()).toContain('critical');
    await update([base]);
    expect(attention().get('.dot').classes()).not.toContain('critical');
    await update([{...base,lastError:'SSH is unavailable'}]);
    expect(attention().get('.dot').classes()).toContain('critical');
    await update([{...base,observation:{...base.observation!,at:now-1000,cpuPercent:10}}]);
    expect(attention().get('.dot').classes()).toContain('critical');
    await update([{...base,observation:{...base.observation!,cpuPercent:10}},{...base,id:'unknown',observation:null}]);
    expect(attention().text()).toBe('Needs attention 0');
    expect(attention().find('.dot').exists()).toBe(false);
    app.unmount();
  });
  it('autosaves monitoring while preserving current AI and pause state',async()=>{
    vi.useFakeTimers();
    apiState.preview=false;
    const settings:Settings={mode:'manual',dailyRunLimit:3,dailyTokenLimit:200000,runTokenLimit:50000,autoAgent:'claude',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false, dockBadgeEnabled: true};
    const snapshot={servers:[],sources:[],incidents:[],nginx:{},logStatus:{},settings,collectedAt:Date.now()/1000};
    vi.mocked(call).mockImplementation(async(command,args)=>{
      if(command==='snapshot')return {...snapshot,settings:{...snapshot.settings}};
      if(command==='update_settings'){snapshot.settings={...snapshot.settings,...args!.patch as Partial<Settings>};return {...snapshot.settings};}
      return {};
    });
    const app=mount(App);await flushPromises();
    await app.findAll('nav button').find(b=>b.text()==='Settings')!.trigger('click');
    const mode=app.getComponent(AutomationMode);
    await mode.get('[role="switch"]').trigger('click');await flushPromises();
    const monitoring=app.findAll('.settings-section').find(s=>s.find('h2').text()==='Monitoring')!;
    expect(monitoring.find('input[type="checkbox"]').exists()).toBe(false);
    expect(monitoring.find('button').exists()).toBe(false);
    await monitoring.findAll('label').find(l=>l.text().startsWith('Poll servers every'))!.get('input').setValue('600');
    await app.get('[aria-label="Pause monitoring"]').trigger('click');await flushPromises();
    await vi.advanceTimersByTimeAsync(250);await flushPromises();
    expect(snapshot.settings).toEqual({...settings,mode:'auto',pollSeconds:600,paused:true});
    await app.get('[aria-label="Resume monitoring"]').trigger('click');await flushPromises();
    await monitoring.findAll('label').find(l=>l.text().startsWith('Poll servers every'))!.get('input').setValue('900');
    snapshot.settings={...snapshot.settings,paused:true};
    window.dispatchEvent(new Event('focus'));await flushPromises();
    await vi.advanceTimersByTimeAsync(250);await flushPromises();
    expect(snapshot.settings).toEqual({...settings,mode:'auto',pollSeconds:900,paused:true});
    app.unmount();
  });
  it('keeps saved values after a late snapshot and flushes edits when leaving settings',async()=>{
    vi.useFakeTimers();
    const initial:Settings={mode:'manual',dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false, dockBadgeEnabled: true};
    let stored={...initial},hold=false,finish!:(value:unknown)=>void;
    const snapshot=()=>({servers:[],sources:[],incidents:[],nginx:{},logStatus:{},settings:{...stored},collectedAt:Date.now()/1000});
    vi.mocked(call).mockImplementation(async(command,args)=>{
      if(command==='snapshot')return hold?new Promise(resolve=>{finish=resolve;}):snapshot();
      if(command==='update_settings')return stored={...stored,...args!.patch as Partial<Settings>};
      return {};
    });
    const app=mount(App);await flushPromises();
    await app.findAll('nav button').find(b=>b.text()==='Settings')!.trigger('click');
    hold=true;const old=snapshot();window.dispatchEvent(new Event('focus'));await flushPromises();
    await app.get('input[min="30"]').setValue('600');await vi.advanceTimersByTimeAsync(250);await flushPromises();
    finish(old);hold=false;await flushPromises();
    expect(app.get('.monitor-full').text()).toBe('Polling every 10 min');
    await app.get('input[min="30"]').setValue('900');
    await app.findAll('nav button').find(b=>b.text()==='Servers')!.trigger('click');await flushPromises();
    expect(stored.pollSeconds).toBe(900);expect(app.get('.monitor-full').text()).toBe('Polling every 15 min');
    app.unmount();
  });
  it('opens the action journal and shows its size and rotation limit in storage settings',async()=>{
    vi.mocked(call).mockImplementation(async command=>{
      if(command==='snapshot')return {servers:[],sources:[],incidents:[],nginx:{},logStatus:{},settings:{mode:'manual',dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false},collectedAt:Date.now()/1000};
      if(command==='storage_status')return {activity:{bytes:3670016,limitBytes:31457280,dropped:0,error:null}};
      if(command==='activity_log')return {events:[],next:null,expired:false,skipped:0,storage:{bytes:3670016,limitBytes:31457280,dropped:0,error:null}};
      if(command==='local_resource_sample')return {cpuPercent:2,memoryBytes:16777216,rxBytes:0,txBytes:5120,durationMs:5000};
      return {};
    });
    const app=mount(App);await flushPromises();
    await app.findAll('nav button').find(b=>b.text()==='Activity log')!.trigger('click');await flushPromises();
    expect(app.get('h1').text()).toBe('Activity log');expect(app.find('.journal').exists()).toBe(true);
    expect(app.get('.page-title [aria-label="Cyberbot Resources"]').text()).toContain('16 MB');
    await app.findAll('nav button').find(b=>b.text()==='Settings')!.trigger('click');await flushPromises();
    const storage=app.findAll('.settings-section').find(s=>s.get('h2').text()==='Storage')!;
    expect(storage.text()).toContain('Activity log');expect(storage.text()).toContain('3.5 / 30 MiB');
    expect(storage.text()).toContain('Old entries are deleted automatically');
    expect(app.find('.local-resources').exists()).toBe(false);
    expect(vi.mocked(call).mock.calls.every(c=>['snapshot','storage_status','activity_log','local_resource_sample','take_notification_target','notification_status'].includes(c[0]))).toBe(true);
    app.unmount();
  });
  it('pauses and resumes from the sidebar on any page without changing AI settings',async()=>{
    const settings:Settings={mode:'auto',dailyRunLimit:3,dailyTokenLimit:200000,runTokenLimit:50000,autoAgent:'claude',pollSeconds:30,logPollSeconds:600,concurrency:4,paused:false, dockBadgeEnabled: true};
    const snapshot={servers:[],sources:[],incidents:[],nginx:{},logStatus:{},settings,collectedAt:Date.now()/1000};
    vi.mocked(call).mockImplementation(async(command,args)=>{
      if(command==='snapshot')return {...snapshot,settings:{...snapshot.settings}};
      if(command==='update_settings'){snapshot.settings={...snapshot.settings,...args!.patch as Partial<Settings>};return {...snapshot.settings};}
      return {};
    });
    const app=mount(App);await flushPromises();
    expect(app.get('.monitor-full').text()).toBe('Polling every 30 s');
    await app.get('[aria-label="Pause monitoring"]').trigger('click');await flushPromises();
    expect(snapshot.settings).toEqual({...settings,paused:true});
    expect(app.get('.monitor-full').text()).toBe('Monitoring paused');
    await app.findAll('nav button').find(b=>b.text()==='Settings')!.trigger('click');
    await app.get('[aria-label="Resume monitoring"]').trigger('click');await flushPromises();
    expect(snapshot.settings).toEqual(settings);
    expect(app.get('.monitor-full').text()).toBe('Polling every 30 s');
    app.unmount();
  });
  it('keeps the current polling state after a failed save and ignores repeated clicks while saving',async()=>{
    const settings:Settings={mode:'manual',dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false, dockBadgeEnabled: true};
    let fail!:(error:Error)=>void;
    vi.mocked(call).mockImplementation(async command=>{
      if(command==='snapshot')return {servers:[],sources:[],incidents:[],nginx:{},logStatus:{},settings,collectedAt:Date.now()/1000};
      if(command==='update_settings')return new Promise((_resolve,reject)=>{fail=reject;});
      return {};
    });
    const app=mount(App);await flushPromises();
    const pause=app.get('[aria-label="Pause monitoring"]');
    await pause.trigger('click');await pause.trigger('click');
    expect(vi.mocked(call).mock.calls.filter(c=>c[0]==='update_settings')).toHaveLength(1);
    expect(pause.attributes('disabled')).toBeDefined();
    fail(new Error('The recording failed'));await flushPromises();
    expect(app.get('.monitor-full').text()).toBe('Polling every 3 min');
    expect(app.get('[aria-label="Pause monitoring"]').attributes('disabled')).toBeUndefined();
    expect(app.get('[role="alert"]').text()).toContain('The recording failed');
    app.unmount();
  });
  it('imports the selected inventory without name or path fields',async()=>{
    apiState.preview=false;
    vi.mocked(call).mockImplementation(async command=>command==='snapshot'?{
      servers:[],sources:[],incidents:[],nginx:{},logStatus:{},settings:{mode:'manual',dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false},collectedAt:Date.now()/1000,
    }:command==='pick_inventory_file'?{name:'inventory.yml',location:'/Users/test/Inventory with spaces/inventory.yml'}:{});
    const app=mount(App);await flushPromises();
    expect(app.findAll('nav button').map(b=>b.text())).toEqual(['Servers','Incidents','AI','Activity log','Library','Settings']);
    expect(app.get('nav [aria-current="page"]').text()).toBe('Servers');
    expect(app.get('h1').text()).toBe('Servers');
    await app.get('.empty .primary').trigger('click');await flushPromises();
    const form=app.get('.source-form');
    expect(form.get('h2').text()).toBe('Add server');
    expect(form.text()).not.toMatch(/Project|Tag/);
    await form.findAll('button').find(b=>b.text()==='Ansible inventory')!.trigger('click');
    expect(form.find('input').exists()).toBe(false);
    expect(form.find('textarea').exists()).toBe(false);
    await form.get('.inventory-picker button').trigger('click');await flushPromises();
    expect(call).toHaveBeenCalledWith('pick_inventory_file');
    expect(call).toHaveBeenCalledWith('add_source',{kind:'ansible',location:'/Users/test/Inventory with spaces/inventory.yml'});
    expect(app.find('.source-dialog').exists()).toBe(false);
    await app.get('.empty .primary').trigger('click');await flushPromises();
    const manual=app.get('.source-form');
    await manual.findAll('button').find(b=>b.text()==='Manual list')!.trigger('click');
    expect(manual.find('input').exists()).toBe(false);
    expect(manual.text()).not.toContain('Title:');
    await manual.get('textarea').setValue('10.20.1.10\ndb.example.com\nops@web.example.com:2222');
    await manual.trigger('submit');await flushPromises();
    expect(call).toHaveBeenCalledWith('add_source',{kind:'manual',location:'10.20.1.10\ndb.example.com\nops@web.example.com:2222'});
    expect(app.find('.source-dialog').exists()).toBe(false);
    app.unmount();
  });
  it('uses the selected agent check and the pending count only when entering AI', async () => {
    apiState.preview = false;
    let settings: Settings = { mode: 'manual', dailyRunLimit: 0, dailyTokenLimit: 0, runTokenLimit: 0, autoAgent: 'codex', pollSeconds: 180, logPollSeconds: 600, concurrency: 4, paused: false, dockBadgeEnabled: true };
    let pendingActions = 0;
    let failCheck = false;
    let agents = [
      { name: 'codex', path: '/usr/local/bin/codex', version: '1.2.3', ready: true, reason: 'CLI checked' },
      { name: 'claude', path: '/usr/local/bin/claude', version: '2.3.4', ready: false, reason: 'Version not supported' },
    ];
    vi.mocked(call).mockImplementation(async (command, args) => {
      if (command === 'snapshot') return { servers: [], sources: [], incidents: [], nginx: {}, logStatus: {}, settings, pendingActions };
      if (command === 'auto_status') return { day: 20000, runs: 0, actualTokens: 0, chargedTokens: 0, reservedTokens: 0, uncertainRuns: 0, queued: 0, jobs: [] };
      if (command === 'action_requests') return [];
      if (command === 'detect_agents') {
        if (failCheck) throw new Error('Call unavailable');
        return agents;
      }
      if (command === 'update_settings') return settings = { ...settings, ...args?.patch as Partial<Settings> };
      return {};
    });
    let app = mount(App);
    const navigate = async (name: string) => {
      await app.get(`nav button[title="${name}"]`).trigger('click');
      await flushPromises();
    };
    const active = () => app.get('[role="tab"][aria-selected="true"]').attributes('id');
    const check = () => app.get('.cli-check button').trigger('click');
    await flushPromises();
    await navigate('Settings');
    expect(app.find('.cli-check').exists()).toBe(false);
    await navigate('AI');
    expect(app.findAll('main h1').map(heading => heading.text())).toEqual(['AI']);
    expect(app.findAll('main [role="switch"]')).toHaveLength(1);
    expect(active()).toBe('ai-settings-tab');
    expect(call).not.toHaveBeenCalledWith('detect_agents');
    expect(call).not.toHaveBeenCalledWith('auto_status');

    await check();
    await flushPromises();
    expect(app.get('.cli-check').text()).toContain('Version not supported');
    expect(app.get('.cli-check').text()).toContain('/usr/local/bin/codex');
    expect(active()).toBe('ai-settings-tab');
    failCheck = true;
    await check();
    await flushPromises();
    expect(app.get('.cli-error').text()).toContain('Call unavailable');
    expect(JSON.parse(localStorage.getItem(cliChecksKey)!)).toEqual({ codex: true, claude: false });

    await navigate('Servers');
    await navigate('AI');
    expect(active()).toBe('ai-sessions-tab');
    pendingActions = 2;
    window.dispatchEvent(new Event('focus'));
    await flushPromises();
    expect(app.get('#ai-actions-tab').text()).toContain('2');
    expect(app.get('nav button[title="AI"]').attributes('aria-label')).toBe('AI, 2 requests awaiting approval');
    expect(active()).toBe('ai-sessions-tab');
    app.unmount();

    app = mount(App);
    await flushPromises();
    await navigate('AI');
    expect(active()).toBe('ai-actions-tab');
    await app.get('#ai-settings-tab').trigger('click');
    const agent = app.get('select[aria-label="AI agent"]');
    await agent.setValue('claude');
    await agent.trigger('blur');
    await flushPromises();
    await navigate('Servers');
    await navigate('AI');
    expect(active()).toBe('ai-settings-tab');

    failCheck = false;
    agents = [{ ...agents[0], ready: false, reason: 'CLI removed' }, agents[1]];
    await check();
    await flushPromises();
    expect(JSON.parse(localStorage.getItem(cliChecksKey)!)).toEqual({ codex: false, claude: false });
    expect(vi.mocked(call).mock.calls.filter(([command]) => command === 'detect_agents')).toHaveLength(3);
    expect(vi.mocked(call).mock.calls.some(([command]) => /^(start_|console_|poll_server)/.test(command))).toBe(false);
    app.unmount();
  });

  it('routes explicit AI settings and notification targets independently of the entry tab', async () => {
    apiState.preview = false;
    let target: { open: boolean; incidentIds: string[]; openActions?: boolean; actionRequestId?: string } = { open: false, incidentIds: [] };
    const settings: Settings = { mode: 'manual', dailyRunLimit: 0, dailyTokenLimit: 0, runTokenLimit: 0, autoAgent: 'codex', pollSeconds: 180, logPollSeconds: 600, concurrency: 4, paused: true, dockBadgeEnabled: true };
    vi.mocked(call).mockImplementation(async command => {
      if (command === 'snapshot') return { servers: [], sources: [], incidents: [], nginx: {}, logStatus: {}, settings };
      if (command === 'take_notification_target') return target;
      if (command === 'action_requests') return [];
      return {};
    });
    const app = mount(App);
    await flushPromises();
    const send = async (event: string) => {
      const callback = vi.mocked(listen).mock.calls.find(([name]) => name === event)?.[1];
      expect(callback).toBeDefined();
      callback?.({ event, id: 0, payload: null });
      await flushPromises();
    };
    target = { open: true, incidentIds: [], openActions: true };
    await send('notification-open');
    expect(app.get('#ai-actions-tab').attributes('aria-selected')).toBe('true');
    expect(app.get('.pause-notice').text()).toContain('new automatic investigations are on hold');
    await send('ai-settings-open');
    expect(app.get('#ai-settings-tab').attributes('aria-selected')).toBe('true');
    target = { ...target, actionRequestId: 'request-id' };
    await send('notification-open');
    expect(call).toHaveBeenCalledWith('open_action_approval', { id: 'request-id' });
    expect(app.get('#ai-settings-tab').attributes('aria-selected')).toBe('true');
    app.unmount();
  });
  it('cancels file selection safely and retries a failed inventory without reopening the picker',async()=>{
    apiState.preview=false;
    let picks=0,imports=0,finish!: (file:unknown)=>void;
    const file={name:'hosts',location:'/Users/test/infrastructure/hosts'};
    vi.mocked(call).mockImplementation(async command=>{
      if(command==='snapshot')return {servers:[],sources:[],incidents:[],nginx:{},logStatus:{},settings:{mode:'manual',dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false},collectedAt:Date.now()/1000};
      if(command==='pick_inventory_file'){
        picks++;
        if(picks===1)return null;
        if(picks===2)throw new Error('Failed to open file selection');
        return new Promise(resolve=>{finish=resolve;});
      }
      if(command==='add_source'&&++imports===1)throw new Error('Inventory damaged');
      return {};
    });
    const app=mount(App);await flushPromises();
    await app.get('.empty .primary').trigger('click');await flushPromises();
    const form=app.get('.source-form');
    await form.findAll('button').find(b=>b.text()==='Ansible inventory')!.trigger('click');
    const choose=form.get('.inventory-picker button');
    await choose.trigger('click');await flushPromises();
    expect(app.find('.source-dialog').exists()).toBe(true);
    expect(vi.mocked(call).mock.calls.some(c=>c[0]==='add_source')).toBe(false);
    await choose.trigger('click');await flushPromises();
    expect(form.get('[role="alert"]').text()).toBe('Failed to open file selection');
    expect(choose.attributes('disabled')).toBeUndefined();
    await choose.trigger('click');
    expect(choose.attributes('disabled')).toBeDefined();
    expect(form.get('.tabs button').attributes('disabled')).toBeDefined();
    await choose.trigger('click');
    await app.get('.source-dialog').trigger('cancel');
    expect(picks).toBe(3);
    expect(app.find('.source-dialog').exists()).toBe(true);
    finish(file);await flushPromises();
    expect(form.get('[role="alert"]').text()).toBe('Inventory damaged');
    expect(form.get('.inventory-name').text()).toBe('hosts');
    expect(form.get('footer .primary').text()).toBe('Retry import');
    expect(form.find('input').exists()).toBe(false);
    await form.trigger('submit');await flushPromises();
    expect(picks).toBe(3);
    expect(vi.mocked(call).mock.calls.filter(c=>c[0]==='add_source')).toEqual([
      ['add_source',{kind:'ansible',location:file.location}],['add_source',{kind:'ansible',location:file.location}],
    ]);
    expect(app.find('.source-dialog').exists()).toBe(false);
    app.unmount();
  });
  it('manages connections from the dashboard without a separate navigation page',async()=>{
    apiState.preview=false;
    const snapshot={servers:[],sources:[{id:'inventory-a',name:'Production',kind:'ansible',location:'/inventory.yml',lastSync:null,error:null}],incidents:[],nginx:{},logStatus:{},settings:{mode:'manual',dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false},collectedAt:Date.now()/1000};
    vi.mocked(call).mockImplementation(async(command)=>{
      if(command==='snapshot')return snapshot;
      if(command==='refresh_source')throw new Error('Inventory unavailable');
      if(command==='delete_source')snapshot.sources=[];
      return {};
    });
    const app=mount(App,{attachTo:document.body});await flushPromises();
    await app.get('[aria-label="Search servers"]').trigger('click');
    await app.get('input[aria-label="Search servers"]').setValue('db');
    const manage=app.get('.manage-servers');
    await manage.trigger('click');await flushPromises();
    expect(app.get<HTMLDialogElement>('.management-dialog').element.open).toBe(true);
    expect(app.get('nav [aria-current="page"]').text()).toBe('Servers');
    await app.get('.source-row .row-actions button').trigger('click');await flushPromises();
    expect(call).toHaveBeenCalledWith('refresh_source',{id:'inventory-a'});
    expect(app.get('.management-dialog [role="alert"]').text()).toBe('Inventory unavailable');
    await app.get('.source-row .quiet').trigger('click');
    expect(vi.mocked(call).mock.calls.some(c=>c[0]==='delete_source')).toBe(false);
    await app.get('.management-dialog').trigger('cancel');await flushPromises();
    expect(app.find('.management-dialog').exists()).toBe(false);
    expect(document.activeElement).toBe(manage.element);
    expect(app.get<HTMLInputElement>('input[aria-label="Search servers"]').element.value).toBe('db');
    await manage.trigger('click');await flushPromises();
    expect(app.find('.source-row .danger').exists()).toBe(false);
    await app.get('.management-head .primary').trigger('click');await flushPromises();
    expect(app.find('.management-dialog').exists()).toBe(false);
    expect(app.get<HTMLDialogElement>('.source-dialog').element.open).toBe(true);
    await app.get('[aria-label="Close add server form"]').trigger('click');
    await manage.trigger('click');await flushPromises();
    await app.get('.source-row .quiet').trigger('click');
    await app.get('.source-row .danger').trigger('click');await flushPromises();
    expect(call).toHaveBeenCalledWith('delete_source',{id:'inventory-a'});
    expect(app.find('.source-row').exists()).toBe(false);
    expect(app.get('.management-dialog').text()).toContain('No servers yet');
    await app.get('[aria-label="Close server management"]').trigger('click');
    await app.findAll('nav button').find(b=>b.text()==='Settings')!.trigger('click');
    await app.findAll('nav button').find(b=>b.text()==='Servers')!.trigger('click');
    expect(app.find('.fleet-controls').exists()).toBe(true);
    expect(app.find('.management-dialog').exists()).toBe(false);
    app.unmount();
  });
});

it('searches individual incidents across fields and respects the resolved filter', async () => {
  vi.useFakeTimers();
  const server: Server = {
    id: 'node', name: 'inventory.example.net', sourceId: 'fixture',
    endpoint: { host: '192.0.2.10', user: 'ops', port: 2201, identityFile: null, jumpHost: null },
    observation: null, lastError: null, lastAttempt: null, nextCheck: 0, failures: 0,
  };
  const incident: Incident = {
    id: 'i-nginx', episode: 'ep-nginx', serverId: server.id, check: 'nginx:upstream',
    title: 'Upstream errors', status: 'open', severity: 'critical', evidence: 'Bad gateway',
    openedAt: 100, updatedAt: 101,
  };
  const resolved: Incident = { ...incident, id: 'i-disk', check: 'disk:/', title: 'Disk full',
    status: 'resolved', evidence: '98% used', resolvedByUserAt: 120 };
  vi.mocked(call).mockImplementation(async command => {
    if (command === 'snapshot') return {
      servers: [server], incidents: [incident, resolved], sources: [], logStatus: {},
      settings: { mode: 'manual', autoAgent: 'codex', pollSeconds: 180, paused: false },
    };
    if (command === 'incident_groups') return { groups: [], total: 0 };
    return {};
  });
  const app = mount(App);
  try {
    await flushPromises();
    await app.get('nav button[title="Incidents"]').trigger('click');
    await flushPromises();
    const search = app.get<HTMLInputElement>('input[aria-label="Search incidents"]');
    await search.setValue('  INVENTORY.EXAMPLE.NET  192.0.2.10:2201   nginx:upstream   gateway CRITICAL  i-nginx ');
    expect(app.get('.incident-row').text()).toContain('Upstream errors');
    expect(app.find('.resolve-all').exists()).toBe(false);
    await search.setValue('98% manually resolved');
    await vi.advanceTimersByTimeAsync(200);
    expect(app.text()).toContain('No matching incidents');
    await app.get('.incident-actions input').setValue(true);
    await flushPromises();
    expect(app.get('.incident-row').text()).toContain('Disk full');
    await search.trigger('keydown', { key: 'Escape' });
    expect(search.element.value).toBe('');
    expect(app.findAll('.incident-row')).toHaveLength(2);
    expect(app.find('.resolve-all').exists()).toBe(true);
  } finally {
    app.unmount();
    vi.useRealTimers();
    vi.clearAllMocks();
  }
});

it('removes manually resolved incidents from the active page and keeps them in resolved history',async()=>{
 apiState.preview=false;vi.stubGlobal('ResizeObserver',class{observe(){}unobserve(){}disconnect(){}});
 const server:Server={id:'s',name:'web',sourceId:'src',endpoint:{host:'host',user:'root',port:22,identityFile:null,jumpHost:null},observation:null,lastError:null,lastAttempt:null,nextCheck:0,failures:0};
 let incident={id:'i',episode:'ep',serverId:'s',check:'cpu',title:'CPU',severity:'warning',status:'open',openedAt:100,updatedAt:100,evidence:'95%',resolvedByUserAt:null as number|null};
 vi.mocked(call).mockImplementation(async(command)=>{if(command==='resolve_incident'){incident={...incident,status:'resolved',resolvedByUserAt:101};return;}if(command==='snapshot')return {servers:[server],incidents:[{...incident}],sources:[],services:{},nginx:{},logStatus:{},settings:{mode:'manual',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:true,dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex'},collectedAt:102};if(command==='incident_groups')return {groups:[],total:0};return {};});
 const w=mount(App);await flushPromises();await w.findAll('.sidebar nav button').find(b=>b.text().startsWith('Incidents'))!.trigger('click');await flushPromises();expect(w.findAll('.incident-row')).toHaveLength(1);await w.get('[aria-label="Mark resolved: CPU"]').trigger('click');await flushPromises();expect(w.find('.incident-row').exists()).toBe(false);await w.get('input[type="checkbox"]').setValue(true);await flushPromises();expect(w.text()).toContain('Manually resolved');expect(w.find('.resolve').exists()).toBe(false);w.unmount();apiState.preview=true;
});

it.each([false,true])('marks the open incidents in the current scope (from notification: %s)',async(fromNotification)=>{
 apiState.preview=false;
 vi.stubGlobal('ResizeObserver',class{observe(){}unobserve(){}disconnect(){}});
 const base={serverId:'s',check:'cpu',title:'CPU',severity:'warning',openedAt:100,updatedAt:100,evidence:'95%'};
 let incidents:Incident[]=[
  {...base,id:'first',episode:'ep1',status:'open',resolvedByUserAt:null},
  {...base,id:'second',episode:'ep2',status:'open',resolvedByUserAt:null},
  {...base,id:'history',episode:'old',status:'resolved',resolvedByUserAt:100},
 ];
 const settings={mode:'manual',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:true,dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex'};
 const selected=fromNotification?incidents.slice(0,1):incidents.slice(0,2);
 vi.mocked(call).mockImplementation(async(command)=>{
  if(command==='snapshot')return {servers:[],incidents,sources:[],services:{},nginx:{},logStatus:{},settings,collectedAt:102};
  if(command==='take_notification_target')return {open:fromNotification,incidentIds:['first','history']};
  if(command==='incident_groups')return {groups:[],total:incidents.some(i=>i.status==='open')?1:0};
  if(command==='resolve_incidents')incidents=incidents.map(i=>selected.includes(i)?{...i,status:'resolved',resolvedByUserAt:102}:i);
  return {};
 });
 const w=mount(App);
 try{
  await flushPromises();
  if(!fromNotification){
   await w.findAll('.sidebar nav button').find(b=>b.text().startsWith('Incidents'))!.trigger('click');
   await flushPromises();
   await w.findAll('label').find(label=>label.text()==='Show individual incidents')!.get('input').setValue(false);
   expect(w.find('.incident-row').exists()).toBe(false);
  }
  await w.get('.resolve-all').trigger('click');
  await flushPromises();
  expect(call).toHaveBeenCalledWith('resolve_incidents',{episodes:selected.map(({id,episode})=>({id,episode}))});
  expect(w.find('.resolve-all').exists()).toBe(false);
  expect(w.find('.incident-row').exists()).toBe(false);
  await w.findAll('label').find(label=>label.text()==='Show resolved')!.get('input').setValue(true);
  await flushPromises();
  expect(w.findAll('.incident-row').filter(row=>row.text().includes('Manually resolved'))).toHaveLength(selected.length+1);
 }finally{
  w.unmount();
  apiState.preview=true;
  vi.unstubAllGlobals();
 }
});

it.each(['open','resolved'] as const)('opens the server from the fleet with %s incidents on the appropriate tab',async(status)=>{
 apiState.preview=true;vi.stubGlobal('ResizeObserver',class{observe(){}unobserve(){}disconnect(){}});
 const server:Server={id:'server',name:'web',sourceId:'src',endpoint:{host:'host',user:'root',port:22,identityFile:null,jumpHost:null},observation:null,lastError:null,lastAttempt:null,nextCheck:0,failures:0};
 const incident={id:'incident',episode:'episode',serverId:'server',check:'cpu',title:'CPU overload',severity:'warning',status,openedAt:100,updatedAt:100,evidence:'95%'};
 vi.mocked(call).mockImplementation(async(command)=>{if(command==='snapshot')return {servers:[server],incidents:[incident],sources:[],services:{},nginx:{},logStatus:{},settings:{mode:'manual',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:true,dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex'},collectedAt:102};if(command==='incident_groups')return {groups:[],total:0};if(command==='history')return [];return {};});
 const w=mount(App);await flushPromises();if(status==='open'){await w.findAll('.sidebar nav button').find(b=>b.text().startsWith('Incidents'))!.trigger('click');await flushPromises();await w.get('.incident-main').trigger('click');await flushPromises();expect(w.get('.detail-dialog .detail-tabs button.active').text()).toBe('Incidents');expect(w.get('.detail-dialog').text()).toContain('CPU overload');expect(w.find('.detail-dialog .metrics').exists()).toBe(false);
 await w.get('[aria-label="Close server"]').trigger('click');await w.findAll('.sidebar nav button').find(b=>b.text()==='Servers')!.trigger('click');await flushPromises();}
 await w.get('.ribbon-slot button').trigger('click');await flushPromises();expect(w.get('.detail-dialog .detail-tabs button.active').text()).toBe(status==='open'?'Incidents':'Overview');
 expect(w.find('.detail-dialog .incident-row').exists()).toBe(status==='open');
 expect(vi.mocked(call).mock.calls.some(([command])=>command==='start_investigation'||command==='poll_server')).toBe(false);w.unmount();vi.unstubAllGlobals();
});

it.each([false,true])('uses pending-first-check status consistently with confirmed CVEs: %s',async(affected)=>{
 vi.stubGlobal('ResizeObserver',class{observe(){}unobserve(){}disconnect(){}});
 const server:Server={id:'pending',name:'pending',sourceId:'s',endpoint:{host:'pending.invalid',user:'root',port:22,identityFile:null,jumpHost:null},observation:null,lastError:'old error',lastAttempt:1,nextCheck:0,failures:2};
 vi.mocked(call).mockImplementation(async c=>c==='snapshot'?{servers:[server],awaitingFirstCheck:['pending'],vulnerabilities:affected?{pending:{status:'critical',affected:1,critical:1,at:1}}:{},sources:[],incidents:[],nginx:{},logStatus:{},settings:{mode:'manual',autoAgent:'codex',pollSeconds:180,logPollSeconds:600,paused:false,concurrency:4,dailyTokenLimit:null,dailyRunLimit:null,runTokenLimit:50000},collectedAt:Date.now()/1000}:{});
 const app=mount(App,{attachTo:document.body});await flushPromises();
 const attention=app.findAll('.fleet-filters button').find(b=>b.text().startsWith('Needs attention'))!;
 expect(attention.text()).toContain(affected?'1':'0');await attention.trigger('click');expect(app.findComponent(FleetList).exists()).toBe(affected);
 if(affected)expect(app.getComponent(FleetList).props('servers')[0].awaitingFirstCheck).toBe(true);
 await app.findAll('.fleet-filters button').find(b=>b.text().startsWith('Insufficient data'))!.trigger('click');
 expect(app.findComponent(FleetList).exists()).toBe(!affected);app.unmount();vi.unstubAllGlobals();
});

it('opens the detail panel without selecting a control and restores the opener on close',async()=>{
 vi.stubGlobal('ResizeObserver',class{observe(){}unobserve(){}disconnect(){}});
 const server:Server={id:'focus',name:'focus',sourceId:'s',endpoint:{host:'focus.invalid',user:'root',port:22,identityFile:null,jumpHost:null},observation:null,lastError:null,lastAttempt:null,nextCheck:0,failures:0};
 vi.mocked(call).mockImplementation(async c=>c==='snapshot'?{servers:[server],sources:[],incidents:[],nginx:{},logStatus:{},settings:{mode:'manual',autoAgent:'codex',pollSeconds:180,logPollSeconds:600,paused:false,concurrency:4,dailyTokenLimit:null,dailyRunLimit:null,runTokenLimit:50000},collectedAt:Date.now()/1000}:c==='history'?[]:{});
 const app=mount(App,{attachTo:document.body});await flushPromises();const opener=app.get<HTMLButtonElement>('button.ribbon');opener.element.focus();await opener.trigger('click');await flushPromises();
 expect(app.get('.detail-panel').attributes('autofocus')).toBeDefined();expect(app.get('.detail-panel').attributes('tabindex')).toBe('-1');expect(app.find('.date-popover').exists()).toBe(false);
 await app.get('[aria-label="Close server"]').trigger('click');await flushPromises();expect(document.activeElement).toBe(opener.element);app.unmount();vi.unstubAllGlobals();
});

it('opens the correct server sidebar from an old UUID in Library history', async () => {
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
  const firstId = '2c9d9fc4-8d97-4c5c-b119-cec1ae464e5d';
  const secondId = '3bddedc6-ec99-4541-9089-15258b7b43a0';
  const servers: Server[] = [firstId, secondId].map((id, index) => ({
    id, name: `inventory-db-${index}`, sourceId: 's',
    endpoint: { host: 'db.example.net', user: 'ops', port: 22 + index, identityFile: null, jumpHost: null },
    observation: null, lastError: null, lastAttempt: null, nextCheck: 0, failures: 0,
  }));
  const values = { enabled: true, intervalSeconds: 180, diagnosticEnabled: false, expectedPeers: 0, expectReplica: false };
  vi.mocked(call).mockImplementation(async command => {
    if (command === 'snapshot') return { servers, sources: [], incidents: [], nginx: {}, logStatus: {},
      settings: { mode: 'manual', autoAgent: 'codex', pollSeconds: 180, logPollSeconds: 600, paused: false },
    };
    if (command === 'monitoring_catalog') return [{ id: 'metrics', name: 'OS resources', runner: 'metrics', purpose: 'Resources', configurable: true, intervalEditable: true, version: 'v1' }];
    if (command === 'monitoring_library') return { metrics: { values, serverOverride: false, instanceOverrides: {} } };
    if (command === 'monitoring_policy') return { values, origins: { intervalSeconds: 'factory' }, overrides: {}, revision: 1 };
    if (command === 'activity_log') return { events: servers.map(({ id }) => ({
      id, target: id, at: 1700000000000, category: 'server', phase: 'completed', monitoring: { trigger: 'schedule' },
    })) };
    if (command === 'history') return [];
    return {};
  });
  const app = mount(App, { attachTo: document.body });
  try {
    await flushPromises();
    await app.get('.sidebar button[title="Library"]').trigger('click');
    await flushPromises();
    await app.get('.server-picker button').trigger('click');
    expect(app.findAll('[role="option"] .option-label > span').map(option => option.text())).toEqual(['All servers', 'db.example.net', 'db.example.net']);
    const serverSearch = app.get('input[aria-label="Find a server"]');
    await serverSearch.setValue('inventory-db-1');
    expect(app.get('[role="option"]').attributes('title')).toBe('inventory-db-1 · ops@db.example.net:23');
    await serverSearch.trigger('keydown', { key: 'Escape' });
    await app.get('.row-button').trigger('click');
    await flushPromises();
    const details = app.findAll('details').find(item => item.get('summary').text() === 'Recent runs')!;
    (details.element as HTMLDetailsElement).open = true;
    await details.trigger('toggle');
    await flushPromises();
    const links = details.findAll('.server-link');
    expect(links.map(link => link.text())).toEqual(['db.example.net', 'db.example.net']);
    expect(details.text()).not.toContain(firstId);
    expect(links[1].attributes('title')).toBe('inventory-db-1 · ops@db.example.net:23');
    (links[1].element as HTMLButtonElement).focus();
    await links[1].trigger('click');
    await flushPromises();
    expect(app.get('.detail-dialog h2').text()).toBe('db.example.net');
    expect(app.get('.detail-dialog .server-title p').text()).toBe('ops@db.example.net:23');
    expect(app.get('main h1').text()).toBe('Library');
    await app.get('[aria-label="Close server"]').trigger('click');
    await flushPromises();
    expect(document.activeElement).toBe(links[1].element);
  } finally {
    app.unmount();
    vi.unstubAllGlobals();
  }
});
