import { describe,it,expect } from 'vitest';
import { health, partialHealthReason, serverHealthLabel } from './health';
import type { Server } from './types';
const base:Server={id:'a',sourceId:'s',name:'web',endpoint:{host:'web',user:'ops',port:22,identityFile:null,jumpHost:null},observation:{at:1000,cpuPercent:10,memoryPercent:20,swapPercent:0,load:1,uptime:10,disks:[{mount:'/',usedPercent:30,inodePercent:10}],services:[],missing:[],bytesReceived:100,durationMs:20},lastError:null,lastAttempt:1000,nextCheck:1180,failures:0};
describe('health distinguishes absence of evidence',()=>{
  it('never calls an unobserved server healthy',()=>expect(health({...base,observation:null},1000)).toBe('unknown'));
  it('marks old observations stale after sleep',()=>expect(health(base,2000)).toBe('stale'));
  it('surfaces transport failure over previous green metrics',()=>expect(health({...base,lastError:'auth failure'},1000)).toBe('unreachable'));
  it('requires CPU, memory and a disk reading for a green server', () => {
    for (const missing of [{ cpuPercent: null }, { memoryPercent: null }, { disks: [] }]) {
      const server = { ...base, observation: { ...base.observation!, ...missing } };
      expect(health(server, 1000)).toBe('unknown');
      expect(partialHealthReason(server, 'unknown')).toContain('basic metrics');
    }
  });
  it('critical disk overrides normal CPU',()=>expect(health({...base,observation:{...base.observation!,disks:[{mount:'/',usedPercent:98,inodePercent:1}]}},1000)).toBe('critical'));
  it('Nginx failure changes the overall tile',()=>expect(health({...base,services:[{kind:'nginx',name:'Nginx',detected:true,status:'critical',at:1000}]},1000)).toBe('critical'));
  it('unknown Nginx does not hide a known log warning',()=>expect(health({...base,logStatus:'warning',services:[{kind:'nginx',name:'Nginx',detected:true,status:'unknown',at:1000}]},1000)).toBe('warning'));
  it.each([undefined, 'unknown', 'stale'] as const)('keeps fresh normal metrics green with log status %s', logStatus => {
    expect(health({ ...base, logStatus }, 1000)).toBe('healthy');
  });
  it.each(['warning', 'critical'] as const)('keeps a confirmed %s log finding visible', logStatus => {
    expect(health({ ...base, logStatus }, 1000)).toBe(logStatus);
  });
  it('keeps fresh normal metrics green during incomplete diagnostic coverage', () => {
    const server: Server = {
      ...base,
      observation: { ...base.observation!, cpuPercent: 0, missing: ['services'] },
      services: [{kind:'nginx',name:'Nginx',status:'unknown',at:1000}, {kind:'postgresql',name:'PostgreSQL',status:'unknown',at:1000}, {kind:'docker',name:'Docker',status:'stale',at:1000}],
      checkStatus: 'unknown',
      vulnerabilities: { status: 'unknown', affected: 0, critical: 0, at: 1000 },
    };
    const status = health(server, 1000);
    expect(status).toBe('healthy');
    expect(serverHealthLabel(server, status)).toBe('Healthy');
    expect(partialHealthReason(server, status)).toBeUndefined();
    const noMetrics = { ...server, observation: null };
    expect(serverHealthLabel(noMetrics, health(noMetrics, 1000))).toBe('No data');
    expect(partialHealthReason(noMetrics, 'unknown')).toBeUndefined();
  });
  it.each(['critical', 'warning', 'unknown'] as const)('a confirmed vulnerability makes the tile red with CVE status %s', status => {
    expect(health({...base,vulnerabilities:{status,affected:1,critical:0,at:1000}},1000)).toBe('critical');
  });
  it('only a confirmed custom check finding affects server health',()=>{expect(health({...base,checkStatus:'critical'},1000)).toBe('critical');expect(health({...base,checkStatus:'unknown'},1000)).toBe('healthy');});
  it('normal complete observation is healthy',()=>expect(health(base,1000)).toBe('healthy'));
});
it('PostgreSQL diagnostics affect health without treating absent databases as failures',()=>{expect(health({...base,services:[{kind:'postgresql',name:'PostgreSQL',status:'critical',at:1000}]},1000)).toBe('critical');expect(health({...base,services:[{kind:'postgresql',name:'PostgreSQL',status:'unknown',at:1000}]},1000)).toBe('healthy');expect(health({...base,services:[{kind:'postgresql',name:'PostgreSQL',status:'not_detected',at:1000}]},1000)).toBe('healthy');});

it('multiple installed services retain the worst known state independently',()=>{const services=[{kind:'mysql',name:'MySQL',status:'healthy',at:1000},{kind:'redis',name:'Redis',status:'critical',at:1000},{kind:'docker',name:'Docker',status:'unknown',at:1000}];expect(health({...base,services},1000)).toBe('critical');expect(health({...base,services:services.filter(s=>s.kind!=='redis')},1000)).toBe('healthy');});

it('uses per-server monitoring intervals and never marks disabled metrics green',()=>{
 const server={id:'one',sourceId:'s',name:'one',endpoint:{host:'h',user:'root',port:22,identityFile:null,jumpHost:null},lastError:null,lastAttempt:100,nextCheck:500,failures:0,observation:{at:100,cpuPercent:1,memoryPercent:2,swapPercent:0,load:1,uptime:100,disks:[{mount:'/',usedPercent:20,inodePercent:1}],services:[],missing:[],bytesReceived:100,durationMs:1},monitoring:{enabled:true,intervalSeconds:600,diagnosticEnabled:false,expectedPeers:0,expectReplica:false}};
 expect(health(server,700,180)).toBe('healthy');server.monitoring.enabled=false;expect(health(server,700,180)).toBe('unknown');expect(health({...server,logStatus:'critical'},700,180)).toBe('critical');
});

it('keeps persisted transport errors and resource measurements unknown until the first completed check',()=>{
 const pending={...base,awaitingFirstCheck:true,lastError:'previous timeout',observation:{...base.observation!,cpuPercent:100}};
 expect(health(pending,10000)).toBe('unknown');
 expect(health({...pending,awaitingFirstCheck:false},10000)).toBe('unreachable');
 expect(health({...base,awaitingFirstCheck:true,monitoring:{enabled:false} as Server['monitoring']},1000)).toBe('unknown');
});

it('keeps independently confirmed problems visible while resource metrics are pending or missing', () => {
  const pending = { ...base, awaitingFirstCheck: true, lastError: 'previous timeout', logStatus: 'warning' as const };
  expect(health(pending, 10000)).toBe('warning');
  expect(serverHealthLabel(pending, 'warning')).toBe('Needs attention · awaits a metric survey');
  const affected = { ...pending, vulnerabilities: { status: 'critical' as const, affected: 1, critical: 1, at: 1000 } };
  expect(health(affected, 10000)).toBe('critical');
  expect(health({ ...affected, awaitingFirstCheck: false, observation: null, lastError: null }, 10000)).toBe('critical');
});
