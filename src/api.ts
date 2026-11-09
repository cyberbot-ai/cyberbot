import { invoke, isTauri } from '@tauri-apps/api/core';
import { serviceCatalog } from './services';
import { previewAction, previewServerHost, previewServiceCards } from './previewServices';
import { serverAddress } from './serverDirectory';
import type { Snapshot, Server, Settings, ActivityQuery, ActionRequest, VulnerabilityView, VulnerabilityCard, VulnerabilityFinding } from './types';
import {
  vulnerabilityPageSize, type VulnerabilityCatalogDetail, type VulnerabilityCatalogQuery,
  type VulnerabilityCatalogRow, type VulnerabilityStatus,
} from './vulnerabilityCatalog';
export const preview = !isTauri();
let previewSettings: Settings = {mode:'manual',dailyRunLimit:0,dailyTokenLimit:0,runTokenLimit:0,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false};
function previewSnapshot(): Snapshot {
  const now=Math.floor(Date.now()/1000);
  const servers: Server[] = Array.from({length:24}, (_, i) => {
    const host = previewServerHost(i);
    return {id:`demo-${i}`,sourceId:'preview',name:host,endpoint:{host,user:'ops',port:22,identityFile:null,jumpHost:null},observation:{at:now-i*3,cpuPercent:i===2?94:12+(i*7)%56,memoryPercent:24+(i*11)%54,swapPercent:0,load:0.4,uptime:132000,disks:[{mount:'/',usedPercent:i===5?98:20+(i*9)%48,inodePercent:12}],services:[],missing:i===9?['services']:[],bytesReceived:900,durationMs:240},lastError:i===11?'SSH: connection rejected':null,lastAttempt:now-i*3,nextCheck:now+180,failures:i===11?2:0};
  });
  // Fictional preview data exercises mixed software, instances, missing and stale data.
  servers[19].observation!.at = now - 900;
  servers[23].observation = null;
  const services = previewServiceCards(servers, now);
  return {servers,pendingActions:Number(new URLSearchParams(location.search).has('demoActions')),services,vulnerabilities:previewVulnerabilityCards(now),logStatus:Object.fromEntries(servers.map(s=>[s.id,'healthy'])),sources:[{id:'preview',name:'Demonstration inventory',kind:'ansible',location:'/example/inventory.yml',lastSync:now,error:null}],incidents:[{id:'demo-incident',serverId:'demo-5',check:'disk:/',title:'The disk is filling up',severity:'critical',status:'open',openedAt:now-600,updatedAt:now,evidence:'/: 98% busy'}],settings:{...previewSettings},collectedAt:now};
}
const previewAdvisories = [
  ['Out-of-bounds access', 'openssl', '3.0.16', '3.0.17'],
  ['Authorization bypass', 'openssh-server', '9.2p1-2+deb12u6', '9.2p1-2+deb12u7'],
  ['Request parsing error', 'curl', '7.88.1-10+deb12u12', '7.88.1-10+deb12u13'],
  ['Out-of-bounds read', 'libxml2', '2.9.14', null],
  ['Header parsing error', 'zlib1g', '1.2.13', '1.3'],
] as const;
const previewAffectedServers: Readonly<Record<string, readonly number[]>> = {
  'demo-0': [0, 1, 2], 'demo-4': [0, 3], 'demo-9': [2],
};
const previewCve = (index: number) => `CVE-2026-${9999999 - index}`;
const previewHidden = () => new URLSearchParams(location.search).get('demoVulnerabilities') === 'hidden';
const previewAdvisoryIndices = (id: string, hidden: boolean) => hidden
  ? (id === 'demo-0' ? [0] : [])
  : previewAffectedServers[id] ?? [];

function previewVulnerabilityCards(at: number): Record<string, VulnerabilityCard> {
  const hidden = previewHidden();
  const cards: Record<string, VulnerabilityCard> = {};
  for (const id of Object.keys(previewAffectedServers)) {
    const count = previewAdvisoryIndices(id, hidden).length;
    if (!count) continue;
    const affected = hidden ? 0 : count;
    cards[id] = {status: affected ? 'critical' : 'healthy', affected, critical: affected, hiddenCount: hidden ? count : 0, at};
  }
  return cards;
}
function previewVulnerabilities(id:unknown,includeHidden:boolean):VulnerabilityView{
 const empty:VulnerabilityView={evaluation:null,fresh:false,collecting:false,lastSuccess:null,nextCheck:0,error:null,total:0,offset:0,findings:[],fixes:{},sources:[],hiddenCount:0,active:{affected:0,critical:0,unknown:0,hidden:0}};
 const at = Math.floor(Date.now() / 1000) - 60;
 const hidden = previewHidden();
 const indices = previewAdvisoryIndices(String(id), hidden);
 if (!indices.length) return empty;
 const affected = hidden ? 0 : indices.length;
 const hiddenCount = hidden ? indices.length : 0;
 const findings: VulnerabilityFinding[] = hidden && !includeHidden ? [] : indices.map(index => {
   const [title, source, version, fixedVersion] = previewAdvisories[index];
   const cve = previewCve(index);
   return {source, cve, state:'affected', severity:'critical', severitySource:'Demo',
     packages:[{name:source, version, fixedVersion}], description:`${title}. Fictional finding for demonstration.`,
     url:`https://advisories.example.com/${cve}`, reason:null, fixPublished:fixedVersion !== null,
     fingerprint:String(index + 1).repeat(64), hiddenAt:hidden ? at : null};
 });
 const fixes = Object.fromEntries(findings.filter(f => f.fixPublished).map(f => [`${f.source}:${f.cve}:${f.source}`, 'available']));
 return {...empty, evaluation:{at,root:'demo',checks:indices.length,freshUntil:at+86400,coverage:[],generations:{},affected:indices.length,critical:indices.length,unknown:0,error:null},
   fresh:true,lastSuccess:at,total:findings.length,hiddenCount,active:{affected,critical:affected,unknown:0,hidden:hiddenCount},findings,fixes};
}

function previewVulnerabilityCatalog(servers: Server[]) {
  const hidden = previewHidden();
  const statuses: VulnerabilityStatus[] = ['affected', 'hidden', 'resolved', 'unknown'];
  return Array.from({ length: 24 }, (_, index) => {
    const [title, pkg] = previewAdvisories[index % previewAdvisories.length];
    const cve = previewCve(index);
    const publishedOn = index === 23 ? null : '2026-10-' + String(31 - index).padStart(2, '0');
    const packages = index === 0 ? [pkg, 'libssl3'] : [pkg];
    const matches: VulnerabilityCatalogDetail['servers'] = [];
    if (index % 5 !== 4) {
      const matched = index < previewAdvisories.length
        ? servers.filter(server => previewAdvisoryIndices(server.id, hidden).includes(index))
        : servers.slice(index, index + 1);
      matched.forEach((server, position) => matches.push({
        serverId: server.id, name: server.name, host: server.endpoint.host, address: serverAddress(server.endpoint),
        findings: [{ package: pkg, status: index < previewAdvisories.length ? (hidden ? 'hidden' : 'affected') : statuses[(index + position) % statuses.length] }],
      }));
    }
    const row: VulnerabilityCatalogRow = {
      cve, title, publishedOn, firstPackage: pkg, packageCount: packages.length,
      firstServer: matches[0]?.host ?? null, serverCount: matches.length,
    };
    const detail: VulnerabilityCatalogDetail = { packages, servers: matches, partial: false };
    return { row, detail };
  });
}

function previewVulnerabilityPage(servers: Server[], query: VulnerabilityCatalogQuery) {
  const term = query.search.trim().toLowerCase();
  const matches = previewVulnerabilityCatalog(servers).filter(({ row, detail }) => {
    const statusMatches = query.status === 'noFindings'
      ? !query.serverId && !detail.servers.length
      : (!query.status && !query.serverId) || detail.servers.some(server =>
        (!query.serverId || query.serverId === server.serverId)
        && (!query.status || server.findings.some(finding => finding.status === query.status)));
    return statusMatches && [row.cve, row.title, ...detail.packages,
      ...detail.servers.flatMap(server => [server.name, server.host, server.address])]
      .some(value => value.toLowerCase().includes(term));
  });
  const total = matches.length;
  const offset = Math.min(Math.floor(query.offset / vulnerabilityPageSize),
    Math.floor(Math.max(0, total - 1) / vulnerabilityPageSize)) * vulnerabilityPageSize;
  const rows = matches.slice(offset, offset + vulnerabilityPageSize).map(({ row }) => row);
  return { rows, offset, total, partial: false };
}

export async function call<T>(command: string, args?: Record<string,unknown>): Promise<T> {
  if (!preview) return invoke<T>(command,args);
  if(command==='local_resource_sample')return {cpuPercent:1.4,memoryBytes:177209344,rxBytes:194560,txBytes:33280,durationMs:5000} as T;
  if(command==='ai_profiles') return {revision:1,providers:{codex:{low:{model:'gpt-6-luna',effort:'high'},medium:{model:'gpt-6.1-terra',effort:'high'},high:{model:'gpt-6.1-sol',effort:'high'}},claude:{low:{model:'haiku',effort:'high'},medium:{model:'sonnet',effort:'high'},high:{model:'opus',effort:'high'}}}} as T;
  if(command==='action_requests'){const r=previewAction();return (new URLSearchParams(location.search).has('demoActions')&&(!args?.serverId||args.serverId===r.serverId)?[{...r,goal:r.artifact.spec.goal,action:r.artifact.spec.action,sessionGranted:false}]:[]) as T;}
  if(command==='action_request')return previewAction() as T;
  if(command==='update_settings'){previewSettings={...previewSettings,...args?.patch as Partial<Settings>};return {...previewSettings} as T;}
  if(command==='incident_groups')return {groups:[],total:0} as T;
  if(command==='group_investigations')return [] as T;
  if(command==='notification_status')return {enabled:true,permission:'unavailable',error:null,queued:0,overflow:0} as T;
  if(command==='take_notification_target')return {open:false,incidentIds:[]} as T;
  if(command==='server_dependencies'){
    const available=previewSnapshot().servers.filter(s=>s.id!==args?.id).map(s=>({id:s.id,name:s.name,host:s.endpoint.host,address:serverAddress(s.endpoint)}));
    return {available,dependsOn:available.filter(s=>s.id==='demo-2').map(s=>s.id)} as T;
  }
  if (command === 'list_service_instances') {
    const cards = previewSnapshot().services?.[String(args?.id)] ?? [];
    return Object.entries(serviceCatalog).flatMap(([kind, spec]) => {
      const matches = cards.filter(card => card.kind === kind);
      const base = matches.find(card => !card.instanceId || card.instanceId === 'default');
      return [
        {id:'default',kind,name:base?.name ?? spec.name,canAdd:spec.multiple,canRemove:false},
        ...matches.filter(card => card.instanceId && card.instanceId !== 'default')
          .map(card => ({id:card.instanceId,kind,name:card.name,canAdd:spec.multiple,canRemove:true})),
      ];
    }) as T;
  }
  if (command === 'service_catalog') return serviceCatalog as T;
  if (command === 'service_summary') {
    const kind = String(args?.kind ?? '');
    const spec = serviceCatalog[kind];
    const config = spec?.actions.includes('configure') ? {
      enabled:false, endpoint:spec.endpoint, port:spec.port, user:'', intervalSeconds:180,
      expectedPeers:0, expectReplica:false, ...spec.profileDefaults,
    } : null;
    return {kind,config,summary:null,evidence:[],error:null,fresh:false,status:'unknown',nextCheck:0} as T;
  }
  if(command==='activity_log') { const query=args?.query as ActivityQuery|undefined; const events=Array.from({length:12},(_,i)=>({id:`demo:${i}`,at:Date.now()-i*21000,category:['ssh','server','ai','mcp','app','app'][i%6],action:['SSH connection','Collect metrics','Codex','get_server','update_settings','sync_source'][i%6],phase:i===2?'started':i===6?'failed':'completed',operationId:`demo-operation-${i}`,target:i%6<2?`ops@${previewServerHost(0)}:22`:null,runId:i===2?'demo-run':null,durationMs:i===2?null:230+i*12})).filter(e=>(!query?.category||e.category===query.category)&&(!query?.phase||e.phase===query.phase)&&(!query?.search||e.target?.includes(query.search))); return {events,next:null,expired:false,skipped:0,storage:{bytes:4800,limitBytes:31457280,dropped:0,error:null}} as T; }
  if (command==='storage_status') return {databaseBytes:0,walBytes:0,limitBytes:1073741824,cacheBytes:0,cacheLimitBytes:134217728,activity:{bytes:4800,limitBytes:31457280,dropped:0,error:null},blocked:false,message:null} as T;
  if (command==='vulnerability_summary') return previewVulnerabilities(args?.id,Boolean(args?.includeHidden)) as T;
  if (command === 'vulnerability_catalog') {
    return previewVulnerabilityPage(previewSnapshot().servers, args?.query as VulnerabilityCatalogQuery) as T;
  }
  if (command === 'vulnerability_catalog_detail') {
    const entry = previewVulnerabilityCatalog(previewSnapshot().servers).find(({ row }) => row.cve === args?.cve);
    if (!entry) throw new Error('The recording is no longer available.');
    return entry.detail as T;
  }
  if (command==='snapshot') return previewSnapshot() as T;
  if (command==='auto_status') return {day:Math.floor(Date.now()/86400000),runs:0,actualTokens:0,chargedTokens:0,reservedTokens:0,uncertainRuns:0,blockedReason:null,waitingReason:null,queued:0,jobs:[]} as T;
  if (command==='investigations') return [] as T;
  if (command==='log_summary') return {shortCheck:false,lastIncomplete:null,summary:null,lastSuccess:null,nextCheck:0,error:null,fresh:false} as T;
  if (command==='history') return [] as T;
  if (command==='detect_agents') return [] as T;
  throw new Error('This is a demonstration of the interface. Run the desktop through the npm run desktop.');
}
