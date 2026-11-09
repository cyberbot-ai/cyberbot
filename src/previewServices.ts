import type { ActionRequest, Server, ServiceCard } from './types';

// Fictional preview data for the browser.
export function previewServerHost(index: number): string {
  const group = Math.floor(index / 4);
  const role = index % 4;
  if (role < 2) return `s${group * 2 + role + 1}.app.example.com`;
  return `s${group + 1}.${role === 2 ? 'db' : 'worker'}.example.com`;
}

export function previewServiceCards(servers: Server[], now: number): Record<string, ServiceCard[]> {
  const services: Record<string, ServiceCard[]> = Object.fromEntries(servers.map((server, i) => [server.id,
    (i % 4 === 2 ? [
      {kind:'postgresql',instanceId:'default',name:'PostgreSQL:5432',status:'healthy',at:now},
      {kind:'postgresql',instanceId:'reports',name:'PostgreSQL:5433',status:i===6?'critical':'healthy',at:now},
      {kind:'redis',instanceId:'default',name:'Redis',status:'healthy',at:now},
    ] : i % 4 === 3 ? [
      {kind:'docker',name:'Docker',status:'healthy',at:now},
      {kind:'redis',instanceId:'queue',name:'Redis',status:'healthy',at:now},
    ] : [
      {kind:'nginx',name:'Nginx',status:'healthy',at:now},
      {kind:'php-fpm',name:'PHP-FPM',status:'healthy',at:now},
      {kind:'redis',instanceId:'default',name:'Redis',status:'healthy',at:now},
    ]) as ServiceCard[]
  ]));
  for (const [i, server] of servers.entries()) if (server.observation) server.observation.services = [
    {name:'sshd.service',state:'active'}, {name:'cron.service',state:'active'},
    ...(i % 4 === 3 ? [{name:'docker.service',state:'active'}] : [])
  ];
  return services;
}

export function previewAction():ActionRequest {
 const now=Math.floor(Date.now()/1000);
 const endpoint=JSON.stringify({host:previewServerHost(0),user:'root',port:22});
 return {id:'11111111-1111-4111-8111-111111111111',runId:'22222222-2222-4222-8222-222222222222',serverId:'demo-0',serverLabel:`root@${previewServerHost(0)}:22`,state:'awaitingApproval',createdAt:now-80,expiresAt:now+420,artifactHash:'b271dc018563a289'.repeat(4),decision:null,error:null,result:null,review:{id:'demo-low',verdict:{decision:'allow',explanation:'Only the number of worker_processes changes. The intermediary will check the original hash, save a copy and check the configuration before replacing it.',effects:['One directive of the main Nginx','Reload may interrupt some connections']},model:'Demonstration low',usage:{},usageComplete:true,tokens:1840},artifact:{runId:'22222222-2222-4222-8222-222222222222',scopeEndpoints:{'demo-0':endpoint,'demo-1':JSON.stringify({host:previewServerHost(1),user:'root',port:22})},endpoint,rules:'actions-v1',provider:'codex',profile:{revision:1,alias:'medium',primary:{model:'gpt-6.1-terra',effort:'high'},low:{model:'gpt-6-luna',effort:'high'}},spec:{serverId:'demo-0',goal:'Change the number of Nginx processes',code:"result = {'workerProcesses': '2'}",inputs:[],action:{kind:'nginx_workers',workerProcesses:'2',activation:'reload'},rollbackPlan:'Restore the exact backup and reload if the current hash matches.'},inputs:[],prepared:{before:'worker_processes auto;',after:'worker_processes 2;'},isolation:{files:false,network:false,processes:false}}};
}
