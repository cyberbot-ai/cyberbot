// Local visual fixture. There is no SSH, Tauri invocation or model connection.
import { ref } from 'vue';
import catalog from '../../collectors/connectors/catalog.json';
export const preview=true;
export const scenario=ref('normal');
export const value=()=>scenario.value==='normal'?12.4:scenario.value==='maximum'?Number.MAX_VALUE:12884901888.5;
export async function call<T>(command:string,args?:Record<string,unknown>):Promise<T>{
  const n=value(),at=Date.now()/1000;
  const config={enabled:true,database:'postgres',endpoint:'127.0.0.1',port:5432,user:'ops',intervalSeconds:180,expectedPeers:0,expectReplica:false};
  const timing={samples:1,sumMs:n,maxMs:n,slow:1,histogram:Array(14).fill(1)};
  let result:unknown;
  switch(command){
    case 'service_catalog':result=catalog;break;
    case 'history':result=[];break;
    case 'server_dependencies':result={available:Array.from({length:100},(_,i)=>({id:`node-${i}`,name:scenario.value==='normal'?`${['web','api','db','cache'][i%4]}-${i+1}`:'server-with-a-very-long-name-'.repeat(10)+(i+1)})),dependsOn:['node-2','node-3']};break;
    case 'service_summary':{
      if (args?.kind === 'postgresql') { result={config,status:'healthy',fresh:true,error:null,evidence:[],summary:{id:'fixture',at,bytesReceived:1024,findings:[],data:{connected:true,coverage:true,issues:[],durationMs:20,meta:{version:150000,fullStats:true,superuser:false,recovery:false},metrics:{connections:n,maxConnections:n*1.1,reservedConnections:3,active:n,longQueries:n,longestQuerySeconds:n,blocked:n,maxWaitSeconds:n,idleTransactions:n,blockers:[],streaming:n,receiver:n,replicaBacklogBytes:n,replayBacklogBytes:n,replicationUnknown:false,slotRetainedBytes:n,inactiveSlots:n,autovacuumWorkers:n,xidAge:n,deadlocks:n,rollbacks:n}}}}; break; }
      if (args?.kind === 'nginx') { result={fresh:true,error:null,card:{status:'healthy'},evidence:[],summary:{detected:true,receivedAt:at,service:'active',windowSeconds:600,coverage:{complete:true,initial:false,gaps:[]},rps:n,rpsSource:'access_log',counts:{'5xx':n,requests:n,'4xx':n},requestTime:timing,upstreamTime:timing,status:{active:n,reading:n,writing:n,waiting:n},missing:[],examples:[],findings:[],bytesReceived:1000,bytesRead:2000,durationMs:10}}; break; }
      const spec=catalog[args?.kind as keyof typeof catalog];
      const metrics=Object.fromEntries(spec.metrics.map(m=>[m.key,n]));
      result={config,status:'healthy',fresh:true,error:null,summary:{id:'fixture',at,bytesReceived:1024,data:{complete:true,issues:[],metrics,durationMs:20},rates:metrics,findings:[]},evidence:[]};break;
    }
    case 'log_summary': {
      const check = 'logs:new_error_pattern';
      const text = 'worker: Error reopening state file /var/lib/worker/' + (scenario.value === 'normal' ? 'state.db' : 'long-file-name-'.repeat(13) + '…');
      result = {
        fresh:true,lastSuccess:at,error:null,
        findingExamples:{[check]:{at,source:'journal',text}},
        summary:{remoteAt:at,windowSeconds:600,coverage:{complete:true,initial:false,sources:['journal'],gaps:[]},
          counts:{ssh_failed:n,ssh_banned:n,system_error:n},examples:[],
          findings:[{check,title:'A new recurring error pattern',severity:'warning',count:231}],
          learning:false,bytesReceived:1024,bytesRead:2048,durationMs:10},
      };
      break;
    }
    default:throw new Error(`No surgery at the booth: ${command}`);
  }
  return result as T;
}
