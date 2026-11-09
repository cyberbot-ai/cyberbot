<script setup lang="ts">
import ServerLink from './ServerLink.vue';
import RelativeDate from './RelativeDate.vue';
import ResolveIncidentButton from './ResolveIncidentButton.vue';
import {ref,watch,onMounted,onUnmounted} from 'vue';
import {call,preview} from '../api';
import type {IncidentGroup,GroupView,Investigation} from '../types';
const props=defineProps<{now:number;showResolved:boolean;refreshKey?:string}>();
const emit=defineEmits<{count:[n:number];updated:[];aiSettings:[]}>();
const groups=ref<IncidentGroup[]>([]),total=ref(0),offset=ref(0),selected=ref(''),view=ref<GroupView>(),page=ref(0),runs=ref<Investigation[]>([]),busy=ref(false),error=ref('');
let revision=0,detailRevision=0,timer:ReturnType<typeof setInterval>|undefined;
const states:Record<string,string>={open:'Open',resolved:'Resolved',withdrawn:'Completed with incomplete data'};
const autoStates:Record<string,string>={running:'Investigation in progress',completed:'Investigation completed',failed:'Investigation failed',cancelled:'Investigation cancelled',interrupted:'Investigation interrupted',dismissed:'Skipped',budget_exceeded:'Budget exhausted'};
async function refresh(){const r=++revision;try{const result=await call<{groups:IncidentGroup[];total:number}>('incident_groups',{includeClosed:props.showResolved,offset:offset.value});if(r!==revision)return;groups.value=result.groups;total.value=result.total;emit('count',result.total);}catch(e){if(r===revision)error.value=String(e);}}
async function detail(){if(!selected.value)return;const r=++detailRevision;const id=selected.value;try{const [v,history]=await Promise.all([call<GroupView>('incident_group',{id,offset:page.value}),call<Investigation[]>('group_investigations',{id})]);if(r!==detailRevision||id!==selected.value)return;view.value=v;runs.value=history;}catch(e){if(r===detailRevision)error.value=String(e);}}
async function resolved(){await refresh();await detail();emit('updated');}
function choose(id:string){selected.value=selected.value===id?'':id;page.value=0;view.value=undefined;runs.value=[];detailRevision++;if(selected.value)void detail();}
async function start(){busy.value=true;error.value='';try{await call('start_group_investigation',{id:selected.value});await detail();}catch(e){error.value=String(e);}finally{busy.value=false;}}
async function cancel(id:string){try{await call('cancel_investigation',{id});await detail();}catch(e){error.value=String(e);}}
function next(){page.value=view.value?.nextOffset??page.value;void detail();}
function first(){page.value=0;void detail();}
watch(()=>props.showResolved,()=>{offset.value=0;void refresh();});
watch(()=>props.refreshKey,()=>{void refresh();void detail();});
watch(offset,()=>{void refresh();});
onMounted(()=>{void refresh();timer=setInterval(()=>{if(!document.hidden){void refresh();void detail();}},15000);});
onUnmounted(()=>{revision++;detailRevision++;clearInterval(timer);});
</script>
<template><section v-show="total || error" class="groups" aria-label="Incident groups">
<p v-if="error" role="alert" class="error">{{error}} <button @click="emit('aiSettings')">AI settings</button></p>
<template v-if="total">
<h2>Incident groups <small>{{total}}</small></h2>
<p class="note group-intro">Incidents linked by timing and infrastructure. A shared cause has not been confirmed.</p>
<div v-if="groups.length" class="group-list">
<article v-for="group in groups" :key="group.id" class="group">
<button class="heading" :aria-expanded="selected===group.id" @click="choose(group.id)"><span class="group-title"><strong>{{group.title}}</strong><small>{{group.serverCount}} servers · {{group.memberCount}} events</small></span><span class="group-status" :class="group.status==='open'?group.severity:''">{{states[group.status]??group.status}}</span></button>
<div v-if="selected===group.id&&view" class="details"><p>{{view.group.reason}}. Opened <RelativeDate :at="view.group.openedAt"/>.</p><p>{{view.fresh}} fresh · {{view.open}} open<template v-if="view.group.removedMembers"> · {{view.group.removedMembers}} removed incidents · incomplete coverage</template></p><p v-if="view.group.autoState">{{autoStates[view.group.autoState]??view.group.autoState}}. New members are added to the group without restarting the automatic investigation.</p>
<details v-if="view.dependencies?.length"><summary>Declared dependencies on this page</summary><p v-for="edge in view.dependencies" :key="edge.join('→')"><ServerLink :id="edge[0]" section="incidents"/> → <ServerLink :id="edge[1]" section="incidents"/></p><p v-if="view.dependenciesTruncated">The dependency list was truncated.</p></details><ol class="timeline"><li v-for="member in view.members" :key="member.incident.episode||member.incident.id"><RelativeDate :at="member.incident.openedAt"/><ServerLink :id="member.incident.serverId" :name="member.serverName" :address="member.serverAddress" section="incidents"/><div class="member-title"><strong>{{member.incident.title}}</strong><ResolveIncidentButton :incident="member.incident" @resolved="resolved" @error="error=$event"/></div><span>{{member.incident.status==='open'?'Open':member.incident.status==='resolved'?(member.incident.resolvedByUserAt?'Manually resolved':'Restored'):'Outside the scope'}} · {{member.incident.check}}</span><p>{{member.incident.evidence}}</p><small>Updated <RelativeDate :at="member.incident.updatedAt"/> · {{member.incident.id}}<template v-if="member.truncated"> · truncated</template></small></li></ol>
<div class="actions"><button v-if="page" @click="first">First events</button><button v-if="view.nextOffset!==null" @click="next">Next events</button><small>Showing {{page+1}}–{{page+view.members.length}} of {{view.total}}</small></div>
<div class="actions"><button :disabled="busy||preview||runs.some(r=>r.status==='running')||!view.members.length" @click="start">Investigate incident group</button></div><p class="note">The investigation uses one budget and covers the affected servers and their declared dependencies at the time it starts.</p>
<details v-for="run in runs" :key="run.id" class="report" :open="run.status==='running'"><summary><RelativeDate :at="run.startedAt"/> · {{run.agent}} · {{run.origin==='auto'?'Automatic':'Manual'}} · {{run.status}}</summary><p>Scope: {{run.serverIds.length}} servers</p><button v-if="run.status==='running'" @click="cancel(run.id)">Stop</button><p v-if="run.error" class="error">{{run.error}} <button @click="emit('aiSettings')">AI settings</button></p><pre>{{run.text||'Starting the AI agent…'}}</pre></details>
</div></article>
</div>
<div v-if="offset || offset+groups.length<total" class="actions"><button v-if="offset" @click="offset=Math.max(0,offset-50)">Previous incident groups</button><button v-if="offset+groups.length<total" @click="offset+=50">Next incident groups</button></div>
</template></section></template>
<style scoped>
.groups { margin-bottom: 24px; }
h2 { margin: 0; font-size: 17px; font-weight: 550; }
.group-intro { margin: 6px 0 12px; }
.group-list { border: 1px solid var(--line); border-radius: 8px; background: var(--surface); overflow: hidden; }
.group + .group { border-top: 1px solid var(--line); }
.heading {
  width: 100%;
  border: 0;
  border-radius: 0;
  padding: 12px 16px;
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  background: transparent;
  text-align: left;
  overflow-wrap: anywhere;
}
.heading:hover, .heading[aria-expanded="true"] { background: var(--hover); }
.heading:focus-visible { outline-offset: -3px; }
.group-title { min-width: 0; display: grid; gap: 4px; }
.group-title strong { font-size: 14px; font-weight: 550; }
.group-status { max-width: 40%; text-align: end; }
.details { padding: 0 16px 16px; overflow-wrap: anywhere; }
.member-title{display:flex;justify-content:space-between;align-items:center;gap:12px}small,.note,p,time{color:var(--muted);font-size:12px;line-height:1.6}button,select{font:inherit;color:var(--text);border:1px solid var(--line);background:var(--surface);border-radius:7px;padding:8px 12px;cursor:pointer}button:disabled{opacity:.45;cursor:default}.timeline{list-style:none;padding:0;display:grid;gap:16px}.timeline li{border-left:2px solid var(--line);padding-left:16px;display:grid;gap:5px;overflow-wrap:anywhere}.timeline strong{font-size:13px}.timeline span{font-size:12px}.timeline p{margin:0}.actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:16px}label{display:flex;gap:8px;align-items:center;font-size:12px}.warning{color:var(--warning)}.critical,.error{color:var(--danger)}.error{background:var(--danger-bg);padding:10px;border-radius:7px}.report{margin-top:16px}.report summary{font-size:12px;color:var(--muted);cursor:pointer}pre{font:13px/1.7 -apple-system,BlinkMacSystemFont,sans-serif;white-space:pre-wrap;overflow-wrap:anywhere;max-height:500px;overflow:auto;background:var(--subtle);padding:14px;border-radius:8px}button:focus-visible,select:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
</style>
