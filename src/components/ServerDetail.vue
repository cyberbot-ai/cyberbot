<script setup lang="ts">
import { serverAddress, serverDisplayHost, serverHint } from '../serverDirectory';
import ServerTabBar from './ServerTabBar.vue';
import RefreshButton from './RefreshButton.vue';
import MetricValue from './MetricValue.vue';
import RelativeDate from './RelativeDate.vue';
import DependenciesPanel from './DependenciesPanel.vue';
import UiIcon from './UiIcon.vue';
import IncidentList from './IncidentList.vue';
import ResolveAllIncidentsButton from './ResolveAllIncidentsButton.vue';
import CheckPanel from './CheckPanel.vue';
import ServiceInstances from './ServiceInstances.vue';
import { serviceCatalog } from '../services';
import LogPanel from './LogPanel.vue';
import VulnerabilityPanel from './VulnerabilityPanel.vue';
import InvestigationPanel from './InvestigationPanel.vue';
import { computed, defineAsyncComponent, onBeforeUnmount, ref, watch } from 'vue';
import { call, preview } from '../api';
import { health, healthLabel, resourceHealth, serverHealthLabel, partialHealthReason, percent, type Resource } from '../health';
import type { Incident, Observation, Server } from '../types';
const props=defineProps<{server:Server; now:number; interval:number;standalone?:boolean;incidents?:Incident[];initialSection?:'overview'|'incidents';initialShowResolved?:boolean;aiAgent?:string}>();
const emit=defineEmits<{close:[];detach:[];updated:[];error:[message:string];aiSettings:[]}>();
const serverIncidents=computed(()=>props.incidents?.filter(i=>i.serverId===props.server.id)??[]);
const activeIncidents=computed(()=>serverIncidents.value.filter(i=>i.status==='open'));
const showResolved=ref(props.initialShowResolved??false);
const incidentRows=computed(()=>showResolved.value?serverIncidents.value:activeIncidents.value);
const showDependencies=ref(false),showUndetected=ref(false);
const samples = ref<Observation[]>([]);
const refreshing = ref(new Set<string>());
const busy = computed(() => refreshing.value.has(props.server.id));
const refreshMessage = ref('');
const refreshError = ref('');
const refreshRevision = ref(0);
const metricsError = computed(() => !props.server.awaitingFirstCheck && props.server.lastError !== refreshError.value
  ? props.server.lastError : null);
watch(() => props.server.id, () => {
  refreshMessage.value = '';
  refreshError.value = '';
});
watch(() => props.server.observation?.at, () => { refreshError.value = ''; });
const initialTab=()=>props.initialSection??(activeIncidents.value.length?'incidents':'overview');
const defaultService = Object.keys(serviceCatalog).find(kind => serviceCatalog[kind].preferred) ?? Object.keys(serviceCatalog)[0];
const section=ref<string>(initialTab()),service=ref(defaultService);
// A question from another tab is sent once by the AI panel; the id distinguishes repeated asks.
const aiAsk=ref<{id:number;text:string}>();let askId=0;
function askAi(text:string){aiAsk.value={id:++askId,text};section.value='investigation';}
const ServerConsole=defineAsyncComponent(()=>import('./ServerConsole.vue'));
const tabs=[{id:'overview',label:'Overview'},{id:'incidents',label:'Incidents'},{id:'services',label:'Services'},{id:'logs',label:'Logs'},{id:'security',label:'Vulnerabilities'},{id:'checks',label:'Checks'},{id:'investigation',label:'AI'},{id:'console',label:'Console'}];
const activePanel=computed(()=>({services:ServiceInstances,logs:LogPanel,security:VulnerabilityPanel,checks:CheckPanel,investigation:InvestigationPanel})[section.value as 'services'|'logs'|'security'|'checks'|'investigation']);
const serviceOptions=computed(()=>Object.entries(serviceCatalog).flatMap(([kind,s])=>{
 const cards=props.server.services?.filter(c=>c.kind===kind)??[];
 if(cards.length)return cards.map(c=>({id:c.instanceId&&c.instanceId!=='default'?`${kind}@${c.instanceId}`:kind,kind,instanceId:c.instanceId??'default',name:c.name,status:c.status,found:c.detected??c.status!=='not_detected'}));
 return [{id:kind,kind,instanceId:'default',name:s.name,status:'',found:false}];
}).sort((a,b)=>{const rank=(s:string|undefined)=>s==='critical'?0:s==='warning'?1:s==='healthy'?2:s==='unknown'?3:4;return rank(a.status)-rank(b.status)||a.name.localeCompare(b.name);}));
const selectedService=computed(()=>{const [kind,instanceId='default']=service.value.split('@');return {kind,instanceId};});
const serviceRefreshKey=computed(()=>{
 const {kind,instanceId}=selectedService.value;
 const card=props.server.services?.find(c=>c.kind===kind&&(c.instanceId??'default')===instanceId);
 const scope=`${serviceCatalog[kind]?.incidentNamespace ?? 'service:'}${service.value}:`;
 return JSON.stringify([refreshRevision.value,card?.status,card?.availability,card?.at,activeIncidents.value.filter(i=>i.check.startsWith(scope)).map(i=>i.episode??i.id)]);
});
function selectConnection(id:string){service.value=id==='default'?selectedService.value.kind:`${selectedService.value.kind}@${id}`;}
// Only services seen on the server are shown as chips; the rest stay one click away for manual setup.
const visibleServices=computed(()=>serviceOptions.value.filter(s=>s.found||s.id===service.value||showUndetected.value));
const hiddenServices=computed(()=>serviceOptions.value.filter(s=>!s.found&&s.id!==service.value).length);
const status=computed(()=>health(props.server,props.now,props.interval));
const coverageNote = computed(() => partialHealthReason(props.server, status.value));
const level=(s:string|undefined)=>s==='critical'?'critical':s==='warning'?'warning':'';
const vulnerabilityCount = computed(() => props.server.vulnerabilities?.affected ?? 0);
const tabMarks=computed<Record<string,string>>(()=>{const worst=serviceOptions.value[0]?.status;return {services:level(worst),logs:level(props.server.logStatus),security:vulnerabilityCount.value ? 'critical' : '',checks:level(props.server.checkStatus)};});
const pressure=(resource:Resource,value:number|null|undefined)=>level(resourceHealth(props.server,resource,value));
const currentObservation = computed(() => props.server.networkOffline ? null : props.server.observation);
const fullestDisk=computed(()=>[...currentObservation.value?.disks??[]].sort((a,b)=>b.usedPercent-a.usedPercent)[0]);
function openService(id:string){service.value=id;section.value='services';}
let historyRevision = 0;
watch(()=>props.server.id,()=>{historyRevision++;samples.value=[];aiAsk.value=undefined;showResolved.value=props.initialShowResolved??false;section.value=initialTab();showUndetected.value=false;service.value=serviceOptions.value.find(s=>s.found)?.id??defaultService;},{immediate:true});
watch(()=>props.initialSection,()=>{section.value=initialTab();});
watch(()=>props.initialShowResolved,value=>{showResolved.value=value??false;});
async function loadHistory(id: string) {
  const revision = ++historyRevision;
  try {
    const history = await call<Observation[]>('history', { id });
    if (revision === historyRevision && props.server.id === id) samples.value = history;
  } catch (error) {
    if (revision === historyRevision && props.server.id === id) emit('error', String(error));
  }
}
watch([() => props.server.id, () => props.server.observation?.at, () => section.value === 'overview'], ([id, , visible]) => {
  if (visible) void loadHistory(id);
  else historyRevision++;
}, { immediate: true });
onBeforeUnmount(() => { historyRevision++; });
const cpuChart = computed(() => {
  const history = samples.value.filter(sample => Number.isFinite(sample.at));
  if (history.length < 2) return '';
  const start = history[0].at;
  const span = Math.max(1, history[history.length - 1].at - start);
  const maxGap = (props.server.monitoring?.intervalSeconds ?? props.interval) * 2 + 30;
  const path: string[] = [];
  let previous: number | undefined;
  let count = 0;
  for (const { at, cpuPercent } of history) {
    if (cpuPercent == null || !Number.isFinite(cpuPercent)) {
      previous = undefined;
      continue;
    }
    const point = `${(at - start) * 600 / span},${100 - Math.max(0, Math.min(100, cpuPercent))}`;
    path.push(previous == null || at - previous > maxGap ? `M${point} L${point}` : `L${point}`);
    previous = at;
    count++;
  }
  return count >= 2 ? path.join(' ') : '';
});
async function refreshServer() {
  const id = props.server.id;
  if (refreshing.value.has(id)) return;
  refreshError.value = '';
  refreshMessage.value = '';
  refreshing.value.add(id);
  try {
    const result = await call<{ updated: number; failed: string[] }>('poll_server', { id });
    if (props.server.id === id) {
      refreshRevision.value++;
      refreshMessage.value = result.failed.length
        ? `${result.updated} checks updated · ${result.failed.length} incomplete`
        : 'Server refreshed';
    }
  } catch (error) {
    if (props.server.id === id) {
      refreshRevision.value++;
      refreshError.value = String(error).replace(/^Error: /, '');
    }
  } finally {
    refreshing.value.delete(id);
    emit('updated');
  }
}

</script>
<template><section class="detail"><header class="server-header"><div class="server-title"><div class="server-heading">
  <h2 :title="serverHint(server)">{{serverDisplayHost(server.name, server.endpoint.host)}}</h2>
  <RefreshButton :disabled="preview || busy" :aria-busy="busy" @click="refreshServer">{{ busy ? 'Refreshing…' : 'Refresh server' }}</RefreshButton>
</div><p>{{serverAddress(server.endpoint)}}</p>
<div class="status" :class="status"><span class="state"><i></i>{{serverHealthLabel(server,status)}}</span><span v-if="server.observation?.platform">{{server.observation.platform.distro}} {{server.observation.platform.versionId}}</span></div>
<div v-if="coverageNote" class="coverage-note">{{ coverageNote }}</div></div>
<div class="header-actions"><button v-if="!standalone" class="icon-button" :disabled="preview" title="Open in new window" aria-label="Open in new window" @click="emit('detach')"><UiIcon name="external"/></button><button class="icon-button" aria-label="Close server" @click="$emit('close')"><UiIcon name="close"/></button></div></header>
<p v-if="server.networkOffline" class="notice connectivity-notice" role="status">No internet connection. Server data is temporarily unavailable.</p>
<p v-if="refreshError" class="poll-message alert" role="alert">{{ refreshError }}</p>
<p v-else-if="refreshMessage" class="poll-message notice" role="status">{{ refreshMessage }}</p>
<nav class="detail-tabs" aria-label="Server sections"><button v-for="tab in tabs" :key="tab.id" :class="{active:section===tab.id}" :aria-pressed="section===tab.id" @click="section=tab.id">{{tab.label}}<span v-if="tab.id==='security'&&vulnerabilityCount" class="count" :class="tabMarks.security" :title="`Vulnerabilities confirmed: ${vulnerabilityCount}`">{{vulnerabilityCount}}</span><i v-else-if="tabMarks[tab.id]" class="mark" :class="tabMarks[tab.id]" :title="healthLabel[tabMarks[tab.id] as 'warning'|'critical']"></i></button></nav>
<div class="detail-content" :class="{'chat-content':section==='investigation','console-content':section==='console'}">
  <template v-if="section==='overview'">
    <ServerTabBar title="Metrics">
      <RelativeDate :at="currentObservation?.at" empty="Not checked yet"/>
    </ServerTabBar>
    <p v-if="server.awaitingFirstCheck && !server.networkOffline" class="notice" role="status">Waiting for the first check to collect data.</p>
    <div v-if="metricsError && !server.networkOffline" class="alert" role="alert">{{metricsError}}</div>
  <div class="metrics">
    <div :class="pressure('cpu',currentObservation?.cpuPercent)"><small>CPU</small><strong><MetricValue :value="currentObservation?.cpuPercent" :precision="0" unit="%"/></strong><svg v-if="cpuChart && !server.networkOffline" class="spark" viewBox="0 0 600 100" preserveAspectRatio="none" aria-hidden="true"><path :d="cpuChart" fill="none" class="chart-line" vector-effect="non-scaling-stroke" stroke-width="1.5" stroke-linecap="round"/></svg></div>
    <div :class="pressure('memory',currentObservation?.memoryPercent)"><small>Memory</small><strong><MetricValue :value="currentObservation?.memoryPercent" :precision="0" unit="%"/></strong><span class="sub">swap {{percent(currentObservation?.swapPercent)}}</span></div>
    <div :class="pressure('disk',fullestDisk?.usedPercent)"><small>Disk</small><strong><MetricValue :value="fullestDisk?.usedPercent" :precision="0" unit="%"/></strong><code class="sub">{{fullestDisk?.mount??'no data'}}</code></div>
    <div><small>Load average</small><strong><MetricValue :value="currentObservation?.load" :precision="2"/></strong><span class="sub">1 minute</span></div>
  </div>
  <section class="chart"><h3>CPU usage <small>recent observations</small></h3><svg v-if="cpuChart" viewBox="0 0 600 110" preserveAspectRatio="none" role="img" aria-label="CPU usage history"><path d="M0 25H600 M0 50H600 M0 75H600 M0 100H600" class="chart-grid" fill="none" vector-effect="non-scaling-stroke"/><path :d="cpuChart" fill="none" class="chart-line" stroke-width="2" stroke-linecap="round" vector-effect="non-scaling-stroke"/></svg><p v-else class="chart-empty">The chart will appear after two CPU readings.</p></section>
  <section class="resource-section"><h3>Disks</h3><div v-for="disk in currentObservation?.disks" :key="disk.mount" class="disk"><code>{{disk.mount}}</code><span class="bar"><i :class="pressure('disk',disk.usedPercent)" :style="{width:`${Math.min(100,Math.max(0,disk.usedPercent))}%`}"></i></span><span class="value" :class="pressure('disk',disk.usedPercent)">{{percent(disk.usedPercent)}}</span><small>inode {{percent(disk.inodePercent)}}</small></div><p v-if="!currentObservation?.disks.length" class="notice">Disk data is not available yet.</p></section>
  <details v-if="currentObservation" class="resource-section"><summary>OS and services</summary><div class="columns">
    <section class="resource-section"><h3>System services <small v-if="currentObservation?.services.length">{{currentObservation.services.length}}</small></h3><div v-if="currentObservation?.services.length" class="os-services"><span v-for="item in currentObservation.services" :key="item.name" :class="{'text-error':item.state==='failed'}" :title="item.state"><i :class="item.state==='active'?'healthy':item.state==='failed'?'critical':''"></i>{{item.name.replace(/\.service$/,'')}}</span></div><p v-else class="notice">Services not yet discovered.</p></section>
    <section v-if="currentObservation?.platform" class="resource-section"><h3>Operating system</h3><dl class="kv"><dt>Linux</dt><dd>{{currentObservation.platform.distro}} {{currentObservation.platform.versionId}} · {{currentObservation.platform.architecture}}</dd><dt>Services</dt><dd>{{currentObservation.platform.initSystem}}<small v-if="currentObservation.platform.serviceAdapter==='unsupported'"> · the adapter is not yet supported</small></dd><dt>Packages</dt><dd>{{currentObservation.platform.packageManager}}<small v-if="currentObservation.platform.packageAdapter==='unsupported'"> · collection is not yet supported</small></dd></dl><p v-if="currentObservation.platform.advisoryProvider==='unsupported'" class="notice">Package vulnerability checks are unavailable for this distribution.</p></section>
  </div></details>
  <details v-if="currentObservation?.missing.length" class="small"><summary>What’s tested</summary><p>Unavailable data: {{currentObservation.missing.join(', ')}}</p></details>
  <details class="resource-section" @toggle="showDependencies=($event.target as HTMLDetailsElement).open"><summary>Server dependencies</summary><DependenciesPanel v-if="showDependencies" :key="server.id" :server-id="server.id"/></details></template>
  <section v-if="section==='incidents'" class="server-incidents" aria-label="Server incidents">
    <ServerTabBar title="Incidents"><span>Open {{ activeIncidents.length }}</span></ServerTabBar>
    <div class="incident-toolbar">
      <label class="incident-history"><input v-model="showResolved" type="checkbox">Show resolved</label>
      <ResolveAllIncidentsButton :incidents="activeIncidents" title="Mark open incidents on this server as resolved"
        @updated="emit('updated')" @error="emit('error',$event)"/>
    </div>
    <IncidentList v-if="incidentRows.length" :incidents="incidentRows" :openable="false" @updated="emit('updated')" @error="emit('error',$event)"/>
    <p v-else class="notice">{{showResolved?'This server has no incidents.':'No open incidents.'}}</p>
  </section>
  <KeepAlive :key="server.id">
    <component :key="section==='services'?service:section" :is="activePanel" v-if="activePanel"
      v-bind="section==='investigation'?{aiAgent,ask:aiAsk}:section==='security'?{refreshKey:JSON.stringify([refreshRevision,server.vulnerabilities])}:section==='logs'?{refreshKey:JSON.stringify([refreshRevision,server.logStatus])}:section==='services'?{refreshKey:serviceRefreshKey}:{}"
      @ai-settings="emit('aiSettings')" @ask="askAi" :server-id="server.id" :kind="selectedService.kind"
      :initial-instance="selectedService.instanceId" hide-selector :now="now" @select="selectConnection" @updated="emit('updated')">
      <template v-if="section==='services'" #before-content>
        <div class="service-tabs" aria-label="Diagnostics of service">
          <button v-for="item in visibleServices" :key="item.id" :aria-pressed="service===item.id"
            :class="{active:service===item.id,undetected:!item.found}" @click="openService(item.id)">
            <i :class="item.status"/>{{item.name}}
          </button>
          <button v-if="hiddenServices" class="more" :aria-expanded="showUndetected" @click="showUndetected=!showUndetected">{{showUndetected?'Hide undiscovered':`Show ${hiddenServices} undetected services`}}</button>
        </div>
      </template>
    </component>
  </KeepAlive>
  <KeepAlive :key="`console:${server.id}`">
    <ServerConsole v-if="section==='console'" :server-id="server.id"/>
  </KeepAlive>
</div></section></template>
<style scoped>
.connectivity-notice{margin:0 18px 8px;color:var(--warning);background:var(--warning-bg);padding:9px 12px;border-radius:7px}
.server-incidents{margin-bottom:20px}.incident-toolbar{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px 12px;margin-bottom:16px}.incident-history{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted)}.incident-history input{accent-color:var(--accent)}
.detail{display:flex;flex-direction:column;color:var(--text);font:13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;height:100%;min-width:0;box-sizing:border-box}.server-header{display:flex;justify-content:space-between;gap:16px;padding:22px 28px 0}.server-title{min-width:0}.server-heading{display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px}.server-heading button{font-size:12px;padding:4px 9px}.poll-message{margin:8px 28px 0}.coverage-note{margin-top:6px;color:var(--muted);font-size:12px;line-height:1.5;overflow-wrap:anywhere}h2{font-size:22px;font-weight:600;margin:4px 0 2px;letter-spacing:-.4px;overflow-wrap:anywhere}.server-header p{font:12px/1.5 ui-monospace,monospace;color:var(--muted);margin:0;overflow-wrap:anywhere}.header-actions{flex-shrink:0;display:flex;align-items:flex-start;gap:4px}button{font:inherit;color:inherit;display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--line);background:var(--surface);border-radius:7px;padding:7px 12px;cursor:pointer;min-height:32px}button:hover{background:var(--hover)}button:disabled{opacity:.45;cursor:default}button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.icon-button{border:0;background:none;padding:8px}
.status{display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px;margin-top:8px;color:var(--muted);font-size:12px}.state{display:inline-flex;align-items:center;gap:6px;padding:1px 9px;border-radius:20px;background:var(--subtle);color:var(--muted)}.status i{width:6px;height:6px;border-radius:50%;background:var(--muted)}.status.healthy .state{background:var(--accent-bg);color:var(--success)}.status.healthy i{background:var(--success)}.status.warning .state{background:var(--warning-bg);color:var(--warning)}.status.warning i{background:var(--warning)}.status.critical .state,.status.unreachable .state{background:var(--danger-bg);color:var(--danger)}.status.critical i,.status.unreachable i{background:var(--danger)}
.detail-tabs{display:flex;gap:22px;overflow-x:auto;padding:0 28px;margin-top:14px;border-bottom:1px solid var(--line);flex-shrink:0}.detail-tabs button{background:none;border:0;border-bottom:2px solid transparent;border-radius:0;padding:11px 0;color:var(--muted);font-size:13px;white-space:nowrap;gap:6px}.detail-tabs button.active{color:var(--text);border-bottom-color:var(--accent)}.mark{width:6px;height:6px;border-radius:50%}.mark.warning{background:var(--warning)}.mark.critical{background:var(--danger)}.count{font-size:11px;line-height:16px;padding:0 6px;border-radius:9px;background:var(--subtle)}.count.warning{background:var(--warning-bg);color:var(--warning)}.count.critical{background:var(--danger-bg);color:var(--danger)}
.detail-content{flex:1;min-height:0;overflow:auto;padding:22px 28px 40px;scrollbar-color:var(--line-strong) transparent}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:24px}.metrics>div{min-width:0;display:flex;flex-direction:column;gap:2px;background:var(--subtle);border-radius:10px;padding:12px 14px}.metrics strong{min-width:0;max-width:100%;font-size:24px;font-weight:450;font-variant-numeric:tabular-nums;letter-spacing:-.5px}.metrics .sub{font-size:11.5px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.metrics>.warning{background:var(--warning-bg)}.metrics>.warning strong{color:var(--warning)}.metrics>.critical{background:var(--danger-bg)}.metrics>.critical strong{color:var(--danger)}.spark{width:100%;height:20px}
small{font-size:12px;color:var(--muted);font-weight:400}h3{font-size:14px;font-weight:600;margin:0 0 8px;display:flex;align-items:baseline;gap:8px}.chart h3{justify-content:space-between}.chart svg{width:100%;height:120px}.chart-grid{stroke:var(--line)}.chart-line{stroke:var(--accent)}.chart-empty{padding:32px 16px;text-align:center;color:var(--muted);background:var(--subtle);border-radius:8px;font-size:12px}.resource-section{margin-top:24px}
.disk{display:grid;grid-template-columns:minmax(80px,170px) minmax(0,1fr) 44px 80px;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)}.disk code{overflow-wrap:anywhere;font-size:12px}.disk small{text-align:right}.bar{height:6px;border-radius:3px;background:var(--subtle);overflow:hidden}.bar i{display:block;height:100%;border-radius:3px;background:var(--accent)}.bar i.warning{background:var(--warning)}.bar i.critical{background:var(--danger)}.value{text-align:right;font-variant-numeric:tabular-nums}.value.warning{color:var(--warning)}.value.critical{color:var(--danger)}
.columns{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:28px}.os-services{display:flex;flex-wrap:wrap;gap:6px 14px}.os-services span{display:inline-flex;align-items:center;gap:6px}.os-services i{width:6px;height:6px;border-radius:50%;background:var(--line-strong)}.os-services i.healthy{background:var(--success)}.os-services i.critical{background:var(--danger)}.kv{display:grid;grid-template-columns:auto minmax(0,1fr);gap:6px 16px;margin:0}.kv dt{color:var(--muted)}.kv dd{margin:0;text-align:right;overflow-wrap:anywhere}
details>summary{cursor:pointer;color:var(--muted)}.alert{padding:12px;margin-bottom:16px;background:var(--danger-bg);color:var(--danger);border-radius:7px;overflow-wrap:anywhere}.notice{overflow-wrap:anywhere;color:var(--muted);line-height:1.6}.notice.small{font-size:12px;margin-top:18px}.text-error{color:var(--danger)}
.service-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:20px}.service-tabs button{border:0;background:none;color:var(--muted)}.service-tabs button.active{background:var(--hover);color:var(--text)}.service-tabs .more{font-size:12px}.service-tabs i{width:6px;height:6px;flex-shrink:0;border-radius:50%;background:var(--muted)}.service-tabs i.healthy{background:var(--success)}.service-tabs i.warning{background:var(--warning)}.service-tabs i.critical{background:var(--danger)}
.service-tabs button.undetected{color:#6a6a6a}
.app[data-theme=dark] .service-tabs button.undetected{color:#999}
.service-tabs .undetected i{background:currentColor;opacity:.5}
@media(max-width:700px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.columns{grid-template-columns:1fr;gap:0}}
@media(max-width:600px){.server-header{padding:18px 18px 0}.detail-tabs{padding-inline:18px;gap:18px}.detail-content{padding:20px 18px 32px}.metrics strong{font-size:21px}.chart h3 small{display:none}.disk{grid-template-columns:minmax(0,1fr) 44px;}.disk .bar,.disk small{display:none}}
.detail-content.chat-content,.detail-content.console-content{display:flex;flex-direction:column;padding-bottom:16px}
</style>
