<script setup lang="ts">
import UiInput from './UiInput.vue';
import UiSelect from './UiSelect.vue';
import ServerTabBar from './ServerTabBar.vue';
import MetricValue from './MetricValue.vue';
import { exactMetric } from '../metrics';
import { serviceAvailabilityLabels } from '../services';
import RelativeDate from './RelativeDate.vue';
import {ref,watch,onActivated,onDeactivated,computed} from 'vue';
import {call,preview} from '../api';
import {useConfigAutosave} from '../useConfigAutosave';
import type {ConnectorSpec,ConnectorView,ConnectorConfig,ServiceDeviation} from '../types';
const props=defineProps<{serverId:string;kind:string;now:number;instanceId?:string;displayName?:string;refreshKey?:string}>();const emit=defineEmits<{updated:[]}>();
const spec=ref<ConnectorSpec>(),view=ref<ConnectorView>(),config=ref<ConnectorConfig>(),busy=ref(false),dirty=ref(false),error=ref('');let revision=0,active=true;
onActivated(()=>{active=true;void load();});onDeactivated(()=>{active=false;revision++;});
const statuses:Record<string,string>={healthy:'No issues found',critical:'Critical',warning:'Needs attention',unknown:'Status unconfirmed',not_detected:'Not found'};
const issues:Record<string,string>={endpoint_ambiguous:'Multiple listeners found. Select a local address and port.',endpoint_not_local:'No local service listener confirmed at this address and port',profile_disabled:'Diagnostic connection disabled',not_detected:'Standard installation checks did not find the service',client_missing:'The required client is missing from the server',unsupported_version:'Unsupported version or response format',credentials_unavailable:'Credentials are not available or do not meet the requirements',connection_denied:'Connection or operation not permitted',source_unavailable:'Statistics not available',partial_coverage:'Some checks could not run. A dash indicates an unknown value.',query_timeout:'Check timed out',response_limit:'Response size limit reached',counter_warmup:'Another observation is needed to calculate the rate',replication_lag_unknown:'Replication lag could not be determined'};
const tone=computed(()=>({healthy:'ok',warning:'warn',critical:'crit'} as Record<string,string>)[view.value?.status??'']??'');
const replication=computed(()=>spec.value?.replication);
async function load(){const rev=++revision;try{const [catalog,result]=await Promise.all([spec.value?Promise.resolve({[props.kind]:spec.value}):call<Record<string,ConnectorSpec>>('service_catalog'),call<ConnectorView>('service_summary',{id:props.serverId,kind:props.kind,...(props.instanceId?{instanceId:props.instanceId}:{})})]);if(rev!==revision)return;spec.value=catalog[props.kind];view.value=result;if(!dirty.value)config.value={...result.config};error.value='';}catch(e){if(rev===revision)error.value=String(e);}}
watch(()=>[props.serverId,props.kind,props.instanceId],()=>{dirty.value=false;view.value=undefined;spec.value=undefined;void load();},{immediate:true});
watch(()=>[props.now,props.refreshKey],()=>{if(active&&!document.hidden&&!busy.value)void load();});
const autosave=useConfigAutosave({command:'configure_service',scope:()=> ({id:props.serverId,kind:props.kind,...(props.instanceId?{instanceId:props.instanceId}:{})}),value:()=>config.value,dirty,error,saved:async()=>{await load();emit('updated');}});
async function act(save=false){if(save){await autosave.submit();return;}busy.value=true;error.value='';try{const args={id:props.serverId,kind:props.kind,...(props.instanceId?{instanceId:props.instanceId}:{})};if(save){await call('configure_service',{...args,config:config.value});dirty.value=false;}else await call('refresh_service',args);await load();emit('updated');}catch(e){error.value=String(e);}finally{busy.value=false;}}
function deviationValue(value:number,deviation:ServiceDeviation){
  const metric=spec.value?.metrics.find(m=>m.key===deviation.key.split(':').at(-1));
  const unit=metric?.rule?.mode==='delta_per_10m'?' per 10 min':presentation(value,metric?.unit??'').unit;
  const amount=metric?.unit==='bytes'?value/1048576:value;
  return amount.toLocaleString('en-US',{maximumFractionDigits:2})+unit;
}
function presentation(value:number|null|undefined,unit:string){
  return {value:unit==='bytes'&&value!=null?value/1048576:value,
    unit:unit==='bytes'||unit==='MiB'?' MiB':['%','percent'].includes(unit)?' %':['s','seconds'].includes(unit)?' s':'',
    precision:['counter','count','boolean'].includes(unit)?0:2,trim:true,exact:unit==='bytes'?exactMetric(value,' bytes'):undefined};
}
</script>
<template><section class="connector"><ServerTabBar :title="displayName??spec?.name??kind" :busy="busy" :disabled="preview||view?.monitoring?.enabled===false" @refresh="act()">
  <span v-if="view?.availability" class="tag" :class="{ ok: view.availability === 'running', warn: view.availability === 'stopped' }">{{serviceAvailabilityLabels[view.availability]}}</span>
  <span v-if="!view?.availability || view.status === 'not_detected' || view.status === 'warning' || view.status === 'critical'" class="tag" :class="tone">{{ view?.status==='unknown' && view.summary?.data.detected && !view.config.enabled ? 'Diagnostics disabled' : statuses[view?.status??'unknown'] }}</span>
  <RelativeDate :at="view?.summary?.at" empty="Not checked yet"/>
  <template #actions><slot name="actions"/></template>
</ServerTabBar>
<slot name="before-content"/><p v-if="view?.monitoring?.enabled===false" class="notice">Monitoring is off. You can enable it in the Monitoring library.</p><p v-if="error||view?.error" class="problem" role="alert">{{error||view?.error}}</p>
<template v-if="view?.summary&&spec">
<p v-for="deviation in view.deviations" :key="deviation.key" class="deviation" :class="{critical:!deviation.pending&&deviation.severity==='critical'}">
  <strong>{{deviation.title}}</strong><template v-if="deviation.value!=null"> · {{deviationValue(deviation.value,deviation)}}</template>
  <span> · threshold {{deviationValue(deviation.threshold,deviation)}}</span>
  <span v-if="deviation.pending"> · Waiting for confirmation</span>
  <span v-else-if="deviation.recovering"> · Awaiting confirmation of recovery</span>
  <template v-if="deviation.at<view.summary.at"> · <RelativeDate :at="deviation.at"/></template>
</p>
<dl class="metrics"><div v-for="metric in spec.metrics" :key="metric.key"><dt>{{metric.label}}</dt><dd><template v-if="view.availability&&metric.unit==='boolean'">{{view.summary.data.metrics[metric.key]==null?'—':view.summary.data.metrics[metric.key]?'Yes':'No'}}</template><MetricValue v-else v-bind="presentation(view.summary.data.metrics[metric.key],metric.unit)"/></dd><small v-if="metric.unit==='counter'&&view.summary.rates[metric.key]!=null"><MetricValue :value="view.summary.rates[metric.key]" :precision="view.summary.rates[metric.key]===0?0:2"/> per 10 min</small></div></dl>
<details class="quality"><summary>Data quality<template v-if="view.summary.data.issues.length"> · {{view.summary.data.issues.length}}</template></summary><ul><li>{{view.summary.data.complete?'All selected checks completed':'Incomplete coverage'}} · {{view.summary.bytesReceived}} bytes · {{view.summary.data.durationMs}} ms</li><li v-for="issue in view.summary.data.issues" :key="issue">{{issues[issue]??issue}}</li></ul></details>
<details><summary>Incidents and history</summary><p>Two observations at least one minute apart confirm a threshold breach. Repeat findings update the same incident. Confirming recovery requires fresh data. Automatic investigations share a budget.</p><article v-for="proof in view.evidence" :key="proof.id"><p><RelativeDate :at="proof.at"/></p><p v-for="finding in proof.findings" :key="finding.key">{{finding.title}} · {{finding.value}}</p></article></details></template>
<details v-if="config&&spec"><summary>Connection and permissions</summary><p>{{spec.rights}}</p><p v-if="instanceId&&instanceId!=='default'&&spec.instanceCredentials">Credentials file on the server <code>~/.cache/cyberbot/credentials/{{kind}}/{{instanceId}}.{{spec.instanceCredentials}}</code> (mode 0600). Each connection uses its own credentials file.</p><form @submit.prevent="act(true)" @input="autosave.edited" @change="autosave.edited"><label class="check"><input v-model="config.enabled" type="checkbox">Enable diagnostics</label><label v-if="spec.endpoint!=='local'" class="check"><input v-model="config.autoEndpoint" type="checkbox">Detect address and port automatically</label><div class="fields"><label v-if="!config.autoEndpoint && spec.endpoints.includes('127.0.0.1')">Local IP or socket<UiInput v-model="config.endpoint" :list="`service-endpoints-${kind}`" required/><datalist :id="`service-endpoints-${kind}`"><option v-for="endpoint in spec.endpoints" :key="endpoint" :value="endpoint"/></datalist></label><label v-else-if="!config.autoEndpoint && spec.endpoints.length>1">Local socket<UiSelect v-model="config.endpoint"><option v-for="endpoint in spec.endpoints" :key="endpoint">{{endpoint}}</option></UiSelect></label><label v-if="spec.endpoint!=='local' && !config.autoEndpoint && (!config.endpoint.startsWith('/') || spec.unixSocketName)">port<UiInput v-model.number="config.port" type="number" min="1" max="65535" required/></label><label v-if="!['none','api-key'].includes(spec.credentials)">Diagnostic role<UiInput v-model="config.user" maxlength="63" pattern="[A-Za-z_][A-Za-z0-9_.-]*" placeholder="Existing account"/></label><label>Check interval<UiInput v-model.number="config.intervalSeconds" type="number" unit="seconds" min="60" max="86400" required/></label><label v-if="replication">Expected replicas/participants<UiInput v-model.number="config.expectedPeers" type="number" min="0" max="64" required/></label></div><label v-if="replication" class="check"><input v-model="config.expectReplica" type="checkbox">Expect a connection to the primary</label><span class="autosave-status" role="status">{{autosave.saving.value||autosave.pending.value?'Saving…':'Saved automatically'}}</span></form></details>
</section></template>
<style scoped>
.deviation{background:var(--warning-bg);color:var(--warning);padding:10px 12px;border-radius:7px;margin:0 0 8px}.deviation.critical{background:var(--danger-bg);color:var(--danger)}
.autosave-status{font-size:11px;color:var(--muted)}
.tag{display:inline-flex;align-items:center;padding:1px 9px;border-radius:20px;background:var(--subtle);color:var(--muted);white-space:nowrap}.tag.ok{background:var(--accent-bg);color:var(--success)}.tag.warn{background:var(--warning-bg);color:var(--warning)}.tag.crit{background:var(--danger-bg);color:var(--danger)}
code{overflow-wrap:anywhere}p,li,dt,small{overflow-wrap:anywhere;color:var(--muted);font-size:13px;line-height:1.6}button{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:7px 10px;box-sizing:border-box;max-width:100%}header button{padding:6px 12px;white-space:nowrap}button{cursor:pointer}button:hover:enabled{background:var(--hover)}button:disabled{opacity:.45;cursor:default}button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}.problem{background:var(--danger-bg);color:var(--danger);padding:10px 12px;border-radius:7px;margin:0 0 8px}
.metrics{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;margin:0 0 18px}.metrics>div{min-width:0;background:var(--subtle);border-radius:10px;padding:12px 14px}.metrics dt{font-size:12px;line-height:1.4}.metrics small{font-size:11.5px}dd{min-width:0;max-width:100%;overflow-wrap:anywhere;margin:4px 0 0;font-size:22px;font-weight:450;letter-spacing:-.4px;font-variant-numeric:tabular-nums}
details{margin:8px 0;font-size:13px;color:var(--muted)}summary{cursor:pointer}.quality{background:var(--subtle);border-radius:10px;padding:10px 14px}.quality ul{margin:8px 0 2px;padding-left:18px}.fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:16px 0}label{min-width:0;display:flex;flex-direction:column;gap:6px;font-size:13px}.check{flex-direction:row;align-items:center;margin-block:12px}ul{padding-left:20px}article{padding:8px 0;border-bottom:1px solid var(--line)}@media(max-width:550px){.fields{grid-template-columns:1fr}}
</style>
