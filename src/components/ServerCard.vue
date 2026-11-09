<script setup lang="ts">
import { serverDisplayHost, serverHint } from '../serverDirectory';
import MetricValue from './MetricValue.vue';
import RelativeDate from './RelativeDate.vue';
import { computed } from 'vue';
import { formatMetric, exactMetric } from '../metrics';
import { health, serverHealthLabel, partialHealthReason, percent } from '../health';
import { dashboardConnectors, hideServiceUnit, serviceAvailabilityLabels, servicePriority } from '../services';
import type { Server } from '../types';
const props=defineProps<{server:Server; now:number; interval:number; compact?:boolean}>();
defineEmits<{select:[server:Server]}>();
const displayHost = computed(() => serverDisplayHost(props.server.name, props.server.endpoint.host));
const status=computed(()=>health(props.server,props.now,props.interval));
const hideMetrics=computed(()=>props.server.networkOffline || props.server.awaitingFirstCheck);
const disk=computed(()=>props.server.observation?.disks.reduce((max,d)=>Math.max(max,d.usedPercent),0));
const meters=computed(()=>[{label:'CPU',value:hideMetrics.value?null:props.server.observation?.cpuPercent},{label:'RAM',value:hideMetrics.value?null:props.server.observation?.memoryPercent},{label:'Disk',value:hideMetrics.value?null:disk.value}]);
const services=computed(()=>{
 if(props.server.networkOffline)return [];
 const list:{name:string;state:string;exact?:string;unitFailure?:string}[]=[];
 const kinds = new Set<string>();
 for (const card of dashboardConnectors(props.server, status.value)) {
   kinds.add(card.kind);
   const metric = card.metric;
   const unit = metric ? ' ' + metric.unit : '';
   list.push({name:metric ? `${card.name} · ${formatMetric(metric.value,1,unit)}` : card.name,
     state:card.state,unitFailure:card.unitFailure,exact:metric ? exactMetric(metric.value,unit) : card.availability && serviceAvailabilityLabels[card.availability]});
 }
 if(props.server.vulnerabilities?.affected)list.push({name:`CVE ${props.server.vulnerabilities.affected}`,state:'critical'});
 for(const s of props.server.observation?.services??[]){if(hideServiceUnit(s.name,kinds))continue;list.push({name:s.name.replace('.service',''),state:props.server.awaitingFirstCheck?'unknown':s.state==='active'?'healthy':s.state==='failed'?'critical':'unknown'});}
 return list.map(s=>props.server.awaitingFirstCheck?{...s,name:s.name.replace(/ · .* rps$/,' · —'),state:s.state==='critical'||s.state==='warning'?s.state:'unknown',exact:undefined}:s)
   .sort((a,b)=>servicePriority(a.state)-servicePriority(b.state));
});
</script>
<template><button class="card" :class="[status,{compact}]" :aria-label="`${displayHost}, ${serverHealthLabel(server,status)}, CPU ${percent(hideMetrics?null:server.observation?.cpuPercent)}, memory ${percent(hideMetrics?null:server.observation?.memoryPercent)}, disk ${percent(hideMetrics?null:disk)}`" @click="$emit('select',server)">
  <div class="identity"><span class="status-dot" :title="partialHealthReason(server, status) ?? serverHealthLabel(server, status)"></span><div><strong :title="serverHint(server)">{{displayHost}}</strong><span v-if="compact" class="narrow-status health">{{serverHealthLabel(server,status)}}</span></div><RelativeDate v-if="!compact && !server.networkOffline" class="freshness" :at="server.observation?.at" empty="Not checked yet"/></div>
  <div class="meters"><div v-for="meter in meters" :key="meter.label" class="meter"><span>{{meter.label}}</span><b :class="{hot:(meter.value??0)>=90}"><MetricValue :value="meter.value" :precision="0" unit="%"/></b><span v-if="!compact" class="track"><i :class="{hot:(meter.value??0)>=90}" :style="{width:`${Math.max(0,Math.min(100,Number.isFinite(meter.value)?meter.value??0:0))}%`}"></i></span></div></div>
  <div class="card-bottom"><span class="health">{{serverHealthLabel(server,status)}}</span><span class="services"><span v-for="(s,index) in services.slice(0,2)" :key="index" :class="s.state" :title="[`${s.name}: ${s.state}`, s.exact, s.unitFailure].filter(Boolean).join(' · ')">{{s.name}}</span><span v-if="services.length>2" :title="services.slice(2).map(s=>s.name).join(', ')">+{{services.length-2}}</span></span></div>
</button></template>
<style scoped>
.card{display:flex;flex-direction:column;gap:20px;width:100%;height:166px;box-sizing:border-box;padding:17px 18px;text-align:left;background:var(--surface);border:1px solid var(--line);border-radius:12px;color:var(--text);font:inherit;cursor:pointer;transition:background .15s,border-color .15s}.card:hover{background:var(--subtle);border-color:var(--line-strong)}.card:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.identity{display:flex;align-items:center;gap:10px;min-width:0}.identity>div{flex:1;min-width:0;display:grid;gap:2px}.identity strong{font-size:14px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.freshness{max-width:46%;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;font-size:10px;color:var(--muted);white-space:nowrap;margin-left:auto;align-self:flex-start}.status-dot{width:6px;height:6px;border-radius:50%;background:var(--muted);flex-shrink:0}.healthy .status-dot{background:var(--success)}.warning .status-dot{background:var(--warning)}.critical .status-dot,.unreachable .status-dot{background:var(--danger)}.meters{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;min-width:0;width:100%}.meter{flex:1;min-width:0;display:grid;grid-template-columns:auto minmax(0,1fr);gap:5px;font-size:11px;color:var(--muted)}.meter b{min-width:0;max-width:100%;text-align:right;font-size:12px;font-weight:500;font-variant-numeric:tabular-nums;color:var(--text)}.meter b.hot{color:var(--warning)}.critical .meter b.hot{color:var(--danger)}.track{grid-column:1/-1;height:2px;background:var(--line);overflow:hidden}.track i{display:block;height:100%;background:var(--line-strong)}.track i.hot{background:var(--warning)}.critical .track i.hot{background:var(--danger)}.card-bottom{max-width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:11px;min-width:0;margin-top:auto;color:var(--muted)}.health{white-space:nowrap}.warning .health{color:var(--warning)}.critical .health,.unreachable .health{color:var(--danger)}.services{min-width:0;display:flex;gap:8px;overflow:hidden}.services>span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.services .warning{color:var(--warning)}.services .critical{color:var(--danger)}.narrow-status{display:none}.compact{height:64px;display:grid;grid-template-columns:minmax(150px,1.2fr) minmax(180px,1fr) minmax(150px,1fr);gap:24px;padding:11px 14px;border:0;border-bottom:1px solid var(--line);border-radius:0;background:none}.compact .card-bottom{margin:0;min-width:0}.compact .services{font-size:11px}.compact .meter{display:flex;justify-content:flex-end}.compact .meter>span{display:none}.compact .meters{gap:16px}@media(max-width:680px){.compact .narrow-status{display:block;font-size:10px;line-height:1.2}.compact .identity>div{gap:0}.compact{grid-template-columns:minmax(120px,1fr) minmax(135px,1fr);gap:10px}.compact .card-bottom{display:none}.compact .meters{gap:12px}.card{padding-inline:14px}.freshness{max-width:46%;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;font-size:10px}}@media(prefers-reduced-motion:reduce){.card{transition:none}}
</style>
