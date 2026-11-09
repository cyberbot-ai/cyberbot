<script setup lang="ts">
import ServerTabBar from '../ServerTabBar.vue';
import MetricValue from '../MetricValue.vue';
import RelativeDate from '../RelativeDate.vue';
import { formatDuration, formatTimeRange } from '../../dateTime';
import {computed,ref,watch,onUnmounted} from 'vue';
import {call,preview} from '../../api';
import type { Health, LogSummary, MonitoringValues } from '../../types';

interface NginxCard {detected:boolean;status:Health|'not_detected';rps:number|null;rpsSource:string;at:number|null}
interface NginxTiming {samples:number;sumMs:number;maxMs:number;slow:number;histogram:number[]}
interface NginxSummary {id:string;at:number;receivedAt:number;detected:boolean;service:string;windowSeconds:number;coverage:LogSummary['coverage'];accessComplete:boolean;errorComplete:boolean;missing:string[];rps:number|null;rpsSource:string;status:{active:number;reading:number;writing:number;waiting:number;requests:number}|null;counts:Record<string,number>;statuses:Record<string,number>;requestTime:NginxTiming;upstreamTime:NginxTiming;examples:{at:number;category:string}[];bytesRead:number;bytesReceived:number;durationMs:number;findings:LogSummary['findings']}
interface NginxView {monitoring?:MonitoringValues;evidence?:{summaryId:string;at:number;findings:LogSummary['findings'];counts:Record<string,number>}[];summary:NginxSummary|null;fresh:boolean;error:string|null;nextCheck:number;card:NginxCard}

const props=defineProps<{serverId:string;now:number;kind?:string;refreshKey?:string;displayName?:string;instanceId?:string}>();const emit=defineEmits<{updated:[]}>();
const view=ref<NginxView>();const error=ref('');const busy=ref(false);let version=0;
const labels:Record<string,string>={requests:'Requests',unparsed:'Unrecognized records',upstream_timeout:'Upstream timeouts',upstream_connect:'Upstream connection errors',upstream_unavailable:'No available upstreams',capacity:'Connection limit',critical_error:'Critical errors',client_noise:'Client errors and scans',other_errors:'Other errors'};
const gaps:Record<string,string>={config_limit:'Configuration limit or unsupported structure',config_unavailable:'Configuration unavailable',unsupported_log_path:'Log path outside the allowed directories',multiple_logs:'Multiple logs found. Cyberbot reads one primary log of each type.',access_filtered:'Conditional or compressed logging',source_unavailable:'Log unavailable',source_changed:'The log or format has changed',backlog_skipped:'Older entries skipped. Recent entries were read.',file_rewritten:'File rewritten',file_truncated:'File truncated',rotation_tail_lost:'End of rotated log unavailable',long_line:'Line too long',incomplete_line:'Incomplete line',invalid_encoding:'Unknown encoding',read_limit:'Read or time limit reached',unknown_format:'Unrecognized log format',unknown_timestamp:'Unrecognized timestamp',clock_changed:'Clock drift',late_records:'Late entries outside the check window',timing_unavailable:'Some request timings are unavailable',counter_reset:'Status counter reset'};
const scope = () => ({id:props.serverId,kind:props.kind??'nginx',...(props.instanceId?{instanceId:props.instanceId}:{})});
async function load(){const v=++version;try{const result=await call<NginxView>('service_summary',scope());if(v===version){view.value=result;error.value='';}}catch(e){if(v===version)error.value=String(e);}}
watch(()=>props.serverId,()=>{view.value=undefined;void load();},{immediate:true});watch(()=>[props.now,props.refreshKey],()=>{if(!document.hidden&&!busy.value)void load();});onUnmounted(()=>{version++;});
async function refresh(){busy.value=true;error.value='';try{await call('refresh_service',scope());await load();emit('updated');}catch(e){error.value=String(e);}finally{busy.value=false;}}
const codeKeys=['2xx','3xx','4xx','5xx','1xx'];
const codes=computed(()=>{const c=view.value?.summary?.counts??{};const items=codeKeys.filter(k=>c[k]).map(k=>({key:k,count:c[k]}));return {items,total:items.reduce((n,i)=>n+i.count,0)};});
const other=computed(()=>Object.entries(view.value?.summary?.counts??{}).filter(([k,n])=>k!=='requests'&&!codeKeys.includes(k)&&n>0));
const qualityCount=computed(()=>{const s=view.value?.summary;return s?s.coverage.gaps.length+(s.missing.length?1:0):0;});
const health=computed(()=>{const st=view.value?.card?.status;return st==='critical'?'crit':st==='warning'?'warn':st==='healthy'?'ok':'';});
const healthText=computed(()=>({critical:'Critical',warning:'Needs attention',healthy:'No issues found'} as Record<string,string>)[view.value?.card?.status??'']??'No current results');
function share(part?:number,total?:number){if(!total)return '—';const p=(part??0)/total*100;return p===0?'0%':p<0.1?'< 0.1%':`${p.toFixed(p<10?1:0)}%`;}
function avg(t:NginxTiming){return t.samples?`${Math.round(t.sumMs/t.samples)} ms`:'no data';}
function p95(t:NginxTiming){if(!t.samples)return 'no data';let n=0;const bounds=[5,10,25,50,100,250,500,1000,2500,5000,10000,30000,60000];for(let i=0;i<t.histogram.length;i++){n+=t.histogram[i];if(n>=Math.ceil(t.samples*.95))return i<bounds.length?`≤ ${bounds[i]} ms`:'> 60';}return 'no data';}
</script>
<template>
<section class="nginx">
<ServerTabBar :title="displayName ?? 'Nginx'" :busy="busy" :disabled="preview || view?.monitoring?.enabled===false" @refresh="refresh">
  <span v-if="view?.summary?.detected" class="tag" :class="health">{{ healthText }}</span>
  <RelativeDate :at="view?.summary?.receivedAt" empty="Not checked yet"/>
  <template #actions><slot name="actions"/></template>
</ServerTabBar>
<slot name="before-content"/>
<p v-if="view?.monitoring?.enabled===false" class="notice">Monitoring is off. You can enable it in the Monitoring library.</p><p v-if="error||view?.error" class="problem" role="alert">{{error||view?.error}}</p>
<p v-if="!view?.summary" class="note">Results will appear after the next scheduled check.</p>
<template v-if="view?.summary"><p v-if="!view.summary.detected" class="note">Nginx was not detected. Cyberbot checks again every 6 hours.</p><template v-else>
<div v-for="f in view.summary.findings" :key="f.check" class="problem">{{f.title}} · {{f.count}}</div>
<p v-if="['warning','critical'].includes(view.card.status)&&!view.summary.findings.length" class="problem">The incident stays open until two full checks confirm recovery.</p>
<div class="metrics">
  <div><small>Requests for {{ formatDuration(view.summary.windowSeconds) }}</small><strong><MetricValue :value="view.summary.counts.requests??0" :precision="0"/></strong><span class="sub" :title="`RPS source: ${view.summary.rpsSource}`"><template v-if="view.summary.rps!=null"><MetricValue :value="view.summary.rps" :precision="2"/> RPS</template><template v-else>{{view.summary.coverage.initial?'RPS needs another full check':'RPS unavailable'}}</template></span></div>
  <div :class="{bad:(view.summary.counts['5xx']??0)>0}"><small>5xx responses</small><strong><MetricValue :value="view.summary.counts['5xx']??0" :precision="0"/></strong><span class="sub">{{share(view.summary.counts['5xx'],view.summary.counts.requests)}} of requests</span></div>
  <div><small>Request time</small><strong :class="{none:!view.summary.requestTime.samples}">{{avg(view.summary.requestTime)}}</strong><span class="sub">p95 {{p95(view.summary.requestTime)}}</span></div>
  <div><small>Upstream response time</small><strong :class="{none:!view.summary.upstreamTime.samples}">{{avg(view.summary.upstreamTime)}}</strong><span class="sub">{{view.summary.upstreamTime.samples?`p95 ${p95(view.summary.upstreamTime)}`:'No timing data'}}</span></div>
</div>
<section v-if="codes.total" class="codes"><h4>Response codes</h4><div class="stack" role="img" :aria-label="codes.items.map(c=>`${c.key}: ${c.count}`).join(', ')"><i v-for="c in codes.items" :key="c.key" :class="`c${c.key[0]}`" :style="{width:`${c.count/codes.total*100}%`}"></i></div><div class="legend"><span v-for="c in codes.items" :key="c.key"><i :class="`c${c.key[0]}`"></i>{{c.key}} <b><MetricValue :value="c.count" :precision="0"/></b></span></div></section>
<div v-if="view.summary.status" class="row"><span>Connections: {{view.summary.status.active}}</span><span>Reading {{view.summary.status.reading}} · writing {{view.summary.status.writing}} · waiting {{view.summary.status.waiting}}</span></div>
<dl v-if="other.length" class="other"><template v-for="[k,n] in other" :key="k"><dt>{{labels[k]??k}}</dt><dd><MetricValue :value="n" :precision="0"/></dd></template></dl>
<details class="quality"><summary>Data quality<template v-if="qualityCount"> · {{qualityCount}}</template></summary><ul>
<li>Service {{ view.summary.service }} · period {{ formatTimeRange(view.summary.at - view.summary.windowSeconds, view.summary.at) }}</li>
<li>Data collected for {{ formatDuration(view.summary.windowSeconds) }}. Counts include completed requests in the selected Nginx log.</li>
<li v-if="view.summary.coverage.initial">Calculating RPS requires another full check.</li>
<li v-if="view.summary.missing.length">Unavailable metrics: <code>{{view.summary.missing.join(', ')}}</code></li>
<li v-for="(g,i) in view.summary.coverage.gaps" :key="i">{{g.source}}: {{gaps[g.reason]??g.reason}}<small v-if="g.fromOffset!=null"> · bytes {{g.fromOffset}}–{{g.toOffset}}</small></li>
<li><small>Received {{view.summary.bytesReceived}} bytes · read {{view.summary.bytesRead}} bytes on the server · {{view.summary.durationMs}} ms. Figures exclude SSH overhead.</small></li></ul></details>
<details class="help"><summary>How latency is calculated</summary><p>The p95 estimate uses the upper bound of the matching histogram bucket. Latency data requires request timings in the log.</p></details>
<details class="help"><summary>When an incident is created</summary><p>HTTP 4xx responses and routine scans do not trigger automatic investigations. Cyberbot checks data coverage before opening incidents for 5xx responses, latency, and upstream errors.</p></details>
<details v-if="view.evidence?.length" class="help"><summary>Evidence of open incidents</summary><article v-for="e in view.evidence" :key="e.summaryId"><p><RelativeDate :at="e.at"/></p><p v-for="f in e.findings" :key="f.check">{{f.title}} · {{f.count}}</p><small>Summary {{e.summaryId}}</small></article></details>
<details v-if="view.summary.examples.length" class="help"><summary>Redacted events: {{view.summary.examples.length}}</summary><p v-for="(e,i) in view.summary.examples" :key="i"><RelativeDate :at="e.at"/> · {{labels[e.category]??e.category}}</p></details>
</template></template></section></template>
<style scoped>
.nginx{border:0;margin:0;padding:0}h4{font-size:13px;font-weight:600;margin:0 0 8px}.tag{display:inline-flex;align-items:center;padding:1px 9px;border-radius:20px;background:var(--subtle);color:var(--muted);white-space:nowrap}.tag.ok{background:var(--accent-bg);color:var(--success)}.tag.warn{background:var(--warning-bg);color:var(--warning)}.tag.crit{background:var(--danger-bg);color:var(--danger)}
button{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer;white-space:nowrap}button:hover:enabled{background:var(--hover)}button:disabled{opacity:.45;cursor:default}
p,li{overflow-wrap:anywhere;font-size:13px;line-height:1.6;color:var(--muted)}.note{margin:0}.problem{padding:10px 12px;background:var(--danger-bg);color:var(--danger);border-radius:7px;margin:0 0 8px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 22px}.metrics>div{min-width:0;background:var(--subtle);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:2px}.metrics small{font-size:12px;color:var(--muted)}.metrics strong{font-size:24px;font-weight:450;letter-spacing:-.5px;font-variant-numeric:tabular-nums;min-width:0;max-width:100%;overflow-wrap:anywhere}.metrics strong.none{font-size:15px;line-height:36px;color:var(--muted)}.metrics .sub{font-size:11.5px;color:var(--muted);overflow-wrap:anywhere}.metrics>.bad{background:var(--danger-bg)}.metrics>.bad strong{color:var(--danger)}
.codes{margin-bottom:18px}.stack{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--subtle)}.stack i,.legend i{display:block;height:100%}.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:8px;font-size:12px;color:var(--muted)}.legend span{display:inline-flex;align-items:center;gap:6px}.legend b{color:var(--text);font-weight:500}.legend i{width:7px;height:7px;border-radius:50%}.c1{background:var(--line-strong)}.c2{background:var(--success)}.c3{background:var(--line-strong)}.c4{background:var(--warning)}.c5{background:var(--danger)}
.row{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;font-size:13px;padding:10px 0;border-bottom:1px solid var(--line)}.row>*{min-width:0;max-width:100%;overflow-wrap:anywhere}
.other{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px 16px;font-size:13px;margin:0 0 18px}dt{min-width:0;overflow-wrap:anywhere;color:var(--muted)}dd{margin:0;text-align:right}
details{margin:8px 0;font-size:13px;color:var(--muted)}.quality{background:var(--subtle);border-radius:10px;padding:10px 14px;margin-top:4px}.quality ul{margin:8px 0 2px;padding-left:18px}.quality li{line-height:1.6;margin:2px 0}summary{cursor:pointer}small{color:var(--muted);font-size:12px}code{font-size:12px}article{padding:10px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.help p{margin:6px 0 0 14px}
button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}p{max-width:75ch}
@media(max-width:700px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
