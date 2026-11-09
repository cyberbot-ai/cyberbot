<script setup lang="ts">
import ServerTabBar from './ServerTabBar.vue';
import {computed,onMounted,onUnmounted,ref,watch} from 'vue';
import {listen,type UnlistenFn} from '@tauri-apps/api/event';
import {call,preview as demo} from '../api';
import type {Investigation} from '../types';
import DatedSelect from './DatedSelect.vue';
type Spec={name:string;description:string;intervalSeconds:number;badWindows:number;inputs:string[];severity:string;condition:unknown;tests:unknown[]};
type Report={passed:boolean;cases:{name:string;expected:string;actual:string;passed:boolean}[]};
type Version={id:string;at:number;spec:Spec;author:string;error:string|null;report:{report:Report}|null};
type Binding={versionId:string;previousVersionId:string|null;enabled:boolean;error:string|null;last:{status:string;at:number;freshUntil:number;values:unknown}|null};
type Definition={id:string;name:string;versions:Version[];binding:Binding|null;events:unknown[]};
type View={definitions:Definition[];fields:string[];example:Spec};
type Preview={token:string;versionId:string;serverId:string;input:{missing:string[];values:unknown};response:{status:string;report:Report};before:Spec|null;after:Spec};
const props=defineProps<{serverId:string;now:number}>();const emit=defineEmits<{updated:[];aiSettings:[]}>();
const view=ref<View|null>(null),checkId=ref(''),versionId=ref(''),editor=ref(''),busy=ref(false),error=ref(''),review=ref<Preview|null>(null),accepted=ref(false),report=ref<Report|null>(null);
const question=ref('Detect sustained high memory usage. Add tests for normal usage, threshold breaches, and missing data.'),run=ref<Investigation|null>(null);
const current=computed(()=>view.value?.definitions.find(d=>d.id===checkId.value));const version=computed(()=>current.value?.versions.find(v=>v.id===versionId.value));
const versionOptions=computed(()=>[{value:'',label:'New draft'},...(current.value?.versions??[]).map(v=>({value:v.id,label:`${v.id.slice(0,12)} · ${v.author}`,at:v.at}))]);
const labels:Record<string,string>={healthy:'Healthy',warning:'Warning',critical:'Critical',unknown:'Current data is incomplete'};
let off:UnlistenFn|undefined,offState:UnlistenFn|undefined,disposed=false,epoch=0;let timer:ReturnType<typeof setTimeout>|undefined;
function result(d:Definition){const b=d.binding;if(!b)return 'Testing and preview required';if(!b.last)return 'Waiting for new data';return b.last.freshUntil>=props.now?labels[b.last.status]??b.last.status:'Data is stale';}
function resultTone(d:Definition){const l=d.binding?.last;if(!l||l.freshUntil<props.now)return '';return l.status==='critical'?'crit':l.status==='warning'?'warn':l.status==='healthy'?'ok':'';}
async function select(id:string){checkId.value=id;await choose();}
function invalidate(){review.value=null;accepted.value=false;report.value=null;}
async function reload(){const e=++epoch;const data=await call<View>('checks_view',{serverId:props.serverId,checkId:checkId.value||null});if(disposed||e!==epoch)return;view.value=data;if(versionId.value&&!current.value?.versions.some(v=>v.id===versionId.value))versionId.value='';}
async function action(fn:()=>Promise<void>){busy.value=true;error.value='';try{await fn();await reload();emit('updated');}catch(e){error.value=String(e);}finally{busy.value=false;}}
async function choose(){invalidate();versionId.value='';await action(async()=>{await reload();versionId.value=current.value?.versions[0]?.id??'';editor.value=JSON.stringify(version.value?.spec??view.value?.example,null,2);});}
function selectVersion(){invalidate();editor.value=JSON.stringify(version.value?.spec??view.value?.example,null,2);}
async function create(){await action(async()=>{checkId.value=await call<string>('new_check');versionId.value='';invalidate();editor.value=JSON.stringify(view.value?.example,null,2);});}
async function save(){invalidate();await action(async()=>{const v=await call<Version>('save_check_version',{checkId:checkId.value,spec:JSON.parse(editor.value)});versionId.value=v.id;});}
async function test(){invalidate();await action(async()=>{const r=await call<{report:Report}>('test_check_version',{versionId:versionId.value});report.value=r.report;});}
async function inspect(){invalidate();await action(async()=>{review.value=await call<Preview>('preview_check_version',{serverId:props.serverId,versionId:versionId.value});report.value=review.value.response.report;});}
async function enable(){if(!accepted.value||!review.value)return;const p=review.value;await action(async()=>{await call('activate_check',{serverId:p.serverId,versionId:p.versionId,token:p.token});invalidate();});}
async function disable(){await action(async()=>{await call('disable_check',{serverId:props.serverId,checkId:checkId.value});invalidate();});}
async function rollback(){const id=current.value?.binding?.previousVersionId;if(!id)return;versionId.value=id;selectVersion();await inspect();}
async function discard(){await action(async()=>{await call('discard_check_version',{versionId:versionId.value});versionId.value='';invalidate();});}
async function remove(){await action(async()=>{await call('delete_check',{checkId:checkId.value});checkId.value='';versionId.value='';editor.value='';invalidate();});}
async function generate(){invalidate();versionId.value='';await action(async()=>{const id=await call<string>('create_check_with_agent',{serverId:props.serverId,checkId:checkId.value,question:question.value});run.value=await call<Investigation>('investigation',{id});});}
async function refreshRun(id:string){if(document.hidden||run.value?.id!==id)return;try{run.value=await call<Investigation>('investigation',{id});if(run.value.status!=='running'){await reload();if(!versionId.value){versionId.value=current.value?.versions[0]?.id??'';selectVersion();}}}catch(e){error.value=String(e);}}
function visible(){if(!document.hidden){void action(async()=>{});if(run.value)void refreshRun(run.value.id);}}
watch(()=>props.serverId,()=>{++epoch;checkId.value='';versionId.value='';editor.value='';run.value=null;invalidate();void action(async()=>{});});
onMounted(async()=>{document.addEventListener('visibilitychange',visible);if(demo)return;await action(async()=>{});const un=await listen<string>('investigation-changed',e=>refreshRun(e.payload));if(disposed){un();return;}off=un;const unState=await listen('state-changed',()=>{if(document.hidden||busy.value)return;clearTimeout(timer);timer=setTimeout(()=>{void reload().catch(e=>error.value=String(e));},500);});if(disposed)unState();else offState=unState;});
onUnmounted(()=>{disposed=true;++epoch;off?.();offState?.();clearTimeout(timer);document.removeEventListener('visibilitychange',visible);});
const dirty=computed(()=>!!version.value&&editor.value!==JSON.stringify(version.value.spec,null,2));
</script>
<template><section class="checks"><ServerTabBar title="Checks" :busy="busy" :disabled="demo" @refresh="action(async()=>{})">
  <span v-if="view">Total {{ view.definitions.length }}</span>
  <template #actions><button class="primary" :disabled="busy||demo" @click="create">+ New check</button></template>
</ServerTabBar>
<p v-if="error" role="alert" class="error">{{error}} <button @click="emit('aiSettings')">AI settings</button></p>
<table v-if="view?.definitions.length" class="list" aria-label="Checks"><thead><tr><th>Check</th><th>Status</th><th>Result</th></tr></thead><tbody><tr v-for="d in view.definitions" :key="d.id" :class="{selected:d.id===checkId}"><td><button class="row-button" :aria-pressed="d.id===checkId" :disabled="busy" @click="select(d.id)">{{d.name}}</button></td><td><span class="tag" :class="d.binding?.enabled?'ok':''">{{d.binding?(d.binding.enabled?'Enabled':'Disabled'):'Draft'}}</span></td><td><span class="result" :class="resultTone(d)">{{result(d)}}</span></td></tr></tbody></table>
<p v-else-if="view" class="note">No checks yet. Create a new one or prepare it with an agent.</p>
<div v-if="current" class="detail"><h4>{{current.name}}</h4><div v-if="current.binding" class="status"><strong>{{current.binding.enabled?'Enabled':'Disabled'}}</strong><p>Version {{current.binding.versionId.slice(0,12)}} · {{current.binding.last?(current.binding.last.freshUntil>=now?labels[current.binding.last.status]:'Data is stale'):'Waiting for new data'}}</p><p v-if="current.binding.error" class="error">{{current.binding.error}}</p><pre v-if="current.binding.last">{{current.binding.last.values}}</pre><div class="actions"><button :disabled="busy||!current.binding.enabled" @click="disable">Disable check</button><button :disabled="busy||!current.binding.enabled" @click="action(async()=>{await call('run_checks',{serverId})})">Run on stored data</button><button :disabled="busy||!current.binding.previousVersionId" @click="rollback">Preview the previous version before rollback</button></div></div>
<details><summary>Draft with AI</summary><label>Goal<textarea v-model="question" rows="3" maxlength="3000"/></label><button :disabled="busy||run?.status==='running'||!question.trim()" @click="generate">Draft the check and tests · uses tokens</button><p v-if="run">{{run.status}} <button v-if="run.status==='running'" @click="action(async()=>{await call('cancel_investigation',{id:run!.id})})">Stop it</button></p><p v-if="run?.error" class="error">{{run.error}} <button @click="emit('aiSettings')">AI settings</button></p><pre v-if="run?.text">{{run.text}}</pre></details>
<label>Versions<DatedSelect v-model="versionId" label="Check versions" :options="versionOptions" :disabled="busy" @change="selectVersion"/></label>
<p v-if="version?.error" class="error">Version blocked: {{version.error}}. Run the tests and preview this version again.</p>
<details><summary>Definition and test data</summary><p>Available fields: {{view?.fields.join(', ')}}</p><label>Check definition (JSON)<textarea v-model="editor" rows="16" spellcheck="false" @input="invalidate"/></label><button :disabled="busy||!editor" @click="save">Save as a new version</button></details>
<div class="actions"><button :disabled="busy||!versionId||dirty" @click="test">Run tests</button><button :disabled="busy||!versionId||dirty" @click="inspect">Preview on this server</button><button :disabled="busy||!versionId" @click="discard">Delete unused version</button></div><p v-if="dirty">Save the changes first as a separate version.</p>
<div v-if="report"><p>{{report.passed?'Tests passed':'Some tests failed'}}</p><div v-for="c in report.cases" :key="c.name" class="case">{{c.passed?'✓':'✗'}} {{c.name}} · expected {{labels[c.expected]??c.expected}}, received {{labels[c.actual]??c.actual}}</div></div>
<div v-if="review" class="review"><h4>Version preview {{review.versionId.slice(0,12)}}</h4><p>Result using current data: {{labels[review.response.status]}}</p><p v-if="review.input.missing.length">No data: {{review.input.missing.join(', ')}}</p><pre>{{review.input.values}}</pre><div class="diff"><div><h4>Now</h4><pre>{{review.before??'Disabled'}}</pre></div><div><h4>After activation</h4><pre>{{review.after}}</pre></div></div><label class="confirm"><input v-model="accepted" type="checkbox">I reviewed this version’s rules, tests, and results for this server</label><button :disabled="busy||!accepted||!review.response.report.passed" @click="enable">Enable this version</button><p>The preview is valid for 15 minutes. Changes to the input data or active version invalidate it.</p></div>
<details><summary>Run history</summary><pre>{{current.events}}</pre></details><button :disabled="busy||!!current.binding?.enabled" @click="remove">Delete disabled check</button>
</div>
<details class="help about"><summary>How checks work</summary><p>Checks evaluate saved metrics and summaries. An agent can draft a check and its tests. Preview the exact version before enabling it. Checks have no access to commands, files, or the network.</p></details></section></template>
<style scoped>
.checks{border:0;margin:0;padding:0}h4{font-size:14px;font-weight:600;margin:0 0 4px}
p{font-size:13px;color:var(--muted);line-height:1.6;max-width:75ch}.note{margin:0}.actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}label{display:flex;flex-direction:column;gap:6px;margin:12px 0;font-size:13px;color:var(--muted)}
button,select,textarea{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:7px 11px;box-sizing:border-box}select{max-width:100%}button{cursor:pointer}button:hover:enabled{background:var(--hover)}button:disabled{opacity:.45;cursor:default}.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}.primary:hover:enabled{background:var(--accent);filter:brightness(1.08)}
textarea{width:100%;resize:vertical;font-family:ui-monospace,monospace;font-size:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;max-height:360px;overflow:auto;background:var(--subtle);padding:10px 12px;border-radius:7px;margin:8px 0}.error{padding:10px 12px;color:var(--danger);background:var(--danger-bg);border-radius:7px}
.list{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px}.list th{font-weight:500;font-size:12px;color:var(--muted);text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}.list td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:middle}.list tr.selected td{background:var(--subtle)}.row-button{border:0;background:none;padding:2px 0;text-align:left;font-weight:500}.row-button:hover:enabled{background:none;text-decoration:underline}
.tag{display:inline-flex;padding:1px 9px;border-radius:20px;font-size:12px;background:var(--subtle);color:var(--muted);white-space:nowrap}.tag.ok{background:var(--accent-bg);color:var(--success)}.result{color:var(--muted)}.result.ok{color:var(--success)}.result.warn{color:var(--warning)}.result.crit{color:var(--danger)}
.detail{background:var(--subtle);border-radius:10px;padding:14px 16px;margin-bottom:12px}.detail pre{background:var(--surface)}.status,.review{padding:12px 14px;background:var(--surface);border:1px solid var(--line);border-radius:8px;margin:12px 0}.diff{display:grid;grid-template-columns:1fr 1fr;gap:12px}.diff>div{min-width:0}.confirm{flex-direction:row;align-items:center}.case{font-size:13px;padding:4px 0}
details{margin:10px 0;font-size:13px;color:var(--muted)}summary{cursor:pointer}.about{margin-top:16px}
button:focus-visible,textarea:focus-visible,select:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}textarea::placeholder{color:var(--muted)}
@media(max-width:700px){.diff{grid-template-columns:1fr}}
</style>
