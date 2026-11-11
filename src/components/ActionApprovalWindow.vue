<script setup lang="ts">
import { presentServiceAction } from '../serviceActions';
import ActionRiskWarning from './ActionRiskWarning.vue';
import ServerLink from './ServerLink.vue';
import { actionRequestReference, capturedActionServers } from '../serverDirectory';
import {computed,nextTick,onMounted,onUnmounted,ref} from 'vue';
import {listen,type UnlistenFn} from '@tauri-apps/api/event';
import {getCurrentWindow} from '@tauri-apps/api/window';
import {call,preview} from '../api';
import {useClock} from '../useClock';
import type {ActionRequest} from '../types';
const props=defineProps<{requestId:string}>();
const request=ref<ActionRequest>(),error=ref(''),busy=ref(false),loading=ref(true),session=ref(false),denyButton=ref<HTMLButtonElement>();
const now=useClock();
const scope = computed(() => capturedActionServers(request.value));
const requestServer = computed(() => actionRequestReference(request.value));
const waiting=computed(()=>request.value?.state==='awaitingApproval');
const expired=computed(()=>Boolean(request.value&&request.value.expiresAt<=now.value));
const verdict=computed(()=>request.value?.review?.verdict);
const action=computed(()=>request.value?.artifact.spec.action);
const requiresOneTime=computed(()=>verdict.value?.decision==='confirm'
  || (action.value?.kind==='shell' && verdict.value?.decision==='uncertain'));
const pendingRisk=computed(()=>waiting.value&&!expired.value&&requiresOneTime.value?verdict.value:undefined);
const allowed=computed(()=>waiting.value&&!expired.value&&(verdict.value?.decision==='allow'||requiresOneTime.value));
const useSession=computed(()=>!requiresOneTime.value&&session.value);
const serviceAction = computed(() => presentServiceAction(action.value));
const statusLabels:Record<string,string>={approved:'Approval sent',queued:'Action queued',running:'Action in progress',succeeded:'Action completed',denied:'Action denied',cancelled:'Request cancelled',expired:'Request expired',unknown:'Result unconfirmed',failed:'Action failed',rolledBack:'Original configuration restored',rollbackUnknown:'Rollback unconfirmed'};
let timer:ReturnType<typeof setInterval>|undefined,off:UnlistenFn|undefined,disposed=false,sequence=0;
async function load(){const version=++sequence;try{const result=await call<ActionRequest>('action_request',{id:props.requestId});if(!disposed&&version===sequence)request.value=result;}catch(e){if(!disposed&&version===sequence)error.value=String(e).replace(/^Error: /,'');}finally{if(!disposed)loading.value=false;}}
async function decide(decision: 'deny' | 'once' | 'session') {
  if (busy.value || preview || !request.value || !allowed.value) return;
  busy.value = true;
  error.value = '';
  sequence++;
  const { id, artifactHash } = request.value;
  try {
    const result = await call<ActionRequest>('decide_action', { id, artifactHash, decision });
    if (disposed) return;
    request.value = result;
  } catch (e) {
    if (!disposed) error.value = String(e).replace(/^Error: /, '');
    return;
  } finally {
    if (!disposed) busy.value = false;
  }
  if (request.value.state === 'approved') await close();
}
function visible(){if(!document.hidden&&!busy.value)void load();}
async function close(){if(preview||busy.value)return;busy.value=true;error.value='';try{await getCurrentWindow().close();}catch(e){error.value=`Failed to close the window. ${String(e).replace(/^Error: /,'')}`;}finally{busy.value=false;}}
onMounted(async()=>{await load();if(disposed)return;await nextTick();denyButton.value?.focus();timer=setInterval(visible,15000);document.addEventListener('visibilitychange',visible);if(!preview)void listen('action-changed',visible).then(fn=>{if(disposed)fn();else off=fn;}).catch(()=>{});});
onUnmounted(()=>{disposed=true;sequence++;clearInterval(timer);off?.();document.removeEventListener('visibilitychange',visible);});
</script>
<template>
<main class="approval" aria-labelledby="approval-title">
  <header><p class="eyebrow">AI action approval</p><h1 id="approval-title">{{waiting?'Allow action?':loading?'Loading request…':statusLabels[request?.state??'']??'Request closed'}}</h1><p v-if="request" class="server"><ServerLink v-bind="requestServer" captured/></p></header>
  <div class="content">
    <p v-if="error" class="error" role="alert">{{error}}</p>
    <template v-if="request">
      <h2>{{request.artifact.spec.goal}}</h2>
      <ActionRiskWarning v-if="pendingRisk" class="approval-risk" :verdict="pendingRisk"/>
      <div class="effect" v-if="action?.kind==='diagnostic'"><strong>Calculation using stored data</strong><p>The Python script processes prepared summaries in isolation.</p></div>
      <div v-else-if="serviceAction" class="effect"><strong>{{serviceAction.headline}}</strong><p>{{serviceAction.approval}}</p><p v-if="serviceAction.risky" class="risk">Connections may drop.</p><div v-if="request.artifact.prepared.before" class="diff"><code>− {{request.artifact.prepared.before}}</code><code>+ {{request.artifact.prepared.after}}</code></div></div>
      <template v-else-if="action?.kind==='shell'">
        <div class="effect">
          <strong>Shell runs as {{request.artifact.prepared.user}}</strong>
          <p class="risk">The script runs with this user’s permissions on the server.</p>
          <p>Cyberbot returns the command output to the AI provider and saves it in the action history.</p>
        </div>
        <pre aria-label="Exact script">{{request.artifact.spec.code}}</pre>
      </template>
      <template v-if="verdict && action?.kind==='shell' && !pendingRisk">
        <p><strong>Risk review</strong> · {{verdict.explanation}}</p>
        <ul v-if="verdict.effects.length"><li v-for="effect in verdict.effects" :key="effect">{{effect}}</li></ul>
      </template>
      <p v-else-if="allowed && !requiresOneTime" class="review-ok">Risk review passed</p>
      <p v-if="expired&&waiting" class="error" role="status">This request expired before it was approved.</p>
      <p v-else-if="!waiting" class="result" role="status">{{statusLabels[request.state]??'This request is closed'}}. You can close this window.</p>
      <details v-if="action?.kind==='shell'"><summary>Servers and execution limits</summary><p>Up to {{request.artifact.isolation.wallSeconds}} s</p><ul><li v-for="target in scope" :key="target.id"><ServerLink v-bind="target" captured/></li></ul></details>
      <details v-else><summary>Code and technical details</summary><pre>{{request.artifact.spec.code}}</pre><p>Python is limited to 4 seconds of CPU time, 8 seconds of wall time, and 96 MiB of memory. File access, networking, and process creation are blocked.</p><details><summary>Prepared inputs</summary><pre>{{JSON.stringify(request.artifact.inputs,null,2)}}</pre></details><p v-if="request.review">{{request.review.model??request.artifact.profile.low.model}} · {{request.review.tokens.toLocaleString('en-US')}} tokens<br>{{request.review.verdict.explanation}}</p><p v-if="serviceAction?.rollback && request.artifact.spec.rollbackPlan">{{request.artifact.spec.rollbackPlan}}</p><ul><li v-for="target in scope" :key="target.id"><ServerLink v-bind="target" captured/></li></ul><p class="hash">Artifact {{request.artifactHash}}</p></details>
    </template>
  </div>
  <footer>
    <template v-if="waiting&&!expired">
      <label v-if="!requiresOneTime" class="session"><input v-model="session" type="checkbox" :disabled="busy||!allowed">{{action?.kind==='shell'?'Allow more shell scripts in this run':'Allow more actions in this run'}}</label>
      <p class="scope-note">{{requiresOneTime?'Approval applies to this action only.':useSession?`Applies to ${scope.length} selected servers. Each new script goes through risk review.`:'By default, approval applies to this action only.'}}</p>
      <div class="buttons"><button ref="denyButton" :disabled="busy||preview||!allowed" @click="decide('deny')">Decline</button><button class="primary" :disabled="busy||preview||!allowed" @click="decide(useSession?'session':'once')">{{busy?'Submitting…':useSession?'Allow for this run':'Allow once'}}</button></div>
    </template>
    <button v-else :disabled="busy" @click="close">Close</button>
    <p v-if="preview" class="scope-note">Actions are disabled in the preview.</p>
  </footer>
</main>
</template>
<style scoped>
.approval-risk { margin-bottom: 14px; }
.approval{height:100%;width:100%;display:flex;flex-direction:column;min-height:0;background:var(--canvas);color:var(--text);box-sizing:border-box}header{flex:none;padding:26px 28px 18px;border-bottom:1px solid var(--line)}.eyebrow{font-size:11px;font-weight:600;letter-spacing:.04em;color:var(--muted);margin:0 0 7px}h1{font-size:23px;line-height:1.25;font-weight:600;margin:0}.server{font-size:12px;color:var(--muted);overflow-wrap:anywhere;margin:10px 0 0;max-height:3em;overflow:auto}.content{flex:1;min-height:0;overflow:auto;padding:22px 28px}h2{font-size:15px;line-height:1.5;font-weight:500;overflow-wrap:anywhere;margin:0 0 18px}.effect{background:var(--surface);border-radius:9px;padding:15px 17px}.effect strong{font-size:13px;font-weight:600}p,li{font-size:12px;line-height:1.6;overflow-wrap:anywhere}.effect p{margin:7px 0 0;color:var(--muted)}.effect .risk{color:var(--warning)}.diff{display:flex;flex-direction:column;gap:4px;margin-top:12px;font-size:11px;overflow-wrap:anywhere}.diff code:first-child{color:var(--danger)}.diff code:last-child{color:var(--success)}.review-ok{color:var(--success);margin:13px 0 18px}.error{color:var(--danger)}.result{color:var(--muted)}details{margin-top:14px;color:var(--muted);font-size:12px}summary{cursor:pointer;font-size:12px;color:var(--text)}pre{font:11px/1.7 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere;max-height:220px;overflow:auto;padding:12px;background:var(--surface);border:1px solid var(--line);border-radius:7px;color:var(--text)}.hash{font:10px/1.7 ui-monospace,monospace;overflow-wrap:anywhere}footer{flex:none;padding:16px 28px 22px;border-top:1px solid var(--line);background:var(--canvas)}.session{display:flex;align-items:center;gap:8px;font-size:12px;line-height:1.5;cursor:pointer}.session input{accent-color:var(--accent);margin:0;flex:none}.scope-note{font-size:11px;color:var(--muted);margin:5px 0 14px}.buttons{display:flex;justify-content:space-between;gap:12px}button{font:inherit;font-size:12px;padding:10px 15px;min-height:38px;border:1px solid var(--line);border-radius:7px;background:var(--surface);color:var(--text);cursor:pointer}button.primary{background:var(--accent);color:var(--on-accent);border-color:var(--accent);font-weight:500}button:disabled{opacity:.5;cursor:default}button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}@media(max-width:550px){header{padding:20px 20px 14px}.content{padding:18px 20px}footer{padding:14px 20px 18px}.buttons{gap:8px}.buttons button{font-size:11px;padding:9px 11px}h1{font-size:21px}}
</style>
