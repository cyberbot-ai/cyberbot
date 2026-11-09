<script setup lang="ts">
import UiInput from './UiInput.vue';
import UiSelect from './UiSelect.vue';
import {onBeforeUnmount,onMounted,ref} from 'vue';
import {call,preview} from '../api';
import type {AiProfiles,AgentModel} from '../types';
const config=ref<AiProfiles>(),catalog=ref<Record<string,AgentModel[]>>({}),error=ref(''),busy=ref(''),dirty=ref(false),saving=ref(false);
const titles:Record<string,string>={low:'low · Simple tasks and risk verification',medium:'medium · Regular tasks',high:'high · Tough challenges'};
let queued=false,timer:ReturnType<typeof setTimeout>|undefined;
function edited(e:Event){const form=e.currentTarget as HTMLFormElement;if(!form.checkValidity())return;dirty.value=true;clearTimeout(timer);timer=setTimeout(()=>void save(),350);}
onBeforeUnmount(()=>{clearTimeout(timer);if(dirty.value)void save();});
async function load(){try{config.value=await call<AiProfiles>('ai_profiles');}catch(e){error.value=String(e);}}
async function save(){if(preview||!config.value)return;queued=true;dirty.value=true;if(saving.value)return;saving.value=true;
 try{while(queued){queued=false;const next=JSON.parse(JSON.stringify(config.value)) as AiProfiles;try{const result=await call<AiProfiles>('configure_ai_profiles',{config:next});if(config.value)config.value.revision=result.revision;if(!queued){dirty.value=false;error.value='';}}catch(e){queued=false;error.value=String(e);}}}finally{saving.value=false;}}
async function models(provider:string){busy.value=provider;error.value='';try{catalog.value[provider]=await call<AgentModel[]>('agent_models',{provider});}catch(e){error.value=String(e);}finally{busy.value='';}}
onMounted(load);
</script>
<template>
<div class="profiles"><p>Low, medium and high profiles are available in the dialogs. New actions are separately verified by the low model. The selected profile is saved until the launch is complete.</p>
<p v-if="error" class="error" role="alert">{{error}}</p>
<template v-if="config"><section v-for="(roles,provider) in config.providers" :key="provider" class="provider"><header><h3>{{provider==='codex'?'Codex':'Claude Code'}}</h3><button :disabled="preview||!!busy" @click="models(provider)">{{busy===provider?'Checking…':'Available models'}}</button></header>
<form @submit.prevent="save" @input="edited" @change="edited"><div v-for="(profile,alias) in roles" :key="alias" class="profile"><label>{{titles[alias]}}<UiInput v-model="profile.model" :list="`models-${provider}`" :aria-label="`${provider} ${alias} model`" required pattern="[A-Za-z0-9._-]+" maxlength="128" :disabled="preview" style="--field-width:280px" @input="($event.target as HTMLInputElement).reportValidity()"/></label><label>Level of reasoning<UiSelect v-model="profile.effort" :aria-label="`${provider} ${alias} effort`" :disabled="preview"><option v-for="e in provider==='codex'?['low','medium','high','xhigh','max','ultra']:['low','medium','high','xhigh','max']" :key="e">{{e}}</option></UiSelect></label><small v-if="catalog[provider]" class="availability">{{catalog[provider].find(m=>m.id===profile.model)?.efforts.includes(profile.effort)?'Confirmed by CLI':'Profile not confirmed by CLI'}}</small></div></form>
<datalist :id="`models-${provider}`"><option v-for="model in catalog[provider]" :key="model.id" :value="model.id">{{model.name}}</option></datalist>
</section><p class="state" role="status">{{saving?'Save it…':dirty?'Changes not saved':'Changes are saved automatically'}}</p></template>
<p v-else-if="!error" role="status">Upload profiles…</p>
</div>
</template>
<style scoped>
.profiles { padding-bottom: 12px; }
h3 { font-size: 14px; font-weight: 600; margin: 0; }
p { font-size: 12px; line-height: 1.6; color: var(--muted); }
.profiles > p:first-child { margin: 0 0 14px; }
header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px 12px; margin-bottom: 10px; }
.provider { border-top: 1px solid var(--line); padding: 12px 0; }
form { display: grid; gap: 10px; }
.profile { display: flex; align-items: end; flex-wrap: wrap; gap: 6px 14px; }
label { display: flex; flex-direction: column; gap: 5px; font-size: 12px; min-width: 0; max-width: 100%; }
button { min-height: 32px; padding: 6px 9px; font: inherit; font-size: 12px; color: var(--text); background: var(--surface); border: 1px solid var(--line); border-radius: 6px; cursor: pointer; }
button:hover:enabled { background: var(--hover); border-color: var(--line-strong); }
button:disabled { opacity: .5; cursor: default; }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.availability { font-size: 11px; color: var(--muted); flex-basis: 100%; }
.error { color: var(--danger); overflow-wrap: anywhere; }
.state { font-size: 11px; margin: 0; }
</style>
