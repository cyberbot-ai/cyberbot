<script setup lang="ts">
import UiInput from './UiInput.vue';
import {ref,computed,watch,onActivated,onDeactivated} from 'vue';
import {call,preview} from '../api';
import { servicePanel } from '../servicePanels';
import UiIcon from './UiIcon.vue';
import ServerTabBar from './ServerTabBar.vue';
import { serviceCatalog as catalog } from '../services';
import type {ServiceInstance} from '../types';
const props=defineProps<{serverId:string;kind:string;now:number;initialInstance?:string;hideSelector?:boolean;refreshKey?:string}>();const emit=defineEmits<{updated:[];select:[id:string]}>();
const items=ref<ServiceInstance[]>([]),selected=ref('default'),port=ref(1),adding=ref(false),removing=ref(false),busy=ref(false),error=ref('');let revision=0,active=true;
const current=computed(()=>items.value.find(i=>i.id===selected.value));
const panel=computed(()=>servicePanel(props.kind));
async function load(){const rev=++revision;try{const all=await call<ServiceInstance[]>('list_service_instances',{id:props.serverId});if(rev!==revision)return;items.value=all.filter(i=>i.kind===props.kind);if(!current.value)selected.value=items.value[0]?.id??'default';}catch(e){if(rev===revision)error.value=String(e);}}
watch(()=>[props.serverId,props.kind,props.initialInstance],()=>{selected.value=props.initialInstance??'default';items.value=[];adding.value=false;error.value='';port.value=Math.min(65535,(catalog[props.kind]?.port??0)+1);void load();},{immediate:true});
watch(selected,()=>{removing.value=false;});onActivated(()=>{active=true;if(props.initialInstance)selected.value=props.initialInstance;void load();});onDeactivated(()=>{active=false;revision++;});
watch(()=>props.now,()=>{if(active&&!document.hidden&&!busy.value)void load();});
async function act(action:'add'|'remove'){if(busy.value)return;busy.value=true;error.value='';try{const base={id:props.serverId,kind:props.kind};if(action==='add'){const i=await call<ServiceInstance>('add_service_instance',{...base,port:port.value});await load();selected.value=i.id;emit('select',i.id);adding.value=false;}else{await call('remove_service_instance',{...base,instanceId:selected.value});selected.value='default';emit('select','default');removing.value=false;await load();}emit('updated');}catch(e){error.value=String(e);}finally{busy.value=false;}}
</script>
<template><section class="instances">
<template v-if="!current">
  <ServerTabBar :title="catalog[kind]?.name ?? kind" disabled><span>Loading…</span></ServerTabBar>
  <slot name="before-content"/>
  <p v-if="error" role="alert" class="error">{{error}}</p>
</template>
<KeepAlive :max="8" :key="serverId+kind"><component v-if="current" :is="panel" :key="selected" :server-id="serverId" :kind="kind" :instance-id="selected" :display-name="current.name" :now="now" :refresh-key="refreshKey" @updated="load();emit('updated')"><template #actions><button v-if="current.canRemove" class="remove" :disabled="busy||preview" aria-label="Remove connection from monitoring" title="Remove from monitoring" @click="removing=!removing"><UiIcon name="close" :size="14"/></button><button v-if="current.canAdd" class="add-button" :disabled="busy||preview" aria-label="Add connection" title="Add connection" @click="adding=!adding"><UiIcon name="plus" :size="15"/></button></template><template #before-content><slot name="before-content"/>
<nav v-if="items.length>1&&!hideSelector" class="connections" aria-label="Service connections"><button v-for="i in items" :key="i.id" :aria-pressed="selected===i.id" :class="{selected:selected===i.id}" :disabled="busy" @click="selected=i.id">{{i.name}}</button></nav>
<p v-if="error" role="alert" class="error">{{error}}</p>
<form v-if="adding" class="add" @submit.prevent="act('add')"><label>port<UiInput v-model.number="port" type="number" min="1" max="65535" required/></label><button :disabled="busy||preview">Add connection</button><button type="button" :disabled="busy" @click="adding=false">Cancel</button></form>
<div v-if="removing" class="confirmation"><p>Delete {{current?.name}} from monitoring, along with history and incidents.</p><button :disabled="busy||preview" @click="act('remove')">Remove connection and history</button><button :disabled="busy" @click="removing=false">Cancel</button></div>
</template></component></KeepAlive>
</section></template>
<style scoped>
.connections{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:20px}.connections button{background:none;border-color:transparent;color:var(--muted);font-size:12px}.connections button.selected{background:var(--hover);color:var(--text)}.connections .remove{margin-left:auto;padding:6px;color:var(--muted)}.add-button{padding:6px;min-width:32px;min-height:32px}.add{display:flex;align-items:end;gap:10px;flex-wrap:wrap;margin-bottom:18px}.add label{display:flex;flex-direction:column;gap:6px;color:var(--muted);font-size:12px}button{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:7px 9px;max-width:100%;box-sizing:border-box}button{cursor:pointer;font-size:12px}button:hover:enabled{background:var(--hover)}button:disabled{opacity:.45;cursor:default}.confirmation{margin-bottom:18px}.confirmation p{font-size:12px;line-height:1.6;color:var(--muted);overflow-wrap:anywhere}.confirmation button{margin-right:8px}.error{color:var(--danger);background:var(--danger-bg);padding:12px;border-radius:7px}button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
</style>
