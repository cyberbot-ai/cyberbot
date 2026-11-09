<script setup lang="ts">
import {ref} from 'vue';
import {call,preview} from '../api';
import type {Incident} from '../types';
import UiIcon from './UiIcon.vue';
const props=defineProps<{incident:Incident}>();
const emit=defineEmits<{resolved:[];error:[message:string]}>();
const busy=ref(false);
async function resolve(){
 if(busy.value||preview)return;
 const i=props.incident;busy.value=true;
 try{await call('resolve_incident',{id:i.id,episode:i.episode||`${i.id}:${i.openedAt}`});emit('resolved');}
 catch(e){emit('error',String(e).replace(/^Error: /,''));}
 finally{busy.value=false;}
}
</script>
<template><button v-if="incident.status==='open'" type="button" class="resolve" :disabled="busy||preview" :aria-busy="busy" :aria-label="`Marking it up: ${incident.title}`" :title="busy?'Save it…':'Marking it up'" @click.stop="resolve"><UiIcon name="resolve" :size="18"/></button></template>
<style scoped>
.resolve{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;width:32px;height:32px;padding:6px;border:0;background:transparent;color:var(--muted);border-radius:6px;cursor:pointer}.resolve:hover:enabled{color:var(--success);background:var(--accent-bg)}.resolve:disabled{opacity:.45;cursor:default}.resolve:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
</style>
