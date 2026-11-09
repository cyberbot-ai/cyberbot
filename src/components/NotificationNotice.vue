<script setup lang="ts">
import {onMounted,onBeforeUnmount,ref,watch} from 'vue';
import {call,preview} from '../api';
import type {NotificationStatus} from '../types';
const props=defineProps<{refresh?:number}>();
const value=ref<NotificationStatus>(),busy=ref(false),error=ref('');let disposed=false;
async function load(){if(preview||busy.value||document.hidden)return;try{const result=await call<NotificationStatus>('notification_status');if(!disposed)value.value=result;}catch{/* The settings page provides diagnostics; monitoring is unaffected. */}}
async function allow(){if(busy.value)return;busy.value=true;error.value='';try{const result=await call<NotificationStatus>('request_notification_permission');if(!disposed)value.value=result;}catch(e){if(!disposed)error.value=String(e);}finally{busy.value=false;}}
async function settings(){try{await call('open_notification_settings');}catch(e){error.value=String(e);}}
onMounted(()=>{void load();window.addEventListener('focus',load);document.addEventListener('visibilitychange',load);});
onBeforeUnmount(()=>{disposed=true;window.removeEventListener('focus',load);document.removeEventListener('visibilitychange',load);});
watch(()=>props.refresh,()=>{void load();});
</script>
<template><aside v-if="value?.enabled&&['notDetermined','denied'].includes(value.permission)" class="notice" role="status"><div><strong>Allow notifications of new incidents</strong><p>{{value.permission==='denied'?'System settings → Notifications → Cyberbot. Enable notifications for the app.':'Cyberbot will be able to report problems even when the window is hidden.'}}</p><p v-if="error" class="error" role="alert">{{error}}</p></div><button v-if="value.permission==='notDetermined'" :disabled="busy" @click="allow">{{busy?'Waiting for permission…':'Allow notices'}}</button><button v-else @click="settings">Open the macOS settings</button></aside></template>
<style scoped>
.notice{display:flex;align-items:center;justify-content:space-between;gap:16px;background:var(--accent-bg);border-radius:8px;padding:12px 14px;margin:0 0 16px;font-size:12px;line-height:1.5}.notice>div{min-width:0}.notice strong{font-weight:550;color:var(--text)}p{color:var(--muted);margin:3px 0 0;overflow-wrap:anywhere}.error{color:var(--danger)}button{flex-shrink:0;font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:7px 10px;cursor:pointer}button:disabled{opacity:.6;cursor:default}button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}@media(max-width:650px){.notice{align-items:flex-start;flex-direction:column;gap:9px}button{max-width:100%}}
</style>
