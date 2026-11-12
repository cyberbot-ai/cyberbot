<script setup lang="ts">
import {onBeforeUnmount,onMounted,ref} from 'vue';
import {call,preview} from '../api';
import {updateSettings} from '../settings';
import type {NotificationStatus} from '../types';
const props = defineProps<{dockBadgeEnabled?: boolean}>();
const emit=defineEmits<{updated:[]}>();
const value=ref<NotificationStatus>(),busy=ref(false),error=ref(''),tested=ref(false);
const dockBadgeSaving = ref(false), dockBadgeError = ref('');
const labels:Record<string,string>={authorized:'Allowed by macOS',provisional:'Allowed without banners',denied:'Allow Cyberbot notifications in system settings.',notDetermined:'Permission not requested',unavailable:'Available in the installed macOS application',unsupported:'This OS is not yet supported',unknown:'Permission not verified'};
async function load(){try{value.value=await call<NotificationStatus>('notification_status');}catch(e){error.value=String(e);}}
onMounted(() => { void load(); window.addEventListener('focus', load); });
onBeforeUnmount(() => window.removeEventListener('focus', load));
async function change(enabled:boolean){if(busy.value||preview)return;busy.value=true;error.value='';try{value.value=await call<NotificationStatus>('configure_notifications',{enabled});emit('updated');}catch(e){error.value=String(e);}finally{busy.value=false;}}
async function test(){if(busy.value||preview)return;busy.value=true;error.value='';tested.value=false;try{await call('test_notification');tested.value=true;await load();}catch(e){error.value=String(e);}finally{busy.value=false;}}
async function changeDockBadge(event: Event) {
  const input = event.target as HTMLInputElement;
  dockBadgeSaving.value = true;
  dockBadgeError.value = '';
  try {
    await updateSettings({dockBadgeEnabled: input.checked});
  } catch (error) {
    input.checked = props.dockBadgeEnabled ?? true;
    dockBadgeError.value = String(error).replace(/^Error: /, '');
  } finally {
    dockBadgeSaving.value = false;
  }
}
async function allowDockBadge() {
  dockBadgeSaving.value = true;
  dockBadgeError.value = '';
  try {
    if (value.value?.permission !== 'denied') {
      value.value = await call<NotificationStatus>('request_notification_permission');
      emit('updated');
      if (value.value.badgeAllowed) return;
    }
    await call('open_notification_settings');
  } catch (error) {
    dockBadgeError.value = String(error).replace(/^Error: /, '');
  } finally {
    dockBadgeSaving.value = false;
  }
}
</script>
<template>
  <div class="notifications">
    <div :aria-busy="busy">
      <label><input type="checkbox" :checked="value?.enabled??false" :disabled="!value||busy||preview" @change="change(($event.target as HTMLInputElement).checked)">New incidents</label>
      <p>Notifications work while the window is hidden. Incidents within 5 seconds are grouped into one notification.</p>
      <p v-if="value" class="permission">{{labels[value.permission]??labels.unknown}}</p>
      <button type="button" :disabled="!value?.enabled||busy||preview" @click="test">Send test notification</button>
      <p v-if="tested" role="status">Test notification sent. Banner visibility depends on your notification and Focus settings.</p>
      <p v-if="error||value?.error" class="error" role="alert">{{error||value?.error}}</p>
      <p v-if="value?.overflow" class="error">{{value.overflow}} events exceeded the queue limit and will be included in the summary.</p>
    </div>
    <div :aria-busy="dockBadgeSaving">
      <label>
        <input type="checkbox" :checked="dockBadgeEnabled ?? true" :disabled="dockBadgeEnabled === undefined || dockBadgeSaving || preview" aria-describedby="dock-badge-description" @change="changeDockBadge">
        Show Dock badge
      </label>
      <p id="dock-badge-description">Counts each server with a Critical status or an open incident once.</p>
      <template v-if="dockBadgeEnabled && value && !value.badgeAllowed && !preview && ['notDetermined','denied','authorized','provisional'].includes(value.permission)">
        <p>Allow the Cyberbot app icon badge in macOS notification settings.</p>
        <button type="button" :disabled="dockBadgeSaving" @click="allowDockBadge">{{value.permission === 'denied' ? 'Open macOS settings' : 'Allow Dock badge'}}</button>
      </template>
      <p v-if="dockBadgeError" class="error" role="alert">{{dockBadgeError}}</p>
    </div>
  </div>
</template>
<style scoped>
.notifications{font-size:12px;line-height:1.6}label{display:flex;align-items:center;gap:8px;color:var(--text);margin:16px 0 10px}input{accent-color:var(--accent)}p{color:var(--muted);margin:8px 0;max-width:70ch}.error{color:var(--danger);overflow-wrap:anywhere}button{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:7px 10px;cursor:pointer;margin:5px 0}button:disabled{opacity:.45;cursor:default}input:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
</style>
