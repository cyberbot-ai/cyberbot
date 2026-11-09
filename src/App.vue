<script setup lang="ts">
import RefreshButton from './components/RefreshButton.vue';
import { computed, onBeforeUnmount, onMounted, provide, reactive, ref, watch, nextTick } from 'vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { call, preview } from './api';
import { health } from './health';
import { fleetSortColumns, sortFleet, type FleetSort, type FleetSortKey } from './fleetSort';
import RelativeDate from './components/RelativeDate.vue';
import { useClock } from './useClock';
import type { AgentStatus, InventoryFile, Server, Settings, Snapshot, StorageStatus } from './types';
import FleetGrid from './components/FleetGrid.vue';
import FleetConsole from './components/FleetConsole.vue';
import ActionApprovalWindow from './components/ActionApprovalWindow.vue';
const approvalRequestId=new URLSearchParams(location.search).get('approval');
import ServerDetail from './components/ServerDetail.vue';
import AutoPanel from './components/AutoPanel.vue';
import AiAgentSettings from './components/AiAgentSettings.vue';
import ActivityLog from './components/ActivityLog.vue';
import LocalResourceSummary from './components/LocalResourceSummary.vue';
import AutomationMode from './components/AutomationMode.vue';
import IncidentGroups from './components/IncidentGroups.vue';
import IncidentList from './components/IncidentList.vue';
import ResolveAllIncidentsButton from './components/ResolveAllIncidentsButton.vue';
import UiIcon from './components/UiIcon.vue';
import UiInput from './components/UiInput.vue';
import MonitoringSettings from './components/MonitoringSettings.vue';
import MonitoringLibrary from './components/MonitoringLibrary.vue';
import { monitoringInterval } from './monitoring';
import { serverDirectory, serverDirectoryKey, type ServerIdentity, type ServerSection } from './serverDirectory';
import type {MonitoringTarget} from './types';
const monitoringTarget=ref<MonitoringTarget>();
function openMonitoring(target:MonitoringTarget){monitoringTarget.value=target;page.value='monitoring';}
import NotificationSettings from './components/NotificationSettings.vue';
import NotificationNotice from './components/NotificationNotice.vue';
const notificationRevision=ref(0);
import { onSettingsSaved, updateSettings } from './settings';
import { initialAiTab, readCliChecks, rememberCliChecks, type AiTab } from './aiNavigation';
import {appearanceKey,readAppearance,saveAppearance,effectiveTheme,type ThemeMode} from './appearance';

const storage=ref<StorageStatus>();
const aiTab = ref<AiTab>();
const cliChecks = ref(readCliChecks());
async function showAiTab(tab: AiTab) {
  aiTab.value = tab;
  page.value = 'automation';
  await nextTick();
  document.getElementById(`ai-${tab}-tab`)?.focus();
}
async function openAiSettings() {
  if (standalone && !preview) {
    try { await call('open_ai_settings'); } catch (e) { report(e); }
    return;
  }
  await closeDetails();
  await showAiTab('settings');
}
const pauseBusy=ref(false);
const page=ref('fleet');const data=ref<Snapshot>();const now=useClock();const search=ref('');const filter=ref('all');const compact=ref(true);
const fleetSort = ref<FleetSort>({ key: 'host', direction: 'ascending' });
function changeFleetSort(key: FleetSortKey) {
  const { key: current, direction } = fleetSort.value;
  const ascending = key === current ? direction === 'descending' : key === 'host';
  fleetSort.value = { key, direction: ascending ? 'ascending' : 'descending' };
}
const fleetScrollResetKey = computed(() => JSON.stringify([fleetSort.value.key, fleetSort.value.direction, search.value, filter.value]));
const searchOpen=ref(false),searchInput=ref<HTMLInputElement>(),searchButton=ref<HTMLButtonElement>();
function closeSearch(){search.value='';searchOpen.value=false;void nextTick(()=>searchButton.value?.focus());}
async function toggleSearch(){if(searchOpen.value){closeSearch();return;}searchOpen.value=true;await nextTick();searchInput.value?.focus();}
const sourceForm=ref(false),managementOpen=ref(false);const managementButton=ref<HTMLButtonElement>();const busy=ref(false);const error=ref('');const selectedId=ref(new URLSearchParams(location.search).get('server')??'');
const selectedSection=ref<'incidents'>();
function openServer(id:string,section?:'incidents'){selectedSection.value=section;selectedId.value=id;}
const standalone=Boolean(selectedId.value);const confirmingDelete=ref('');
const agents = ref<AgentStatus[]>([]);
const agentBusy = ref(false);
const agentError = ref('');
const form=reactive({kind:'manual',location:''});
const inventoryFile=ref<InventoryFile>(),choosingInventory=ref(false);
const defaults:Settings={mode:'manual',dailyRunLimit:null,dailyTokenLimit:null,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false};
const settings=computed(()=>data.value?.settings??defaults);
const selectedCliCheck = computed(() => cliChecks.value[settings.value.autoAgent]);
watch(data, snapshot => {
  if (snapshot && page.value === 'automation' && !aiTab.value) {
    aiTab.value = initialAiTab(snapshot, cliChecks.value);
  }
});
const showResolved=ref(false);
const appearance=reactive(readAppearance()),appearanceError=ref('');
const theme=computed(()=>effectiveTheme(appearance,new Date(now.value*1000)));
const themeOptions: {id:ThemeMode;icon:string;label:string}[]=[{id:'light',icon:'sun',label:'Light'},{id:'dark',icon:'moon',label:'Dark'},{id:'auto',icon:'clock',label:'Scheduled'}];
const nextTheme=computed(()=>{
  const index=themeOptions.findIndex(option=>option.id===appearance.mode);
  return themeOptions[(index+1)%themeOptions.length];
});
const themeShortcutLabel=computed(()=>appearance.mode==='auto'?'Scheduled theme':theme.value==='dark'?'Dark theme':'Light theme');
const themeShortcutTitle=computed(()=>`Next theme — ${nextTheme.value.label.toLowerCase()}`);
function cycleTheme(){appearance.mode=nextTheme.value.id;}
watch(appearance,()=>{appearanceError.value=saveAppearance(appearance)?'':'Choose different start times for light and dark themes before saving.';});
function syncAppearance(e:StorageEvent){if(e.key===appearanceKey)Object.assign(appearance,readAppearance());}
const sourceDialog=ref<HTMLDialogElement>(),managementDialog=ref<HTMLDialogElement>(),detailDialog=ref<HTMLDialogElement>();
let detailReturnFocus:HTMLElement|undefined;
watch(selectedId,async(id,previous)=>{
  if(standalone)return;
  if(id&&!previous)detailReturnFocus=document.activeElement instanceof HTMLElement?document.activeElement:undefined;
  if(!id&&previous){const target=detailReturnFocus;detailReturnFocus=undefined;await nextTick();if(target?.isConnected)target.focus({preventScroll:true});}
},{flush:'sync'});
watch([sourceForm,managementOpen,selectedId],async()=>{await nextTick();if(managementOpen.value&&!managementDialog.value?.open)managementDialog.value?.showModal();if(sourceForm.value&&!sourceDialog.value?.open)sourceDialog.value?.showModal();if(selectedId.value&&!standalone&&!detailDialog.value?.open)detailDialog.value?.showModal();});
function backdrop(e:MouseEvent,kind:string){if(e.target!==e.currentTarget)return;const r=(e.currentTarget as HTMLElement).getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom){if(kind==='source'){if(!busy.value)sourceForm.value=false;}else if(kind==='management')closeManagement();else void closeDetails();}}
const pages=[{id:'fleet',icon:'servers',label:'Servers'},{id:'incidents',icon:'incident',label:'Incidents'},{id:'automation',icon:'auto',label:'AI'},{id:'activity',icon:'history',label:'Activity log'},{id:'monitoring',icon:'monitoring',label:'Library'},{id:'settings',icon:'settings',label:'Settings'}];
const consoleSelection=ref<string[]|null>(null);
const title=computed(()=>page.value==='console'?'Console':pages.find(p=>p.id===page.value)?.label??'Infrastructure');
const servers=computed(()=>data.value?.servers.map(s=>({...s,networkOffline:data.value?.offline??false,awaitingFirstCheck:data.value?.awaitingFirstCheck?.includes(s.id)??false,monitoring:data.value?.monitoring?.[s.id],services:data.value?.services?.[s.id],checkStatus:data.value?.checkStatus?.[s.id],vulnerabilities:data.value?.vulnerabilities?.[s.id],logStatus:data.value?.logStatus[s.id]??'unknown'}))??[]);
const approvalServers = ref<ServerIdentity[]>([]);
const directory = computed(() => serverDirectory(approvalRequestId ? approvalServers.value : servers.value));
provide(serverDirectoryKey, {
  current: () => directory.value,
  open: (id, section) => {
    if (approvalRequestId || standalone) return call<void>('open_server_sidebar', { id, incidents: section === 'incidents' });
    openServer(id, section);
  },
});
async function loadApprovalServers() {
  try {
    const list = preview ? (await call<Snapshot>('snapshot')).servers : await call<ServerIdentity[]>('server_directory');
    if (!stopped) approvalServers.value = list;
  } catch {
    // The approval still shows its captured addresses when the directory is unavailable.
  }
}
async function openSidebar(id: string, section?: ServerSection) {
  if (!directory.value.byId.has(id)) await reload();
  if (!stopped && directory.value.byId.has(id)) openServer(id, section);
}
const groupCount=ref(0),showIndividual=ref(true);
const incidents=computed(()=>data.value?.incidents.filter(i=>i.status==='open')??[]);
const notificationIds=ref<Set<string>|null>(null);
const incidentVersion=computed(()=>(data.value?.incidents??[]).map(i=>`${i.id}:${i.episode}:${i.status}`).join('|'));
const incidentRows=computed(()=>[...(data.value?.incidents??[])].reverse().filter(i=>notificationIds.value?notificationIds.value.has(i.id)&&(showResolved.value||!i.resolvedByUserAt):showResolved.value||i.status==='open'));
let offNotifications:UnlistenFn|undefined,offAiSettings:UnlistenFn|undefined,offServerSidebar:UnlistenFn|undefined;
async function openNotification(){try{const target=await call<{open:boolean;incidentIds:string[];openActions?:boolean;actionRequestId?:string}>('take_notification_target');if(stopped||!target?.open)return;selectedId.value='';if(target.openActions){if(target.actionRequestId){await call('open_action_approval',{id:target.actionRequestId});return;}await showAiTab('actions');return;}notificationIds.value=target.incidentIds.length?new Set(target.incidentIds):null;groupCount.value=0;showIndividual.value=true;page.value='incidents';await reload();}catch(e){if(!stopped)report(e);}}
const selected=computed(()=>servers.value.find(s=>s.id===selectedId.value));
const healthy=computed(()=>servers.value.filter(s=>health(s,now.value,settings.value.pollSeconds)==='healthy').length);
const problems=computed(()=>servers.value.filter(s=>['critical','warning','unreachable','stale'].includes(health(s,now.value,settings.value.pollSeconds))).length);
const hasRedProblems=computed(()=>servers.value.some(s=>['critical','unreachable','stale'].includes(health(s,now.value,settings.value.pollSeconds))));
const unknown=computed(()=>servers.value.length-healthy.value-problems.value);
const pollingInterval=computed(()=>{const seconds=data.value?.settings.pollSeconds;return seconds==null?'—':monitoringInterval(seconds);});
const pollingLabel=computed(()=>!data.value?'Loading…':data.value.settings.paused?'Monitoring paused':`Polling every ${pollingInterval.value}`);
const filtered=computed(()=>servers.value.filter(s=>{
  const query=search.value.toLowerCase();const state=health(s,now.value,settings.value.pollSeconds);
  return (!query||[s.name,s.endpoint.host].some(v=>v.toLowerCase().includes(query)))&&(filter.value==='all'||(filter.value==='problems'?['critical','warning','unreachable','stale'].includes(state):filter.value==='unknown'?state==='unknown':state===filter.value));
}));
const orderedServers = computed(() => sortFleet(filtered.value, fleetSort.value, now.value, settings.value.pollSeconds));
let reloadTimer: ReturnType<typeof setTimeout> | undefined;
let reloading: Promise<void> | undefined, followUp: Promise<void> | undefined;
let unlisten:UnlistenFn|undefined;let stopSettingsListener:(()=>void)|undefined;let stopped=false,settingsRevision=0;
function report(e:unknown){error.value=String(e).replace(/^Error: /,'');}
async function fetchSnapshot() {
  const revision = settingsRevision;
  try {
    const [snapshot, stored] = await Promise.allSettled([call<Snapshot>('snapshot'), call<StorageStatus>('storage_status')]);
    if (stopped) return;
    if (snapshot.status === 'rejected') throw snapshot.reason;
    if (revision !== settingsRevision && data.value) snapshot.value.settings = data.value.settings;
    data.value = snapshot.value;
    if (stored.status === 'fulfilled') storage.value = stored.value;
    else report(stored.reason);
  } catch (e) {
    if (!stopped) report(e);
  }
}
function reload(): Promise<void> {
  clearTimeout(reloadTimer);
  reloadTimer = undefined;
  if (stopped) return Promise.resolve();
  if (reloading) {
    // Every request during the current read shares one read that starts after it.
    followUp ??= reloading.then(() => { followUp = undefined; return reload(); });
    return followUp;
  }
  reloading = fetchSnapshot().finally(() => { reloading = undefined; });
  return reloading;
}
function queueReload() {
  if (document.hidden || stopped || reloadTimer !== undefined) return;
  reloadTimer = setTimeout(() => {
    reloadTimer = undefined;
    if (!document.hidden) void reload();
  }, 250);
}
function visibility(){if(!document.hidden)void reload();}
onMounted(async()=>{if(approvalRequestId){window.addEventListener('storage',syncAppearance);window.addEventListener('focus',loadApprovalServers);void loadApprovalServers();return;}stopSettingsListener=onSettingsSaved(acceptSettings);if(!preview&&!standalone){const off=await listen<{id:string;incidents:boolean}>('server-sidebar-open',({payload})=>{void openSidebar(payload.id,payload.incidents?'incidents':undefined);});if(stopped){off();return;}offServerSidebar=off;}await reload();if(stopped)return;if(!preview){const off=await listen('state-changed',queueReload);if(stopped)off();else unlisten=off;if(!standalone){const aiNavigation=await listen('ai-settings-open',()=>{void openAiSettings();});if(stopped)aiNavigation();else offAiSettings=aiNavigation;const notice=await listen('notification-open',()=>{void openNotification();});if(stopped)notice();else offNotifications=notice;await openNotification();}}document.addEventListener('visibilitychange',visibility);window.addEventListener('focus',visibility);window.addEventListener('storage',syncAppearance);});
onBeforeUnmount(()=>{stopped=true;clearTimeout(reloadTimer);unlisten?.();offNotifications?.();offAiSettings?.();offServerSidebar?.();stopSettingsListener?.();document.removeEventListener('visibilitychange',visibility);window.removeEventListener('focus',visibility);window.removeEventListener('focus',loadApprovalServers);window.removeEventListener('storage',syncAppearance);});
async function importSource(source:{kind:string;location:string}){busy.value=true;error.value='';try{await call('add_source',source);sourceForm.value=false;form.location='';inventoryFile.value=undefined;await reload();}catch(e){report(e);}finally{busy.value=false;}}
async function add(){if(busy.value||preview)return;if(form.kind==='ansible'){if(inventoryFile.value)await importSource({kind:'ansible',location:inventoryFile.value.location});}else await importSource({...form});}
async function chooseInventory(){if(busy.value||preview)return;busy.value=true;choosingInventory.value=true;error.value='';try{const file=await call<InventoryFile|null>('pick_inventory_file');if(file){inventoryFile.value=file;choosingInventory.value=false;await importSource({kind:'ansible',location:file.location});}}catch(e){report(e);}finally{busy.value=false;choosingInventory.value=false;}}
function sourceKind(kind:string){if(busy.value)return;form.kind=kind;form.location='';inventoryFile.value=undefined;error.value='';}
async function refresh(id:string){busy.value=true;try{await call('refresh_source',{id});await reload();}catch(e){report(e);await reload();}finally{busy.value=false;}}
async function remove(id:string){busy.value=true;try{await call('delete_source',{id});confirmingDelete.value='';await reload();}catch(e){report(e);}finally{busy.value=false;}}
function acceptSettings(value:Settings){if(data.value){settingsRevision++;data.value.settings=value;}}
function automationSaved(value?:Settings){if(value){if(data.value?.settings!==value)acceptSettings(value);}else void reload();}
async function togglePause(){if(!data.value||pauseBusy.value)return;pauseBusy.value=true;error.value='';try{await updateSettings({paused:!data.value.settings.paused});}catch(e){report(e);}finally{pauseBusy.value=false;}}
async function detect() {
  if (agentBusy.value || preview) return;
  agentBusy.value = true;
  agentError.value = '';
  try {
    agents.value = await call<AgentStatus[]>('detect_agents');
    cliChecks.value = rememberCliChecks(cliChecks.value, agents.value);
  } catch (e) {
    agentError.value = String(e).replace(/^Error: /, '');
  } finally {
    agentBusy.value = false;
  }
}
async function detach(){try{await call('open_server',{id:selectedId.value});selectedId.value='';}catch(e){report(e);}}
function closeManagement(){managementOpen.value=false;confirmingDelete.value='';void nextTick(()=>managementButton.value?.focus());}
function addFromManagement(){managementOpen.value=false;confirmingDelete.value='';error.value='';sourceForm.value=true;}
function changePage(id: string) {
  if (id === 'automation' && page.value !== id) {
    aiTab.value = data.value ? initialAiTab(data.value, cliChecks.value) : undefined;
  }
  if (id === 'monitoring' && page.value !== id) monitoringTarget.value = undefined;
  page.value = id;
  notificationIds.value = null;
  if (id === 'settings' && data.value) Object.assign(settings, data.value.settings);
}
async function closeDetails(){if(standalone&&!preview){try{await getCurrentWindow().close();}catch(e){report(e);}}else{detailDialog.value?.close();selectedId.value='';}}
</script>

<template>
<div class="app" :class="{standalone,'approval-window':approvalRequestId}" :data-theme="theme">
  <ActionApprovalWindow v-if="approvalRequestId" :request-id="approvalRequestId"/>
  <template v-else>
  <aside v-if="!standalone" class="sidebar">
    <div class="brand"><span class="brand-logo" aria-hidden="true"></span><strong>cyberbot</strong></div>
    <nav aria-label="Main navigation">
      <button v-for="item in pages" :key="item.id" :class="{active:page===item.id}" :aria-current="page===item.id?'page':undefined"
        :aria-label="item.id === 'automation' && data?.pendingActions ? `AI, ${data.pendingActions} requests awaiting approval` : undefined"
        :title="item.label" @click="changePage(item.id)">
        <UiIcon :name="item.icon"/><span class="nav-text">{{item.label}}</span>
        <span v-if="item.id==='automation' && data?.pendingActions" class="nav-count" aria-hidden="true">{{data.pendingActions}}</span>
        <span v-if="item.id==='incidents' && incidents.length" class="nav-count">{{incidents.length}}</span>
      </button>
    </nav>
    <div class="sidebar-bottom"><button type="button" class="theme-shortcut" :title="themeShortcutTitle" :aria-label="`${themeShortcutLabel}. ${themeShortcutTitle}`" @click="cycleTheme"><UiIcon :name="theme==='dark'?'moon':'sun'"/><span>{{themeShortcutLabel}}</span></button><div class="monitor-control" :class="{paused:data?.settings.paused}" :title="pollingLabel"><span class="monitor-caption" role="status" :aria-label="pollingLabel"><span class="monitor-full">{{pollingLabel}}</span><span class="monitor-short" aria-hidden="true">{{data?.settings.paused?'Pause':pollingInterval}}</span></span><button type="button" class="monitor-toggle" :disabled="!data||pauseBusy" :aria-busy="pauseBusy" :aria-label="data?.settings.paused?'Resume monitoring':'Pause monitoring'" :title="data?.settings.paused?'Resume monitoring':'Pause polling and automatic investigations'" @click="togglePause"><UiIcon :name="data?.settings.paused?'play':'pause'" :size="16"/></button></div></div>
  </aside>
  <main v-if="!standalone" class="main" :class="{'fleet-page':page==='fleet'}">
    <header class="page-head" :class="{searching:page==='fleet'&&searchOpen,'activity-head':page==='activity','automation-head':page==='automation'}">
      <div class="page-title">
        <AutomationMode v-if="page==='automation' && data" :settings="data.settings" @saved="automationSaved">
          <template #badge><span v-if="preview" class="preview" title="Demo data. SSH and AI are disabled.">Demo</span></template>
        </AutomationMode>
        <h1 v-else>{{title}}</h1><div v-if="page==='fleet'" class="title-search"><button ref="searchButton" type="button" class="search-toggle" :aria-label="searchOpen?'Close search':'Search servers'" :title="searchOpen?'Close search':'Search servers'" :aria-expanded="searchOpen" :aria-controls="searchOpen?'fleet-search':undefined" @click="toggleSearch"><UiIcon name="search" :size="16"/></button><input v-if="searchOpen" id="fleet-search" ref="searchInput" v-model="search" type="search" placeholder="Name or address" aria-label="Search servers" autocomplete="off" @keydown.esc.stop.prevent="closeSearch"></div><span v-if="preview && (page!=='automation' || !data)" class="preview" title="Demo data. SSH and AI are disabled.">Demo</span><LocalResourceSummary v-if="page==='activity'" class="resource-summary"/></div><div class="head-actions"><button type="button" class="console-link" title="Console" aria-label="Console" :aria-current="page==='console'?'page':undefined" @click="changePage('console')"><UiIcon name="console" :size="17"/></button><AutomationMode v-if="data&&page!=='automation'" :settings="data.settings" compact @saved="automationSaved"/><button v-if="page==='fleet'" class="primary" @click="sourceForm=true"><UiIcon name="plus" :size="16"/>Add server</button></div></header>
    <p v-if="data?.offline" class="connectivity-notice" role="status">No internet connection. Server data is temporarily unavailable.</p>
    <NotificationNotice v-if="!preview" :refresh="notificationRevision"/><div v-if="storage?.blocked" class="error" role="alert">{{storage.message}}</div>
    <div v-if="error" class="error" role="alert"><span>{{error}}</span><button aria-label="Dismiss error" @click="error=''"><UiIcon name="close"/></button></div>
    <template v-if="page==='fleet'">
      <div class="fleet-controls">
      <div class="fleet-filters" aria-label="Server status"><button :aria-pressed="filter==='all'" :class="{chosen:filter==='all'}" @click="filter='all'">All <span>{{servers.length}}</span></button><button :aria-pressed="filter==='problems'" :class="{chosen:filter==='problems'}" @click="filter='problems'"><i v-if="problems>0" class="dot attention-dot" :class="{critical:hasRedProblems}" aria-hidden="true"></i>Needs attention <span>{{problems}}</span></button><button :aria-pressed="filter==='healthy'" :class="{chosen:filter==='healthy'}" @click="filter='healthy'">Healthy <span>{{healthy}}</span></button><button :aria-pressed="filter==='unknown'" :class="{chosen:filter==='unknown'}" @click="filter='unknown'">Insufficient data <span>{{unknown}}</span></button><span v-if="search||filter!=='all'" class="result-count">Found {{filtered.length}}</span></div>
      <div class="fleet-toolbar"><button ref="managementButton" type="button" class="manage-servers quiet" aria-label="Manage servers" title="Manage servers" aria-haspopup="dialog" :aria-controls="managementOpen?'server-management':undefined" @click="managementOpen=true"><UiIcon name="gear" :size="16"/>Manage</button><div class="view-switch" aria-label="Server view"><button :aria-pressed="!compact" :class="{active:!compact}" aria-label="Grid view" title="Grid view" @click="compact=false"><UiIcon name="grid" :size="16"/></button><button :aria-pressed="compact" :class="{active:compact}" aria-label="List view" title="List view" @click="compact=true"><UiIcon name="list" :size="16"/></button></div></div>
      </div>
      <div v-if="servers.length" class="fleet-sort" role="group" aria-label="Sort servers">
        <span class="sort-label" aria-hidden="true">Sort by</span>
        <button v-for="column in fleetSortColumns" :key="column.key" type="button" :title="column.hint"
          :aria-pressed="fleetSort.key === column.key"
          :aria-label="fleetSort.key === column.key ? `${column.label}, ${fleetSort.direction}` : undefined"
          @click="changeFleetSort(column.key)">
          {{ column.label }} <span v-if="fleetSort.key === column.key" aria-hidden="true">{{ fleetSort.direction === 'ascending' ? '↑' : '↓' }}</span>
        </button>
      </div>
      <div v-if="!data" class="loading" role="status">Loading infrastructure…</div>
      <div v-else-if="servers.length===0" class="empty"><UiIcon name="servers" :size="36"/><h2>Connect your servers</h2><p>Add an Ansible inventory or a list of hosts.<br>Metrics appear after the first SSH poll.</p><button class="primary" @click="sourceForm=true">Add server</button></div>
      <div v-else-if="!filtered.length" class="empty"><h2>No servers found</h2><p>Try a different search or reset the filters.</p><button @click="search='';filter='all'">Reset filters</button></div>
      <div v-else class="fleet"><FleetGrid :servers="orderedServers" :now="now" :interval="settings.pollSeconds" :compact="compact" :scroll-reset-key="fleetScrollResetKey" @select="openServer($event.id)"/></div>
    </template>
    <section v-else-if="page==='incidents'" class="scroll-content">
      <p v-if="notificationIds" class="notification-selection">Incidents from notification <button @click="notificationIds=null">All incidents</button></p>
      <div class="section-toolbar">
        <p>{{notificationIds?incidentRows.length:incidents.length}} {{notificationIds?'notice':'open'}}</p>
        <div class="incident-actions">
          <label class="checkbox"><input v-model="showResolved" type="checkbox">Show resolved</label>
          <ResolveAllIncidentsButton :incidents="notificationIds ? incidentRows : incidents"
            :title="notificationIds ? 'Mark open incidents from the notification' : 'Mark open incidents on all servers'"
            @updated="reload" @error="report"/>
        </div>
      </div>
      <IncidentGroups v-if="!notificationIds" :refresh-key="incidentVersion" :now="now" :show-resolved="showResolved"
        @ai-settings="openAiSettings" @updated="reload" @count="groupCount=$event"/>
      <label v-if="groupCount" class="checkbox"><input v-model="showIndividual" type="checkbox">Show individual incidents</label>
      <IncidentList v-if="!groupCount||showIndividual" :incidents="incidentRows" show-server
        @open="openServer($event.serverId,'incidents')" @updated="reload" @error="report"/>
      <div v-if="!groupCount&&!incidentRows.length" class="empty"><UiIcon name="check" :size="32"/><h2>No open incidents</h2><p>Issues detected by monitoring will appear here.<br>Use the Insufficient data filter to find servers without enough data.</p></div>
    </section>
    <section v-else-if="page==='console'" class="scroll-content"><FleetConsole v-if="data" v-model="consoleSelection" :servers="servers" :ai-agent="settings.autoAgent" @ai-settings="openAiSettings"/></section>
    <section v-else-if="page==='activity'" class="scroll-content"><ActivityLog @monitoring="openMonitoring"/></section>
    <section v-else-if="page==='monitoring'" class="scroll-content"><MonitoringLibrary :servers="servers" :now="now" :initial="monitoringTarget" @updated="reload"/></section>
    <template v-else-if="page==='automation'">
      <AutoPanel v-if="data && aiTab" :tab="aiTab" :settings="data.settings" :pending-actions="data.pendingActions"
        @update:tab="aiTab = $event" @saved="automationSaved" @open="openServer">
        <template #agent>
          <AiAgentSettings :settings="data.settings" @saved="automationSaved"/>
          <div class="cli-check">
            <div class="cli-check-row">
              <div>
                <h3>CLI check</h3>
                <p role="status">{{ preview ? 'Available in the desktop app.' : selectedCliCheck === true ? 'The selected agent’s CLI is ready.' : selectedCliCheck === false ? 'The selected agent’s CLI check failed.' : 'Check the selected agent’s CLI to finish setup.' }}</p>
              </div>
              <button type="button" :disabled="agentBusy || preview" :aria-busy="agentBusy" @click="detect">
                {{ agentBusy ? 'Checking…' : 'Check CLI' }}
              </button>
            </div>
            <p v-if="agentError" class="cli-error" role="alert">Failed to check the CLI. {{ agentError }}</p>
            <ul v-if="agents.length" class="cli-results">
              <li v-for="agent in agents" :key="agent.name">
                <div class="cli-result-title">
                  <strong>{{ agent.name === 'codex' ? 'Codex' : 'Claude Code' }}</strong>
                  <span :class="agent.ready ? 'cli-ready' : 'cli-unavailable'">{{ agent.ready ? 'Ready' : 'Unavailable' }}</span>
                  <small v-if="agent.version">{{ agent.version }}</small>
                </div>
                <p>{{ agent.reason }}</p>
                <code v-if="agent.path">{{ agent.path }}</code>
              </li>
            </ul>
          </div>
        </template>
      </AutoPanel>
    </template>
    <section v-else class="scroll-content settings">
      <section class="settings-section"><h2>Appearance</h2><p>The interface theme on this computer.</p><div class="theme-options"><button v-for="option in themeOptions" :key="option.id" :aria-pressed="appearance.mode===option.id" :class="{selected:appearance.mode===option.id}" @click="appearance.mode=option.id"><UiIcon :name="option.icon"/>{{option.label}}</button></div><div v-if="appearance.mode==='auto'" class="fields schedule"><label>Dark theme from<UiInput v-model="appearance.nightStart" type="time" required/></label><label>Light theme from<UiInput v-model="appearance.nightEnd" type="time" required/></label><p>Local computer time.</p></div><p v-if="appearanceError" class="text-error" role="alert">{{appearanceError}}</p></section>
      <section class="settings-section"><h2>Monitoring</h2><MonitoringSettings v-if="data" :settings="data.settings" @saved="automationSaved"/></section>
      <section class="settings-section"><h2>Notifications</h2><NotificationSettings @updated="notificationRevision++"/></section>
      <section class="settings-section"><h2>Storage</h2><p v-if="storage?.activity?.error" class="text-error" role="alert">{{storage.activity.error}}</p><p v-if="storage?.activity?.dropped" class="text-error">Dropped log events: {{storage.activity.dropped}}</p><dl class="storage"><div><dt>Activity log</dt><dd>{{((storage?.activity?.bytes??0)/1048576).toFixed(1)}} / 30 MiB</dd></div><div><dt>AI action</dt><dd>{{((storage?.actions?.bytes??0)/1048576).toFixed(1)}} / 32 MiB</dd></div><div><dt>Database</dt><dd>{{((storage?.databaseBytes??0)/1048576).toFixed(1)}} / 1024 MiB</dd></div><div><dt>SQLite write-ahead log</dt><dd>{{((storage?.walBytes??0)/1048576).toFixed(1)}} MiB</dd></div><div><dt>Vulnerability data</dt><dd>{{((storage?.cacheBytes??0)/1048576).toFixed(1)}} / 128 MiB</dd></div></dl><details class="help"><summary>Retention and limits</summary><p>The activity log keeps up to 30 MiB across rotated files. Old entries are deleted automatically. The log excludes code, AI requests, passwords, keys, and command output. A separate private SQLite database stores AI action records for up to 7 days, with limits of 32 MiB, 1,000 completed records, and 20 active requests.</p><p>Metrics are retained for up to 30 days and 120,000 records. Regular reports are kept for 7 days and closed incidents for 30 days. Evidence for open incidents is preserved. Cleanup runs every minute. Data collection pauses when the database is full.</p><p>Metrics, logs, service diagnostics, critical OS vulnerabilities, and reusable checks are supported, and target memory limits, CPUs, and long-term performance have not yet been confirmed by load tests.</p></details></section>
    </section>
  </main>
  <dialog v-if="managementOpen&&!standalone" id="server-management" ref="managementDialog" class="management-dialog" aria-labelledby="management-title" @cancel.prevent="closeManagement" @click="backdrop($event,'management')">
    <header class="management-head"><h2 id="management-title">Manage servers</h2><div class="row-actions"><button class="primary" @click="addFromManagement"><UiIcon name="plus" :size="16"/>Add server</button><button type="button" class="icon-button" aria-label="Close server management" @click="closeManagement"><UiIcon name="close"/></button></div></header>
    <p v-if="error" class="text-error" role="alert">{{error}}</p>
      <p class="page-intro">Servers from Ansible inventory and manual lists.</p>
      <article v-for="source in data?.sources" :key="source.id" class="source-row"><UiIcon name="sources"/><div class="source-description"><h3>{{source.name}} <span>{{source.kind==='manual'?'Manual list':'Ansible'}}</span></h3><p>{{servers.filter(s=>s.sourceId===source.id).length}} servers · <RelativeDate :at="source.lastSync" empty="Not synced yet"/></p><code v-if="source.kind!=='manual'">{{source.location}}</code><p v-if="source.error" class="text-error">{{source.error}}</p></div><div class="row-actions"><RefreshButton :disabled="busy||preview" @click="refresh(source.id)">Refresh</RefreshButton><button v-if="confirmingDelete!==source.id" class="quiet" :disabled="preview" @click="confirmingDelete=source.id">Delete</button><template v-else><button class="danger" :disabled="busy" @click="remove(source.id)">Delete list and history</button><button @click="confirmingDelete=''">Cancel</button></template></div></article>
      <div v-if="!data?.sources.length" class="empty"><h2>No servers yet</h2><p>Add an inventory or enter a list of servers.</p></div>
      <details class="help"><summary>How the server list is updated</summary><p>Cyberbot reads the selected inventory every 5 minutes. If it cannot read the file, it keeps the last successful server list. Inventory files are read as data.</p></details>
  </dialog>
  <dialog v-if="selected&&!standalone" ref="detailDialog" class="detail-dialog" aria-label="Server" @cancel.prevent="closeDetails" @click="backdrop($event,'detail')"><div class="detail-panel" tabindex="-1" autofocus><ServerDetail :key="selected.id" :ai-agent="settings.autoAgent" @ai-settings="openAiSettings" :initial-section="selectedSection" :initial-show-resolved="selectedSection==='incidents'&&showResolved" :incidents="data?.incidents??[]" :server="selected" :now="now" :interval="settings.pollSeconds" @close="closeDetails" @detach="detach" @updated="reload" @error="report"/></div></dialog>
  <div v-if="standalone" class="standalone-detail"><div v-if="error" class="error" role="alert">{{error}}</div><ServerDetail :ai-agent="settings.autoAgent" @ai-settings="openAiSettings" v-if="selected" :initial-section="selectedSection" :initial-show-resolved="selectedSection==='incidents'&&showResolved" :incidents="data?.incidents??[]" :server="selected" :now="now" :interval="settings.pollSeconds" standalone @close="closeDetails" @updated="reload" @error="report"/><div v-else class="empty"><h2>No server found</h2><p>The server may have been removed or may still be loading.</p></div></div>
  <dialog v-if="sourceForm" ref="sourceDialog" class="source-dialog" aria-labelledby="source-title" @cancel.prevent="!busy&&(sourceForm=false)" @click="backdrop($event,'source')">
    <form class="source-form" @submit.prevent="add">
      <header><h2 id="source-title">Add server</h2><button type="button" class="icon-button" aria-label="Close add server form" :disabled="busy" @click="sourceForm=false"><UiIcon name="close"/></button></header>
      <div class="tabs"><button type="button" :disabled="busy" :aria-pressed="form.kind==='manual'" :class="{active:form.kind==='manual'}" @click="sourceKind('manual')">Manual list</button><button type="button" :disabled="busy" :aria-pressed="form.kind==='ansible'" :class="{active:form.kind==='ansible'}" @click="sourceKind('ansible')">Ansible inventory</button></div>
      <label v-if="form.kind==='manual'">Hosts or IP addresses, one per line<textarea v-model="form.location" required rows="6" :disabled="busy" placeholder="10.20.1.10&#10;db.example.com&#10;ops@web.example.com:2222"></textarea></label>
      <div v-else class="inventory-picker"><button type="button" class="primary" :disabled="busy||preview" @click="chooseInventory"><UiIcon name="folder" :size="18"/>{{choosingInventory?'Select a file…':busy?'Import…':inventoryFile?'Select another file':'Select an inventory file'}}</button><p v-if="inventoryFile" class="inventory-name" :title="inventoryFile.location">{{inventoryFile.name}}</p></div>
      <p>{{form.kind==='manual'?'Use user@host to override the user. Cyberbot reads keys and jump hosts from your SSH configuration.':'Static INI, YAML, or JSON. We only read the data from the selected file.'}}</p>
      <p v-if="preview" class="notice">Use the desktop app to connect to servers.</p><p v-if="error" class="text-error" role="alert">{{error}}</p>
      <footer><button type="button" :disabled="busy" @click="sourceForm=false">Cancel</button><button v-if="form.kind==='manual'||inventoryFile" class="primary" :disabled="busy||preview" type="submit">{{busy?'Connect…':form.kind==='ansible'?'Retry import':'Add server'}}</button></footer>
    </form>
  </dialog>
  </template>
</div>
</template>

<style scoped>
.connectivity-notice{margin:0 0 12px;padding:9px 12px;border-radius:7px;background:var(--warning-bg);color:var(--warning);font-size:13px}
.console-link { padding: 6px; background: transparent; border-color: transparent; color: var(--muted); }
.console-link[aria-current=page] { background: var(--accent-bg); color: var(--accent); }
.detail-panel:focus{outline:none}

.notification-selection{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:12px}.notification-selection button{font-size:12px;padding:5px 8px}

.app{--canvas:#f7f8f5;--sidebar:#eef0ec;--surface:#ffffff;--subtle:#f0f2ee;--hover:#e9ede7;--line:#d9ded5;--line-strong:#b2bcb0;--text:#242a25;--muted:#626c61;--accent:#355c40;--accent-bg:#e2ecdf;--on-accent:#ffffff;--success:#287347;--warning:#8d5b13;--warning-bg:#faf0dc;--danger:#b03d37;--danger-bg:#fae8e5;--overlay:#151b235e;--shadow:0 16px 60px #12201424;color-scheme:light}
.app[data-theme=dark]{--canvas:#191c1b;--sidebar:#151817;--surface:#202422;--subtle:#262b28;--hover:#2d332f;--line:#353c36;--line-strong:#59665c;--text:#e8ede6;--muted:#a0aca1;--accent:#b5d2aa;--accent-bg:#2e3f30;--on-accent:#1b2d20;--success:#97c9a2;--warning:#e2bc77;--warning-bg:#3b3324;--danger:#eda39a;--danger-bg:#402b28;--overlay:#080d107d;--shadow:0 16px 60px #0005;color-scheme:dark}

.activity-head .page-title{flex-wrap:wrap;row-gap:5px}
@media(max-width:760px){.main .page-head.activity-head{height:auto;min-height:80px;padding-block:10px;box-sizing:border-box}.activity-head .resource-summary{flex-basis:100%}}
</style>
<style scoped>
.detail-panel:focus{outline:none}

.notification-selection{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:12px}.notification-selection button{font-size:12px;padding:5px 8px}

.app.approval-window{display:block}.app{position:fixed;inset:0;display:flex;background:var(--canvas);color:var(--text);font:13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;-webkit-font-smoothing:antialiased;caret-color:var(--accent)}
*{box-sizing:border-box}::selection{background:var(--accent-bg);color:var(--text)}
button,input,select,textarea{font:inherit;color:inherit}button{cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:8px 12px;border:1px solid var(--line);border-radius:7px;background:var(--surface);min-height:36px;transition:background .15s,border-color .15s}button:hover{background:var(--hover);border-color:var(--line-strong)}button:disabled{opacity:.45;cursor:default}button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}input,textarea,select{background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:8px 10px;min-height:36px;max-width:100%}input::placeholder,textarea::placeholder{color:var(--muted)}input[type=checkbox]{accent-color:var(--accent);min-height:initial}button.primary{background:var(--accent);color:var(--on-accent);border-color:transparent;font-weight:600}.primary:hover{filter:brightness(.95)}.quiet{border-color:transparent;background:none}.icon-button{padding:7px;background:none;border-color:transparent}
.sidebar{width:188px;flex-shrink:0;background:var(--sidebar);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:0 12px 18px}.brand{height:80px;display:flex;align-items:center;gap:10px;padding:0 12px;color:var(--accent)}.brand-logo{display:block;flex-shrink:0;width:21px;height:21px;background:currentColor;-webkit-mask:url("./assets/radar.svg") center/contain no-repeat;mask:url("./assets/radar.svg") center/contain no-repeat}.brand strong{font-size:19px;letter-spacing:-.5px;font-weight:650;color:var(--text)}nav{display:flex;flex-direction:column;gap:4px}nav button{justify-content:flex-start;border-color:transparent;background:none;color:var(--muted);padding:10px;min-height:42px;white-space:nowrap}nav button.active{color:var(--text);background:var(--hover);font-weight:600}nav button.active>svg{color:var(--accent)}.nav-count{margin-left:auto;font-size:11px;background:var(--danger-bg);color:var(--danger);padding:0 6px;border-radius:4px;line-height:20px}.sidebar-bottom{margin-top:auto;display:grid;gap:9px}.theme-shortcut{border:0;justify-content:flex-start;padding:8px 10px;background:none;font-size:12px;color:var(--muted)}
.main{flex:1;min-width:0;display:flex;flex-direction:column;padding:0 28px}.page-head{height:80px;flex-shrink:0;display:flex;align-items:center;justify-content:space-between;gap:12px}.page-title{position:relative;min-width:0}.page-title,.head-actions{display:flex;align-items:center;gap:12px}h1{font-size:23px;font-weight:600;letter-spacing:-.5px;margin:0}.preview{font-size:11px;line-height:20px;padding:0 7px;border:1px solid var(--line);border-radius:4px;color:var(--muted)}.fleet-toolbar{display:flex;align-items:center;gap:10px;padding:5px 0 16px}.view-switch{display:flex;gap:2px}.view-switch button{background:none;border-color:transparent;padding:8px}.view-switch button.active{background:var(--hover);color:var(--accent)}.fleet-filters{display:flex;align-items:center;gap:4px;padding:0 0 16px;flex-wrap:wrap}.fleet-filters button{min-height:32px;padding:5px 10px;border:0;background:none;font-size:12px;color:var(--muted)}.fleet-filters button.chosen{background:var(--hover);color:var(--text)}.fleet-filters button span{font-variant-numeric:tabular-nums;margin-left:2px}.result-count{margin-left:auto;color:var(--muted);font-size:12px}.dot{display:inline-block;width:6px;height:6px;border-radius:50%;flex-shrink:0}.attention-dot{background:var(--warning)}.attention-dot.critical{background:var(--danger)}.fleet{flex:1;min-height:0}
.manage-servers{font-size:12px;min-height:32px;padding:5px 8px;color:var(--muted)}
.source-description h3{overflow-wrap:anywhere}
.incident-actions{display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px}
.main.fleet-page .page-head{height:60px}
.scroll-content{flex:1;min-height:0;overflow:auto;padding-bottom:30px;scrollbar-color:var(--line-strong) transparent}.empty{flex:1;min-height:260px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:32px;color:var(--muted)}.empty h2{font-size:20px;color:var(--text);font-weight:550;margin:18px 0 0}.empty p{line-height:1.7;max-width:60ch;margin-bottom:22px}.loading{height:200px;display:grid;place-items:center;color:var(--muted)}.page-intro{color:var(--muted);margin:0 0 24px}.source-row{display:flex;align-items:center;gap:18px;border-bottom:1px solid var(--line);padding:24px 0}.source-row>svg{color:var(--muted)}.source-description{flex:1;min-width:0}.source-description h3{font-size:14px;margin:0;font-weight:600}.source-description h3 span{font-size:11px;color:var(--muted);font-weight:400;margin-left:8px}.source-description p{color:var(--muted);margin:6px 0;font-size:12px}.source-description code{font-size:12px;overflow-wrap:anywhere;color:var(--muted)}.row-actions{display:flex;gap:8px;flex-wrap:wrap}.danger,.text-error{color:var(--danger)}.section-toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;padding-bottom:14px;color:var(--muted)}
.settings{max-width:920px;width:100%}.settings-section{padding:4px 0 28px;margin-bottom:24px;border-bottom:1px solid var(--line)}.settings-section h2{font-size:16px;font-weight:600;margin:0 0 8px}.settings-section p{color:var(--muted);max-width:75ch;margin:8px 0 16px;line-height:1.6}.theme-options{display:flex;gap:8px;margin:20px 0 8px}.theme-options button.selected{background:var(--accent-bg);border-color:var(--accent);color:var(--accent)}.fields{display:flex;gap:16px;margin:20px 0;flex-wrap:wrap}.fields label{flex:1;min-width:140px}label{display:flex;flex-direction:column;gap:8px;font-size:12px;color:var(--muted)}.checkbox{flex-direction:row;align-items:center;gap:8px;margin-block:16px}.schedule{max-width:560px;align-items:end}.schedule p{font-size:12px;flex-basis:100%;margin:0}.storage{display:flex;flex-wrap:wrap;gap:36px;margin:22px 0}.storage dt{color:var(--muted);font-size:12px}.storage dd{margin:5px 0;font-size:14px;font-variant-numeric:tabular-nums}.help{margin:20px 0;color:var(--muted);font-size:12px}.help summary{cursor:pointer;padding:5px 0}.help p{line-height:1.7;max-width:75ch}.error{display:flex;justify-content:space-between;align-items:center;gap:12px;background:var(--danger-bg);color:var(--danger);padding:12px 16px;margin-bottom:16px;border-radius:7px;overflow-wrap:anywhere}.error button{background:none;color:inherit;border:0;flex-shrink:0}
.management-dialog{width:min(860px,calc(100vw - 32px));max-height:calc(100dvh - 48px);padding:24px;border-radius:12px;box-shadow:var(--shadow);overflow:auto}.management-head{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}.management-head h2{font-size:20px;font-weight:600;letter-spacing:-.3px;margin:0}.management-head .row-actions{flex-shrink:0}.management-dialog .page-intro{margin:0;color:var(--muted)}.management-dialog .source-row{padding:20px 0}
dialog{color:var(--text);background:var(--canvas);border:0;padding:0;box-sizing:border-box}dialog::backdrop{background:var(--overlay)}.detail-dialog{margin:0 0 0 auto;width:min(900px,100vw);max-width:100vw;max-height:100dvh;height:100dvh;box-shadow:var(--shadow)}.detail-panel,.standalone-detail{height:100%;width:100%}.standalone{display:block}.source-dialog{width:min(540px,calc(100vw - 32px));max-height:calc(100dvh - 48px);border-radius:14px;box-shadow:var(--shadow)}.source-form{padding:28px}.source-form header{display:flex;align-items:center;justify-content:space-between;gap:12px}.source-form h2{font-size:21px;font-weight:600;margin:0}.source-form label>input,.source-form textarea{width:100%}.source-form textarea{font:13px/1.7 ui-monospace,monospace;resize:vertical}.source-form p{font-size:12px;color:var(--muted);line-height:1.6}.source-form p.text-error{color:var(--danger)}.inventory-picker{display:flex;flex-direction:column;align-items:center;gap:12px;padding:20px 0}.source-form .inventory-name{margin:0;font-size:13px;color:var(--text);overflow-wrap:anywhere;max-width:100%}.source-form footer{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}.tabs{display:flex;border-bottom:1px solid var(--line);gap:20px;margin:22px 0}.tabs button{border:0;border-bottom:2px solid transparent;border-radius:0;background:none;padding:10px 0;color:var(--muted)}.tabs button.active{color:var(--text);border-bottom-color:var(--accent)}
.fleet-controls{display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px;margin-bottom:8px}.fleet-controls .fleet-filters{flex:1 1 340px;padding:0}.fleet-controls .fleet-toolbar{padding:0;margin-left:auto}
.fleet-sort{display:flex;align-items:center;flex-wrap:wrap;flex-shrink:0;gap:4px;margin-bottom:8px}
.sort-label{padding-inline:4px;font-size:12px;color:var(--muted)}
.fleet-sort button {
  min-height: 28px;
  padding: 3px 6px;
  gap: 4px;
  border: 0;
  background: none;
  font-size: 12px;
  color: var(--muted);
}
.fleet-sort button:hover {
  color: var(--text);
  text-decoration: underline;
  text-underline-offset: 3px;
}
.fleet-sort button[aria-pressed=true] {
  color: var(--text);
  font-weight: 600;
}
.monitor-control{display:flex;align-items:center;justify-content:space-between;gap:4px;padding:0 8px;min-width:0}.monitor-caption{font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}.monitor-short{display:none}.monitor-toggle{flex-shrink:0;width:28px;min-height:28px;padding:0;border:0;background:none;color:var(--muted);border-radius:5px}.monitor-control.paused .monitor-caption{color:var(--warning)}.monitor-control.paused .monitor-toggle{color:var(--accent)}
.title-search{display:flex;align-items:center;gap:6px;min-width:0}.search-toggle{width:28px;min-height:28px;padding:0;border:0;background:none;color:var(--muted);border-radius:5px}.search-toggle:hover,.search-toggle[aria-expanded=true]{background:var(--hover);color:var(--text)}.title-search input{width:180px;height:28px;min-height:28px;padding:4px 8px;font-size:12px}
@media(max-width:1100px){.main.fleet-page .page-head.searching{height:96px;padding-bottom:36px;box-sizing:border-box}.title-search input{position:absolute;top:calc(100% + 8px);left:0;width:min(220px,calc(100vw - 112px));z-index:2;box-shadow:var(--shadow)}}
@media(max-width:900px){.sidebar{width:64px;padding-inline:8px}.brand{justify-content:center;padding:0}.brand strong,.nav-text,.theme-shortcut span{display:none}nav button{justify-content:center;padding:10px}.nav-count{position:absolute;font-size:10px;line-height:15px;margin:0 0 27px 28px}.theme-shortcut{justify-content:center}.monitor-control{flex-direction:column;gap:2px;padding:0}.monitor-full{display:none}.monitor-short{display:inline}.monitor-caption{font-size:10px}.main{padding-inline:22px}.head-actions{gap:4px}}
@media(max-width:560px){.main{padding-inline:14px}.page-head{height:70px}.page-title{gap:7px}h1{font-size:20px}.fleet-toolbar{flex-wrap:wrap}.view-switch{margin-left:auto}.fleet-filters{gap:0}.fleet-filters button{font-size:11px;padding-inline:7px}.result-count{width:100%;margin-top:8px}.preview{font-size:10px;padding-inline:4px}.head-actions .primary{font-size:12px;padding-inline:8px}.source-row{flex-wrap:wrap}.source-row>svg{display:none}.row-actions{flex-basis:100%}.theme-options{flex-wrap:wrap}.theme-options button{flex:1;font-size:12px;white-space:nowrap}.section-toolbar{flex-wrap:wrap}.storage{gap:20px}.source-form{padding:20px}}
@media(max-width:700px){.main .page-head,.main.fleet-page .page-head,.main.fleet-page .page-head.searching{height:auto;min-height:96px;padding-block:10px;flex-wrap:wrap;gap:8px;box-sizing:border-box}.page-title{flex-basis:100%}.head-actions{width:100%;justify-content:space-between}.title-search input{position:static;width:clamp(100px,30vw,180px);box-shadow:none}.page-head.searching .preview{display:none}}
@media(prefers-reduced-motion:reduce){button{transition:none}}


.main .automation-head { height: auto; min-height: 0; padding-block: 20px 14px; flex-wrap: nowrap; align-items: flex-start; }
.automation-head .page-title { flex: 1 1 auto; align-items: flex-start; }
.automation-head .head-actions { width: auto; flex: none; }
.cli-check { margin-bottom: 14px; padding-top: 14px; border-top: 1px solid var(--line); }
.cli-check-row, .cli-result-title { display: flex; align-items: center; flex-wrap: wrap; gap: 8px 12px; }
.cli-check-row { justify-content: space-between; }
.cli-check-row h3 { font-size: 14px; font-weight: 600; margin: 0 0 4px; }
.cli-check-row button { min-height: 32px; font-size: 12px; }
.cli-check p, .cli-check small, .cli-check code { font-size: 12px; color: var(--muted); overflow-wrap: anywhere; }
.cli-check p { margin: 0; }
.cli-check .cli-error { margin-top: 12px; color: var(--danger); }
.cli-results { list-style: none; margin: 12px 0 0; padding: 0; }
.cli-results li { padding: 9px 0; border-top: 1px solid var(--line); }
.cli-result-title { margin-bottom: 4px; }
.cli-result-title strong { font-weight: 600; }
.cli-ready, .cli-unavailable { font-size: 12px; }
.cli-ready { color: var(--success); }
.cli-unavailable { color: var(--warning); }
</style>
