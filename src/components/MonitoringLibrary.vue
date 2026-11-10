<script setup lang="ts">
import ServerLink from './ServerLink.vue';
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue';
import { call } from '../api';
import type { MonitoringDefinition, MonitoringLibraryEntry, MonitoringTarget, Server } from '../types';
import { monitoringInterval } from '../monitoring';
import CheckPanel from './CheckPanel.vue';
import LibraryServerPicker from './LibraryServerPicker.vue';
import MonitoringLibraryDetails from './MonitoringLibraryDetails.vue';
import RefreshButton from './RefreshButton.vue';
import UiIcon from './UiIcon.vue';
import UiInput from './UiInput.vue';
import VulnerabilityCatalog from './VulnerabilityCatalog.vue';

const props = defineProps<{ servers: Server[]; now: number; initial?: MonitoringTarget }>();
const emit = defineEmits<{ updated: [] }>();
const tabs = {
  builtin: 'Built-in checks',
  custom: 'My checks',
  jobs: 'Overrides',
  vulnerabilities: 'Vulnerabilities',
};
const tab = ref<keyof typeof tabs>('builtin');
const catalog = ref<MonitoringDefinition[]>([]);
const entries = ref<Record<string, MonitoringLibraryEntry>>({});
const server = ref('');
const selected = ref('');
const initialInstance = ref<string>();
const onlyExceptions = ref(true);
const busy = ref(false);
const loading = ref(false);
const catalogError = ref('');
const entriesError = ref('');
const query = ref('');
const filter = ref<HTMLInputElement>();
const showAll = ref<HTMLButtonElement>();
let generation = 0;

const filtering = computed(() => tab.value === 'builtin' && !!server.value && onlyExceptions.value);
const matches = computed(() => catalog.value.filter(definition =>
  (tab.value === 'jobs' ? definition.runner === 'local' : definition.configurable) &&
  `${definition.name} ${definition.category} ${definition.purpose}`.toLowerCase().includes(query.value.trim().toLowerCase()),
));
const connectionExceptions = (entry?: MonitoringLibraryEntry) => Object.keys(entry?.instanceOverrides ?? {});
const hasException = (entry?: MonitoringLibraryEntry) => !!(entry?.serverOverride || connectionExceptions(entry).length);
const visible = computed(() => matches.value.filter(definition => !filtering.value || hasException(entries.value[definition.id])));
const noExceptions = computed(() => filtering.value && !Object.values(entries.value).some(hasException));

function schedule(definition: MonitoringDefinition) {
  if (!definition.configurable) return definition.schedule;
  const entry = entries.value[definition.id];
  if (!entry) return '—';
  const exceptions = connectionExceptions(entry);
  if (!entry.serverOverride && exceptions.length > 1) return 'Connected';
  const values = !entry.serverOverride && exceptions.length === 1 ? entry.instanceOverrides[exceptions[0]] : entry.values;
  if (!values.enabled) return 'Turned off';
  if (definition.diagnostics && !values.diagnosticEnabled) return 'Every 6 h';
  return definition.intervalEditable ? 'Every ' + monitoringInterval(values.intervalSeconds) : definition.schedule;
}

async function loadEntries(keep = false) {
  const current = ++generation;
  if (!keep) entries.value = {};
  loading.value = true;
  entriesError.value = '';
  try {
    const result = await call<Record<string, MonitoringLibraryEntry>>('monitoring_library', { serverId: server.value || null });
    if (current !== generation) return;
    entries.value = result;
    if (keep && filtering.value && selected.value && !hasException(result[selected.value])) {
      selected.value = '';
      await nextTick();
      (showAll.value ?? filter.value)?.focus();
    }
  } catch (error) {
    if (current === generation) entriesError.value = String(error).replace(/^Error: /, '');
  } finally {
    if (current === generation) loading.value = false;
  }
}

async function loadCatalog() {
  catalogError.value = '';
  try {
    catalog.value = await call<MonitoringDefinition[]>('monitoring_catalog');
    if (props.initial && tab.value !== 'vulnerabilities') openTarget(props.initial);
  } catch (error) {
    catalogError.value = String(error).replace(/^Error: /, '');
  }
}

function selectTab(value: keyof typeof tabs) {
  tab.value = value;
  query.value = '';
  selected.value = '';
  initialInstance.value = undefined;
}
function toggleRow(id: string) {
  if (busy.value) return;
  selected.value = selected.value === id ? '' : id;
  initialInstance.value = undefined;
}
function changeServer() {
  onlyExceptions.value = true;
  selected.value = '';
  initialInstance.value = undefined;
}
function openTarget(target: MonitoringTarget) {
  const definition = catalog.value.find(item => item.id === target.definitionId);
  if (!definition) return;
  selectTab(definition.runner === 'custom' ? 'custom' : definition.runner === 'local' ? 'jobs' : 'builtin');
  server.value = target.serverId ?? '';
  onlyExceptions.value = false;
  selected.value = definition.id;
  initialInstance.value = target.instanceId ?? undefined;
}
function updated() {
  emit('updated');
  void loadEntries(true);
}

watch(server, () => void loadEntries());
watch(() => props.initial, target => { if (target) openTarget(target); });
watch(() => props.servers, (current, previous) => {
  if (server.value && previous.some(item => item.id === server.value) && !current.some(item => item.id === server.value)) {
    server.value = '';
    changeServer();
  }
});
void loadCatalog();
void loadEntries();
onBeforeUnmount(() => { generation++; });
</script>

<template>
  <div class="library">
    <div class="tabs" role="group" aria-label="Library sections">
      <button v-for="(label, id) in tabs" :key="id" type="button" :aria-pressed="tab === id" :disabled="busy" @click="selectTab(id)">{{ label }}</button>
    </div>
    <VulnerabilityCatalog v-if="tab === 'vulnerabilities'" :servers="servers"/>
    <p v-else-if="catalogError" class="problem" role="alert">{{ catalogError }} <RefreshButton @click="loadCatalog">Load catalog</RefreshButton></p>
    <template v-else-if="catalog.length">
      <div v-if="tab !== 'jobs'" class="toolbar">
        <LibraryServerPicker v-model="server" :servers="servers" :disabled="busy" @change="changeServer"/>
        <label v-if="tab === 'builtin' && server" class="filter"><input ref="filter" v-model="onlyExceptions" type="checkbox" :disabled="busy"> Overrides only</label>
        <UiInput v-if="tab === 'builtin'" v-model="query" type="search" placeholder="Find a check" aria-label="Search checks" :disabled="busy"/>
      </div>
      <template v-if="tab === 'custom'">
        <p class="hint">Custom checks evaluate data Cyberbot has already collected. Each check has its own schedule.</p>
        <CheckPanel v-if="server" :key="server" :server-id="server" :now="now" @updated="emit('updated')"/>
        <p v-else class="hint">Select a server to open its checks and version editor.</p>
      </template>
      <template v-else>
        <p v-if="tab === 'builtin' && entriesError" class="problem" role="alert">{{ entriesError }} <RefreshButton @click="loadEntries()">Refresh settings</RefreshButton></p>
        <template v-else-if="tab === 'jobs' || !loading || Object.keys(entries).length">
          <p v-if="tab === 'jobs'" class="hint">Tasks that Cyberbot runs on this computer.</p>
          <template v-else-if="noExceptions">
            <p class="hint">This server uses global settings for all checks.</p>
            <button ref="showAll" class="link" type="button" @click="onlyExceptions = false; nextTick(() => filter?.focus())">Show all server checks</button>
          </template>
          <p v-else class="hint"><template v-if="server">{{ filtering ? 'Overrides for' : 'Settings for' }} <ServerLink :id="server"/>.</template><template v-else>Checks inherit global settings unless this server overrides them.</template></p>
          <table v-if="visible.length" class="checks" :aria-label="tabs[tab]" :aria-busy="tab === 'builtin' && loading">
            <thead><tr><th scope="col">Check</th><th scope="col">Schedule</th></tr></thead>
            <tbody>
              <template v-for="definition in visible" :key="definition.id">
                <tr class="row" :class="{ open: selected === definition.id }" @click="toggleRow(definition.id)">
                  <th scope="row">
                    <button type="button" class="row-button" :disabled="busy" :aria-expanded="selected === definition.id" :aria-controls="selected === definition.id ? `library-detail-${definition.id}` : undefined">
                      <UiIcon name="chevron" :size="13" :class="{ down: selected === definition.id }"/>{{ definition.name }}
                    </button>
                  </th>
                  <td>
                    {{ schedule(definition) }}
                    <small v-if="server && hasException(entries[definition.id]) && !filtering">Server override</small>
                    <small v-else-if="filtering && !entries[definition.id]?.serverOverride">Connection override</small>
                  </td>
                </tr>
                <tr v-if="selected === definition.id" class="expanded" :id="`library-detail-${definition.id}`">
                  <td colspan="2">
                    <MonitoringLibraryDetails
                      :key="`${server}/${definition.id}/${initialInstance ?? ''}`"
                      :definition="definition" :server="tab === 'jobs' ? '' : server" :now="now"
                      :initial-instance="initialInstance" :instance-overrides="connectionExceptions(entries[definition.id])"
                      :has-server-override="entries[definition.id]?.serverOverride"
                      @busy="busy = $event" @updated="updated" @refreshed="loadEntries(true)"
                    />
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
          <p v-else-if="!noExceptions" class="hint">No checks found.</p>
        </template>
        <p v-else class="hint" role="status">Loading settings…</p>
      </template>
    </template>
    <p v-else class="hint" role="status">Loading the catalog…</p>
  </div>
</template>

<style scoped>
.library{padding-bottom:28px;font-size:13px;line-height:1.5}
.tabs,.toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:8px 16px}
.tabs{border-bottom:1px solid var(--line);margin-bottom:16px}
.tabs button{padding:7px 0;border:0;border-bottom:2px solid transparent;border-radius:0;background:none;color:var(--muted)}
.tabs button[aria-pressed=true]{border-color:var(--accent);color:var(--text);font-weight:600}
.tabs button:hover:not(:disabled){color:var(--text)}
.toolbar{margin-bottom:8px}
.toolbar .ui-input{margin-left:auto}
.filter{display:inline-flex;align-items:center;gap:6px}
.filter input{margin:0;accent-color:var(--accent)}
.hint{margin:6px 0 10px;color:var(--muted);font-size:12px}
.problem{color:var(--danger);background:var(--danger-bg);padding:8px 12px;border-radius:6px}
.link{padding:0;border:0;background:none;color:var(--accent);text-decoration:underline;text-underline-offset:3px}
.checks{width:100%;table-layout:fixed;border-collapse:collapse;text-align:left}
.checks :is(th,td){border-bottom:1px solid var(--line)}
.checks thead th{border-top:1px solid var(--line);padding:6px 10px;color:var(--muted);font-size:12px;font-weight:500}
.checks thead th:nth-child(2){width:43%}
.row{cursor:pointer}
.row:hover,.row.open{background:var(--hover)}
.row th{padding:0}
.row td{padding:8px 10px;font-variant-numeric:tabular-nums}
.row td small{margin-left:6px;color:var(--muted)}
.row-button{width:100%;display:flex;align-items:center;justify-content:flex-start;gap:8px;padding:8px 10px;border:0;border-radius:0;background:none;color:var(--text);text-align:left;font-weight:600;overflow-wrap:anywhere}
.row-button:hover:not(:disabled){background:none}
.row-button svg{color:var(--muted)}
.row-button svg.down{transform:rotate(90deg)}
.row-button:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.expanded td{padding:0;background:var(--surface)}
@media(max-width:700px){.toolbar .ui-input{margin-left:0}.row td small{display:block;margin-left:0}}
</style>
