<script setup lang="ts">
import ActivityServerLink from './ActivityServerLink.vue';
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { call, preview } from '../api';
import { monitoringInterval } from '../monitoring';
import type { ActivityEvent, ActivityPage, MonitoringDefinition, MonitoringOverrides, MonitoringPolicy, MonitoringScalarField, MonitoringScope, MonitoringThresholdField, MonitoringThresholdRule, MonitoringValues, ServiceInstance } from '../types';
import { serviceCatalog } from '../services';
import { servicePanel } from '../servicePanels';
import RefreshButton from './RefreshButton.vue';
import RelativeDate from './RelativeDate.vue';
import UiIcon from './UiIcon.vue';
import UiInput from './UiInput.vue';
import UiSelect from './UiSelect.vue';

const props = defineProps<{
  definition: MonitoringDefinition; server: string; now: number;
  initialInstance?: string; instanceOverrides: string[]; hasServerOverride?: boolean;
}>();
const emit = defineEmits<{ busy: [value: boolean]; updated: []; refreshed: [] }>();
const service = props.definition.runner === 'service' && serviceCatalog[props.definition.id]?.scopeInstances !== false;
const instance = ref(props.initialInstance ?? (!props.hasServerOverride && props.instanceOverrides.length === 1 ? props.instanceOverrides[0] : ''));
const instances = ref<ServiceInstance[]>([]);
const policy = ref<MonitoringPolicy>();
const loading = ref(false);
const saving = ref(false);
const error = ref('');
const instanceError = ref('');
const thresholdDrafts = ref<Record<string, Record<string, string | number>>>({});
const thresholdErrors = ref<Record<string, string>>({});
const sources = ref<{ name: string; text: string }[]>();
const sourceError = ref('');
const loadingSources = ref(false);
const recent = ref<ActivityEvent[]>();
const historyError = ref('');
const historyOpen = ref(false);
const loadingHistory = ref(false);
const endpointOpen = ref(false);
let generation = 0;
let historyGeneration = 0;
let disposed = false;

const scope = computed<MonitoringScope>(() => ({
  definitionId: props.definition.id,
  serverId: props.server || null,
  instanceId: instance.value || null,
}));
const scopeOrigin: Record<string, string> = {
  factory: 'Factory default', global: 'From global settings', server: 'From server settings', instance: 'Connection override',
};
const resetLabel = computed(() => instance.value ? 'Use server settings' : props.server ? 'Use global settings' : 'Use factory defaults');
const triggers: Record<string, string> = { schedule: 'On schedule', manual: 'Manual', ai: 'AI request' };
const phases: Record<string, string> = { completed: 'Finished', failed: 'Failed', cancelled: 'Cancelled', interrupted: 'Interrupted', info: 'Event' };
const message = (value: unknown) => String(value).replace(/^Error: /, '');
const hasOverride = (field: MonitoringScalarField) => policy.value?.overrides[field] != null;

async function loadPolicy() {
  if (!props.definition.configurable) return;
  const current = ++generation;
  thresholdDrafts.value = {};
  thresholdErrors.value = {};
  policy.value = undefined;
  error.value = '';
  loading.value = true;
  try {
    const result = await call<MonitoringPolicy>('monitoring_policy', { scope: scope.value });
    if (current === generation) policy.value = result;
  } catch (failure) {
    if (current === generation) error.value = message(failure);
  } finally {
    if (current === generation) loading.value = false;
  }
}
async function refreshPolicy() {
  await loadPolicy();
  emit('refreshed');
}

async function loadInstances() {
  if (!props.server || !service) return;
  instanceError.value = '';
  try {
    const result = await call<ServiceInstance[]>('list_service_instances', { id: props.server });
    if (disposed) return;
    instances.value = result.filter(item => item.kind === props.definition.id);
    if (instance.value && !instances.value.some(item => item.id === instance.value)) instance.value = '';
  } catch (failure) {
    if (!disposed) instanceError.value = message(failure);
  }
}

async function write(overrides: MonitoringOverrides) {
  if (preview || !policy.value || saving.value) return false;
  const current = generation;
  saving.value = true;
  emit('busy', true);
  error.value = '';
  try {
    const result = await call<MonitoringPolicy>('configure_monitoring', {
      scope: scope.value, overrides, expectedRevision: policy.value.revision,
    });
    if (current !== generation) return false;
    policy.value = result;
    emit('updated');
    return true;
  } catch (failure) {
    if (current === generation) error.value = message(failure);
    return false;
  } finally {
    saving.value = false;
    if (!disposed) emit('busy', false);
  }
}
async function change<K extends MonitoringScalarField>(field: K, value: MonitoringValues[K] | null) {
  return write({ ...policy.value?.overrides, [field]: value });
}
async function toggle(field: 'enabled' | 'diagnosticEnabled', event: Event) {
  const input = event.target as HTMLInputElement;
  if (!await change(field, input.checked)) input.checked = policy.value?.values[field] ?? false;
}
async function setReplica(event: Event) {
  const select = event.target as HTMLSelectElement;
  if (!await change('expectReplica', select.value === '' ? null : select.value === 'true')) {
    select.value = policy.value?.overrides.expectReplica?.toString() ?? '';
  }
}
async function setPeers(event: Event) {
  const input = event.target as HTMLInputElement;
  const count = input.valueAsNumber;
  if (!Number.isSafeInteger(count) || count < 0 || count > 64) {
    error.value = 'Enter a whole number of replicas from 0 to 64.';
  } else if (count === policy.value?.values.expectedPeers || await change('expectedPeers', count)) {
    return;
  }
  input.value = String(policy.value?.values.expectedPeers ?? '');
}

function currentThreshold(rule: string, field: MonitoringThresholdField) {
  return policy.value?.values.thresholds?.[rule]?.[field.key] ?? field.default;
}
function thresholdOrigin(rule: string) {
  const origin = policy.value?.thresholdOrigins?.[rule] ?? 'factory';
  return origin === 'server' && policy.value?.overrides.thresholds?.[rule]
    ? 'Server override' : scopeOrigin[origin];
}
function editThreshold(rule: string, field: string, value: string | number) {
  (thresholdDrafts.value[rule] ??= {})[field] = value;
  delete thresholdErrors.value[rule];
}
async function saveThreshold(rule: MonitoringThresholdRule) {
  const thresholds = { ...policy.value?.overrides.thresholds };
  const values: Record<string, number> = {};
  for (const field of rule.fields) {
    const draft = thresholdDrafts.value[rule.key]?.[field.key];
    const value = draft === '' ? NaN : Number(draft ?? currentThreshold(rule.key, field));
    if (!Number.isFinite(value) || value < field.min || value > field.max || (field.integer && !Number.isInteger(value))) {
      thresholdErrors.value[rule.key] = `Enter ${field.integer ? 'a whole number' : 'a number'} from ${field.min} to ${field.max} for ${field.label}.`;
      return;
    }
    values[field.key] = value;
  }
  if ('warning' in values && 'critical' in values && values.warning >= values.critical) {
    thresholdErrors.value[rule.key] = 'Critical must be higher than Warning.';
    return;
  }
  thresholds[rule.key] = values;
  if (await write({ ...policy.value?.overrides, thresholds })) delete thresholdDrafts.value[rule.key];
}
async function resetThreshold(rule: string) {
  const thresholds = { ...policy.value?.overrides.thresholds };
  delete thresholds[rule];
  if (await write({ ...policy.value?.overrides, thresholds })) {
    delete thresholdDrafts.value[rule];
    delete thresholdErrors.value[rule];
  }
}

async function showSources(event: Event) {
  if (!(event.target as HTMLDetailsElement).open || sources.value || loadingSources.value) return;
  loadingSources.value = true;
  sourceError.value = '';
  try {
    sources.value = await call<{ name: string; text: string }[]>('monitoring_sources', { definitionId: props.definition.id });
  } catch (failure) {
    sourceError.value = message(failure);
  } finally {
    loadingSources.value = false;
  }
}
async function loadHistory() {
  const current = ++historyGeneration;
  loadingHistory.value = true;
  historyError.value = '';
  try {
    const result = await call<ActivityPage>('activity_log', {
      query: { definitionId: props.definition.id, search: props.server || null },
    });
    if (current !== historyGeneration) return;
    recent.value = result.events.filter(item => item.phase !== 'started' && (!instance.value || item.monitoring?.instanceId === instance.value)).slice(0, 8);
  } catch (failure) {
    if (current === historyGeneration) historyError.value = message(failure);
  } finally {
    if (current === historyGeneration) loadingHistory.value = false;
  }
}
function showHistory(event: Event) {
  historyOpen.value = (event.target as HTMLDetailsElement).open;
  if (historyOpen.value && !recent.value && !loadingHistory.value) void loadHistory();
}
function endpointUpdated() {
  void loadPolicy();
  void loadInstances();
  emit('updated');
}

watch(instance, () => {
  void loadPolicy();
  endpointOpen.value = false;
  recent.value = undefined;
  if (historyOpen.value) void loadHistory();
});
void loadInstances();
void loadPolicy();
onBeforeUnmount(() => {
  disposed = true;
  generation++;
  historyGeneration++;
  if (saving.value) emit('busy', false);
});
</script>

<template>
  <div class="details" :aria-busy="loading || saving">
    <p class="purpose">{{ definition.purpose }}</p>
    <label v-if="server && instances.length" class="connection">
      Connection
      <UiSelect v-model="instance" compact :disabled="saving" aria-label="Service connection">
        <option value="">All connections</option>
        <option v-for="item in instances" :key="item.id" :value="item.id">{{ item.name }}{{ instanceOverrides?.includes(item.id) ? ' · settings' : '' }}</option>
      </UiSelect>
    </label>
    <p v-if="instanceError" class="problem" role="alert">{{ instanceError }} <RefreshButton @click="loadInstances">Reload connections</RefreshButton></p>
    <p v-if="error" class="problem" role="alert">{{ error }} <RefreshButton :disabled="saving" @click="refreshPolicy">Refresh settings</RefreshButton></p>
    <p v-if="loading" class="hint" role="status">Loading settings…</p>
    <template v-else-if="policy">
      <p v-if="['metrics', 'logs', 'service', 'packages', 'apt'].includes(definition.runner)" class="hint">
        Server polling interval · {{ monitoringInterval(policy.values.intervalSeconds) }}
      </p>
      <details v-if="definition.thresholds?.length">
        <summary>Alert thresholds</summary>
        <form v-for="rule in definition.thresholds" :key="rule.key" class="threshold" novalidate @submit.prevent="saveThreshold(rule)">
          <fieldset>
            <legend>{{ rule.label }}</legend>
            <div class="threshold-fields">
              <label v-for="field in rule.fields" :key="field.key">
                {{ field.label }}
                <UiInput compact type="number" :unit="field.unit" :min="field.min" :max="field.max"
                  :step="field.integer ? 1 : 'any'" :aria-label="`${rule.label} ${field.label}`"
                  :model-value="thresholdDrafts[rule.key]?.[field.key] ?? currentThreshold(rule.key, field)"
                  :disabled="saving || preview" @update:model-value="editThreshold(rule.key, field.key, $event)"
                />
              </label>
            </div>
            <div class="threshold-actions">
              <small>{{ thresholdOrigin(rule.key) }}</small>
              <button class="link" type="submit" :disabled="!thresholdDrafts[rule.key] || saving || preview">Save</button>
              <button v-if="policy.overrides.thresholds?.[rule.key]" class="link" type="button" :disabled="saving || preview"
                @click="resetThreshold(rule.key)">{{ resetLabel }}</button>
            </div>
            <p v-if="thresholdErrors[rule.key]" class="problem" role="alert">{{ thresholdErrors[rule.key] }}</p>
          </fieldset>
        </form>
      </details>
      <div class="toggle">
        <label><input type="checkbox" :checked="policy.values.enabled" :disabled="saving || preview" @change="toggle('enabled', $event)"> Enable check</label>
        <button v-if="hasOverride('enabled')" type="button" class="link" :disabled="saving || preview" @click="change('enabled', null)">{{ resetLabel }}</button>
      </div>
      <div v-if="definition.diagnostics" class="toggle">
        <label><input type="checkbox" :checked="policy.values.diagnosticEnabled" :disabled="saving || preview" @change="toggle('diagnosticEnabled', $event)"> Collect metrics</label>
        <button v-if="hasOverride('diagnosticEnabled')" type="button" class="link" :disabled="saving || preview" @click="change('diagnosticEnabled', null)">{{ resetLabel }}</button>
      </div>
      <p v-if="!policy.values.enabled" class="hint">Check disabled. Existing incidents stay open.</p>
      <p v-else-if="definition.diagnostics && !policy.values.diagnosticEnabled" class="hint">Each server poll checks whether the service is present.</p>
      <details v-if="definition.replication">
        <summary>Replication</summary>
        <div class="toggle">
          <label>Expected replicas or members <UiInput compact type="number" :value="policy.values.expectedPeers" min="0" max="64" step="1" :disabled="saving || preview" @change="setPeers"/></label>
          <button v-if="hasOverride('expectedPeers')" type="button" class="link" :disabled="saving || preview" @click="change('expectedPeers', null)">{{ resetLabel }}</button>
        </div>
        <label class="connection">Replica connection to primary
          <UiSelect compact :value="policy.overrides.expectReplica?.toString() ?? ''" :disabled="saving || preview" @change="setReplica">
            <option value="">{{ resetLabel }} · {{ (policy.inherited?.expectReplica ?? policy.values.expectReplica) ? 'expected' : 'not expected' }}</option>
            <option value="true">Expected</option><option value="false">Not expected</option>
          </UiSelect>
        </label>
      </details>
    </template>
    <details>
      <summary>Data and permissions</summary>
      <dl class="contract">
        <div><dt>Runs on</dt><dd>{{ definition.place }}</dd></div>
        <div><dt>Reads</dt><dd>{{ definition.reads }}</dd></div>
        <div><dt>Commands and SQL</dt><dd>{{ definition.commands }}</dd></div>
        <div><dt>Writes</dt><dd>{{ definition.writes }}</dd></div>
        <div><dt>Permissions</dt><dd>{{ definition.rights }}</dd></div>
        <div><dt>Schedule</dt><dd>{{ definition.schedule }}</dd></div>
        <div><dt>Limits</dt><dd>{{ definition.limits }}</dd></div>
      </dl>
      <p class="hint">View the source for built-in rules and algorithms.</p>
      <details @toggle="showSources">
        <summary>Sources and version {{ definition.version.slice(0, 12) }}</summary>
        <p v-if="loadingSources" class="hint">Loading sources…</p>
        <p v-if="sourceError" class="problem" role="alert">{{ sourceError }}</p>
        <div v-for="source in sources" :key="source.name"><h4>{{ source.name }}</h4><pre tabindex="0">{{ source.text }}</pre></div>
      </details>
    </details>
    <details @toggle="showHistory">
      <summary>Recent runs</summary>
      <p v-if="historyError" class="problem" role="alert">{{ historyError }}</p>
      <p v-else-if="loadingHistory" class="hint">Loading recent runs…</p>
      <p v-else-if="!recent?.length" class="hint">This check has no recorded runs yet.</p>
      <table v-else class="history">
        <thead><tr><th>Time</th><th>Server</th><th>Trigger</th><th>Result</th></tr></thead>
        <tbody>
          <tr v-for="record in recent" :key="record.id">
            <td><RelativeDate :at="record.at" unit="milliseconds"/></td>
            <td><ActivityServerLink :event="record" empty="App"/></td>
            <td :title="record.monitoring?.version">{{ triggers[record.monitoring?.trigger ?? ''] ?? '—' }}</td>
            <td :class="{ failed: record.phase === 'failed' }">{{ phases[record.phase] ?? record.phase }}</td>
          </tr>
        </tbody>
      </table>
    </details>
    <details v-if="server && instance && service" :key="instance" @toggle="endpointOpen = ($event.target as HTMLDetailsElement).open">
      <summary>Connection settings and metric access</summary>
      <KeepAlive>
        <component v-if="endpointOpen" :is="servicePanel(definition.id)" :server-id="server" :kind="definition.id" :instance-id="instance" :display-name="instances.find(item => item.id === instance)?.name" :now="now" @updated="endpointUpdated"/>
      </KeepAlive>
    </details>
  </div>
</template>

<style scoped>
.details{padding:10px 12px 12px 31px}
.purpose,.hint{margin:0 0 8px;color:var(--muted)}
.hint{font-size:12px}
.toggle,.connection,.toggle label{display:flex;align-items:center;gap:5px 9px;flex-wrap:wrap}
.toggle,.connection{margin:6px 0}
.threshold{margin:9px 0}
.threshold fieldset{min-width:0;margin:0;padding:6px 9px 9px;border:1px solid var(--line);border-radius:6px}
.threshold legend{padding:0 4px;font-size:13px;font-weight:600}
.threshold-fields,.threshold-actions{display:flex;align-items:end;flex-wrap:wrap;gap:6px 12px}
.threshold-fields label{display:grid;gap:4px;color:var(--muted);font-size:12px}
.threshold-actions{margin-top:6px;align-items:center}
.threshold-actions button:disabled{opacity:.5}
.toggle input{margin:0;accent-color:var(--accent)}
small{color:var(--muted);font-size:12px}
.link{border:0;padding:0;background:none;color:var(--accent);text-decoration:underline;text-underline-offset:3px;font-size:12px}
.icon-button{display:inline-grid;place-items:center;width:25px;height:25px;padding:0;color:var(--accent);background:var(--surface);border:1px solid var(--line);border-radius:5px}
.icon-button:hover:not(:disabled){background:var(--hover)}
.problem{color:var(--danger);background:var(--danger-bg);padding:6px 9px;border-radius:6px}
details{margin:8px 0 0}
summary{color:var(--muted);cursor:pointer}
summary:hover{color:var(--text)}
.contract{margin:9px 0;display:grid;gap:6px}
.contract div{display:grid;grid-template-columns:minmax(85px,115px) minmax(0,1fr);gap:8px}
.contract dt{color:var(--muted)}
.contract dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
h4{margin:8px 0}
pre{font:11px/1.5 ui-monospace,monospace;background:var(--subtle);padding:10px;border-radius:6px;max-height:400px;overflow:auto}
.history{border-collapse:collapse;width:100%;text-align:left;table-layout:fixed;font-size:12px}
.history :is(th,td){padding:6px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.history th{color:var(--muted);font-weight:500}
.failed{color:var(--danger)}
@media(max-width:650px){.details{padding-left:12px}.contract div{grid-template-columns:1fr;gap:0}}
</style>
