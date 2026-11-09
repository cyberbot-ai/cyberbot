<script setup lang="ts">
import ServerLink from './ServerLink.vue';
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue';
import { call, preview } from '../api';
import type { AiTab } from '../aiNavigation';
import type { Settings, AutoStatus } from '../types';
import ActionApprovals from './ActionApprovals.vue';
import AutoBudgetForm from './AutoBudgetForm.vue';
import ModelProfiles from './ModelProfiles.vue';
import RelativeDate from './RelativeDate.vue';

const props = defineProps<{ settings: Settings; pendingActions?: number }>();
const tab = defineModel<AiTab>('tab', { default: 'sessions' });
const emit = defineEmits<{ saved: [settings?: Settings]; open: [id: string] }>();
const tabs: { id: AiTab; label: string }[] = [
  { id: 'sessions', label: 'Runs' },
  { id: 'actions', label: 'Actions' },
  { id: 'settings', label: 'Settings' },
];
const tabList = ref<HTMLElement>();
const settingsPanel = ref<HTMLElement>();
const visited = reactive(new Set<AiTab>());
const limitsOpen = ref(false);
const profilesOpen = ref(false);
const profilesVisited = ref(false);
const status = ref<AutoStatus>();
const busy = ref(false);
const error = ref('');
const refreshError = ref('');
const refreshing = ref(false);
const activeJobs = computed(() => status.value?.jobs.filter(job => job.state === 'queued' || job.state === 'running') ?? []);
const history = computed(() => status.value?.jobs.filter(job => job.state !== 'queued' && job.state !== 'running') ?? []);
let timer: ReturnType<typeof setInterval>;
let mounted = false;
let refreshVersion = 0;

function sessionsVisible() {
  return mounted && tab.value === 'sessions' && !document.hidden;
}

async function refresh() {
  if (!sessionsVisible()) return;
  const version = ++refreshVersion;
  refreshing.value = true;
  try {
    const value = await call<AutoStatus>('auto_status');
    if (mounted && version === refreshVersion) {
      status.value = value;
      refreshError.value = '';
    }
  } catch (e) {
    if (mounted && version === refreshVersion) refreshError.value = String(e).replace(/^Error: /, '');
  } finally {
    if (version === refreshVersion) refreshing.value = false;
  }
}

async function action(command: string, id?: string) {
  if (busy.value || preview) return;
  busy.value = true;
  error.value = '';
  try {
    await call(command, id ? { id } : undefined);
    if (mounted) {
      await refresh();
      emit('saved');
    }
  } catch (e) {
    error.value = String(e).replace(/^Error: /, '');
  } finally {
    busy.value = false;
  }
}

function refreshIfVisible() {
  if (!busy.value && !refreshing.value) void refresh();
}

watch(tab, value => {
  visited.add(value);
  if (value === 'sessions') refreshIfVisible();
}, { immediate: true });
watch([() => props.settings.mode, () => props.settings.paused], refreshIfVisible);
onMounted(() => {
  mounted = true;
  refreshIfVisible();
  timer = setInterval(refreshIfVisible, 15000);
  document.addEventListener('visibilitychange', refreshIfVisible);
});
onUnmounted(() => {
  mounted = false;
  clearInterval(timer);
  document.removeEventListener('visibilitychange', refreshIfVisible);
});

async function switchTab(event: KeyboardEvent) {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  event.preventDefault();
  const index = tabs.findIndex(item => item.id === tab.value);
  const offset = event.key === 'ArrowRight' ? 1 : -1;
  const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + offset + tabs.length) % tabs.length;
  tab.value = tabs[next].id;
  await nextTick();
  tabList.value?.querySelector<HTMLElement>('[aria-selected=true]')?.focus();
}

async function openLimits() {
  limitsOpen.value = true;
  tab.value = 'settings';
  await nextTick();
  settingsPanel.value?.querySelector('summary')?.focus();
}

function toggleProfiles(event: Event) {
  profilesOpen.value = (event.currentTarget as HTMLDetailsElement).open;
  if (profilesOpen.value) profilesVisited.value = true;
}

const labels: Record<string, string> = {
  merged: 'Merged into an incident group', queued: 'Queued', suppressed: 'Blocked by the automation policy',
  running: 'Running', completed: 'Completed', failed: 'Failed', cancelled: 'Cancelled',
  interrupted: 'Interrupted', obsolete: 'Issue resolved', dismissed: 'Skipped', budget_exceeded: 'Token limit',
};
const number = (n: number) => n.toLocaleString('en-US');
</script>

<template>
  <div class="ai-page">
    <div ref="tabList" class="ai-tabs" role="tablist" aria-label="AI sections" @keydown="switchTab">
      <button v-for="item in tabs" :id="`ai-${item.id}-tab`" :key="item.id" type="button" role="tab"
        :aria-controls="`ai-${item.id}-panel`" :aria-selected="tab === item.id" :tabindex="tab === item.id ? 0 : -1"
        :aria-label="item.id === 'actions' && pendingActions ? `Actions awaiting approval ${pendingActions}` : undefined"
        @click="tab = item.id">
        {{ item.label }}<span v-if="item.id === 'actions' && pendingActions" class="tab-count" aria-hidden="true">{{ pendingActions }}</span>
      </button>
    </div>

    <div v-show="tab === 'sessions'" id="ai-sessions-panel" class="ai-panel" role="tabpanel" aria-labelledby="ai-sessions-tab" tabindex="0">
      <template v-if="visited.has('sessions')">
        <section class="queue">
          <header class="section-heading">
            <h2>Automatic investigations</h2>
            <span v-if="status?.queued" class="muted">Queued {{  number(status.queued) }}</span>
          </header>
          <p v-if="error" class="error" role="alert">{{ error }}</p>
          <div v-if="refreshError" class="error refresh-error">
            <span role="alert">Could not refresh AI runs. {{ refreshError }}</span>
            <button type="button" class="secondary" :disabled="refreshing" @click="refresh">Retry</button>
          </div>
          <template v-if="status">
            <div v-if="status.blockedReason" class="notice">
              <p role="status">Token usage needs review. {{ status.blockedReason }}</p>
              <button type="button" class="secondary" :disabled="busy || preview" @click="action('resume_auto')">Confirm usage and resume</button>
              <p class="small">Resuming does not restart completed or cancelled jobs.</p>
            </div>
            <div v-if="status.waitingReason" class="notice">
              <p role="status">{{ status.waitingReason }}</p>
              <button type="button" class="text-button" @click="openLimits">Edit limits</button>
            </div>
            <div v-if="!activeJobs.length" class="empty">
              <strong>No active jobs</strong>
              <p v-if="settings.mode === 'auto'">New significant incidents will appear here as jobs.</p>
            </div>
            <article v-for="job in activeJobs" :key="job.id" class="job">
              <div class="job-description">
                <button type="button" class="text-button title" @click="emit('open', job.serverId)">{{ job.title }}</button>
                <ServerLink :id="job.serverId"/>
                <p>{{ job.evidence }}</p>
                <small>{{ labels[job.state] }}<template v-if="job.state === 'queued'"> · waiting for fresh data and available budget</template></small>
              </div>
              <button v-if="job.state === 'queued'" type="button" class="secondary" :disabled="busy || preview" @click="action('dismiss_auto_job', job.id)">Skip</button>
              <button v-if="job.state === 'running' && job.runId" type="button" class="secondary" :disabled="busy || preview" @click="action('cancel_investigation', job.runId)">Stop</button>
            </article>
            <details v-if="history.length" class="disclosure history">
              <summary>History <span>{{ history.length }}</span></summary>
              <article v-for="job in history" :key="job.id" class="job history-row">
                <button type="button" class="text-button" @click="emit('open', job.serverId)">{{ job.title }}</button>
                <ServerLink :id="job.serverId"/>
                <span>{{ labels[job.state] ?? job.state }}</span>
              </article>
              <p v-if="status.jobs.length === 100" class="small">Showing the latest 100 jobs, including queued jobs.</p>
            </details>
          </template>
          <p v-else-if="!refreshError" class="muted" role="status">Loading AI run status…</p>
        </section>
        <section v-if="status" class="usage">
          <header class="section-heading"><h2>Daily usage</h2><span class="muted">UTC</span></header>
          <dl class="metrics">
            <div><dt>Runs</dt><dd>{{ number(status.runs) }}</dd></div>
            <div><dt>Reported tokens</dt><dd>{{ number(status.actualTokens) }}</dd></div>
          </dl>
          <p v-if="status.uncertainRuns" class="usage-warning">Some token usage is unconfirmed.</p>
          <details class="disclosure">
            <summary>Usage and queue details</summary>
            <div class="disclosure-body">
              <p class="small">Usage for <RelativeDate :at="status.day * 86400" calendar-day/>, UTC. Values are in tokens.</p>
              <dl class="metrics">
                <div><dt>Budget in use</dt><dd>{{ number(status.chargedTokens) }}</dd></div>
                <div><dt>Currently reserved</dt><dd>{{ number(status.reservedTokens) }}</dd></div>
                <div><dt>Runs with unconfirmed usage</dt><dd>{{ number(status.uncertainRuns) }}</dd></div>
              </dl>
              <p class="small">The budget includes reported usage, active reservations, and reservations for unconfirmed usage. Cached input tokens also count.</p>
              <p class="small">One automatic investigation runs at a time. Repeat findings are grouped into an episode, and related events across servers can form an incident group. Collecting events can take up to two minutes. Failed or cancelled jobs do not restart automatically. New episodes for the same check wait at least 6 hours. The queue holds up to 500 jobs.</p>
            </div>
          </details>
        </section>
      </template>
    </div>

    <div v-show="tab === 'actions'" id="ai-actions-panel" class="ai-panel" role="tabpanel" aria-labelledby="ai-actions-tab" tabindex="0">
      <ActionApprovals v-if="visited.has('actions')" :active="tab === 'actions'"/>
    </div>

    <div v-show="tab === 'settings'" id="ai-settings-panel" ref="settingsPanel" class="ai-panel" role="tabpanel" aria-labelledby="ai-settings-tab" tabindex="0">
      <div v-if="visited.has('settings')" class="settings-content">
        <slot name="agent"/>
        <AutoBudgetForm v-model:open="limitsOpen" :settings="settings" @saved="emit('saved', $event)"/>
        <details class="disclosure profiles" @toggle="toggleProfiles">
          <summary>Model profiles</summary>
          <ModelProfiles v-if="profilesVisited" v-show="profilesOpen"/>
        </details>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ai-page { display: flex; flex: 1; min-width: 0; min-height: 0; max-width: 920px; flex-direction: column; }
.ai-tabs { display: flex; flex: none; gap: clamp(12px, 3vw, 28px); border-bottom: 1px solid var(--line); }
.ai-tabs button {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 40px;
  border: 0; border-bottom: 2px solid transparent; padding: 6px 3px; border-radius: 0; cursor: pointer;
  background: transparent; color: var(--muted); font: inherit; font-weight: 550; white-space: nowrap;
}
.ai-tabs button:hover { color: var(--text); }
.ai-tabs button[aria-selected=true] { border-bottom-color: var(--accent); color: var(--text); }
.tab-count { min-width: 18px; padding-inline: 4px; border-radius: 6px; background: var(--warning-bg); color: var(--warning); font-size: 11px; text-align: center; font-variant-numeric: tabular-nums; }
.ai-panel { flex: 1; min-height: 0; overflow: auto; padding: 20px 4px 28px; margin-inline: -4px; scrollbar-color: var(--line-strong) transparent; }
.ai-panel:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
.settings-content { max-width: 680px; }
.section-heading, .job { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 6px 16px; }
h2 { margin: 0; font-size: 16px; font-weight: 600; }
p { font-size: 12px; color: var(--muted); line-height: 1.6; }
.muted, .small { font-size: 12px; color: var(--muted); }
.empty { padding: 16px 0; }
.empty strong { font-size: 13px; font-weight: 550; }
.empty p { margin: 4px 0 0; max-width: 68ch; }
button { font: inherit; cursor: pointer; }
button:disabled { opacity: .5; cursor: default; }
button:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.secondary { min-height: 32px; padding: 6px 10px; font-size: 12px; border: 1px solid var(--line); border-radius: 6px; color: var(--text); background: var(--surface); }
.secondary:hover:enabled { background: var(--hover); border-color: var(--line-strong); }
.text-button { background: none; border: 0; padding: 2px 0; color: var(--accent); font-size: 12px; text-align: left; overflow-wrap: anywhere; }
.text-button:hover { text-decoration: underline; text-underline-offset: 2px; }
.title { font-size: 13px; font-weight: 550; }
.job { padding: 12px 0; border-bottom: 1px solid var(--line); }
.job-description { flex: 1 1 240px; min-width: 0; }
.job p { margin: 4px 0; overflow-wrap: anywhere; }
.job small, .history-row span { font-size: 11px; color: var(--muted); }
.notice, .error { padding: 10px 12px; border-radius: 6px; margin: 12px 0; font-size: 12px; overflow-wrap: anywhere; }
.notice { background: var(--warning-bg); color: var(--warning); }
.notice p { color: inherit; margin: 0 0 6px; }
.notice .small { margin: 6px 0 0; }
.notice .text-button { color: inherit; text-decoration: underline; text-underline-offset: 2px; }
.error { color: var(--danger); background: var(--danger-bg); }
.refresh-error { display: flex; align-items: center; gap: 8px 14px; flex-wrap: wrap; }
.usage { border-top: 1px solid var(--line); margin-top: 18px; padding-top: 16px; }
.usage .section-heading { justify-content: flex-start; align-items: baseline; }
.metrics { display: flex; flex-wrap: wrap; gap: 12px 32px; margin: 12px 0; }
.metrics > div { display: flex; align-items: baseline; flex-wrap: wrap; gap: 4px 10px; min-width: 0; }
dt { font-size: 12px; color: var(--muted); }
dd { font-size: 13px; font-weight: 600; font-variant-numeric: tabular-nums; margin: 0; overflow-wrap: anywhere; }
.usage-warning { color: var(--warning); }
.disclosure { border-top: 1px solid var(--line); }
.disclosure summary { cursor: pointer; padding: 10px 0; font-weight: 550; }
.disclosure summary span { color: var(--muted); margin-inline-start: 5px; font-size: 12px; }
.disclosure-body { max-width: 70ch; }
.disclosure-body > p:first-child { margin-top: 0; }
.history { margin-top: 8px; border-top: 0; }
.history-row { padding: 8px 0; }
</style>
