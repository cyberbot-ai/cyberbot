<script setup lang="ts">
import { presentServiceAction } from '../serviceActions';
import ServerLink from './ServerLink.vue';
import { actionLabelAddress, actionRequestAddress, capturedActionServers } from '../serverDirectory';
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { call, preview } from '../api';
import { formatTimeRange } from '../dateTime';
import type { ActionCard, ActionRequest } from '../types';
import RelativeDate from './RelativeDate.vue';
import UiIcon from './UiIcon.vue';

const props = withDefaults(defineProps<{
  runId?: string; serverId?: string; selectedRequest?: string; compact?: boolean; active?: boolean;
}>(), { active: true });

const cards = ref<ActionCard[]>([]), current = ref<ActionRequest>();
const selected = ref(!props.compact ? props.selectedRequest ?? '' : '');
const error = ref(''), loadError = ref(''), busy = ref(false), loading = ref(true);
const root = ref<HTMLElement>(), listTitle = ref<HTMLElement>(), backButton = ref<HTMLButtonElement>();
let listScroll = 0, listTrigger: HTMLButtonElement | undefined;

const labels: Record<string, string> = {
  proposed: 'Preparation', validating: 'Verification of restrictions', reviewing: 'Risk verification',
  awaitingApproval: 'Waiting for permission', approved: 'Permitted', queued: 'In line',
  running: 'Running', succeeded: 'Completed', failed: 'Failed', denied: 'Denied',
  cancelled: 'Cancelled', expired: 'The request expired', unknown: 'Results require verification',
  rollbackRunning: 'Recoiling is being carried out', rolledBack: 'Pushback verified', rollbackUnknown: 'Pushback requires verification',
};
const activeStates = new Set(['proposed', 'validating', 'reviewing', 'awaitingApproval', 'approved', 'queued', 'running', 'rollbackRunning']);
const reviewLabels = {
  allow: 'Check passed', confirm: 'One-time authorization required',
  deny: 'Action blocked', uncertain: 'The risk could not be assessed',
};
const groups = computed(() => [
  { title: 'Awaiting decision', rows: cards.value.filter(r => r.state === 'awaitingApproval') },
  { title: 'In progress', rows: cards.value.filter(r => activeStates.has(r.state) && r.state !== 'awaitingApproval') },
  { title: 'History', rows: cards.value.filter(r => !activeStates.has(r.state)) },
].filter(group => group.rows.length));
const selectedCard = computed(() => cards.value.find(r => r.id === selected.value));
const proposedAction = computed(() => current.value?.artifact.spec.action);
const waiting = computed(() => current.value?.state === 'awaitingApproval');
const planning = computed(() => current.value && activeStates.has(current.value.state) && current.value.state !== 'rollbackRunning');
const scope = computed(() => capturedActionServers(current.value?.artifact.scopeEndpoints ?? {}));
const capturedAddress = computed(() => actionRequestAddress(current.value));
const author = computed(() => {
  const provider = current.value?.artifact.provider;
  return provider === 'codex' ? 'Codex' : provider === 'claude' ? 'Claude Code' : provider || 'AI';
});
const shellUser = computed(() => {
  const user = current.value?.artifact.prepared.user;
  return typeof user === 'string' ? user : '';
});
const serviceAction = computed(() => presentServiceAction(proposedAction.value));
const rollbackAvailable = computed(() => serviceAction.value?.rollback && current.value?.state === 'succeeded'
  && (current.value.result?.effect as { rollbackAvailable?: boolean } | undefined)?.rollbackAvailable === true);
const resultValue = computed(() => current.value?.result?.result);
const shellResult = computed(() => {
  const value = resultValue.value;
  if (proposedAction.value?.kind !== 'shell' || !value || typeof value !== 'object') return null;
  const { exitCode, stdout, stderr, truncated } = value as Record<string, unknown>;
  return {
    exitCode: typeof exitCode === 'number' ? exitCode : null,
    stdout: typeof stdout === 'string' ? stdout : '',
    stderr: typeof stderr === 'string' ? stderr : '',
    truncated: truncated === true,
  };
});
const outcome = computed(() => {
  const request = current.value;
  if (!request) return '';
  if (shellResult.value?.exitCode != null) {
    const { exitCode } = shellResult.value;
    return exitCode === 0 ? 'Teams completed successfully (code).' : `Teams ended with a mistake (code ${exitCode}).`;
  }
  switch (request.state) {
    case 'succeeded':
      return serviceAction.value?.success ?? 'The action ended successfully.';
    case 'denied':
      return request.decision === 'deny' ? 'You denied the request.' : 'Risk check blocked the action.';
    case 'expired': return 'The request expired.';
    case 'cancelled': return 'Request cancelled.';
    case 'unknown': return 'Cyberbot could not confirm the result.';
    case 'failed': return 'Action failed.';
    case 'rollbackRunning': return 'Cyberbot restores the original configuration.';
    case 'rolledBack': return 'Original configuration restored and verified.';
    case 'rollbackUnknown': return 'Cyberbot could not confirm the result of the rollback.';
    default: return labels[request.state] ?? request.state;
  }
});
const codeTitle = computed(() => {
  if (proposedAction.value?.kind !== 'shell') return 'Verification code (Python)';
  if (shellResult.value?.exitCode != null || current.value?.state === 'succeeded') return 'Executed teams';
  return planning.value ? 'Commands to launch' : 'Proposed teams';
});

let timer: ReturnType<typeof setInterval> | undefined, off: UnlistenFn | undefined, disposed = false, sequence = 0;
const isVisible = () => !disposed && props.active && !document.hidden;
const errorText = (e: unknown) => String(e).replace(/^Error: /, '');

async function detail(id: string, version: number) {
  const value = await call<ActionRequest>('action_request', { id });
  if (!isVisible() || version !== sequence || selected.value !== id) return;
  if (value.id !== id || (props.serverId && value.serverId !== props.serverId) || (props.runId && value.runId !== props.runId)) {
    throw new Error('The request relates to another launch.');
  }
  current.value = value;
}
async function load() {
  if (!isVisible()) return;
  const version = ++sequence;
  try {
    const value = await call<ActionCard[]>('action_requests', { runId: props.runId ?? null, serverId: props.serverId ?? null });
    if (!isVisible() || version !== sequence) return;
    if (!Array.isArray(value)) throw new Error('I was unable to read the list of actions');
    cards.value = value;
    loading.value = false;
    if (selected.value) await detail(selected.value, version);
    if (isVisible() && version === sequence) loadError.value = '';
  } catch (e) {
    if (isVisible() && version === sequence) loadError.value = errorText(e);
  } finally {
    if (isVisible() && version === sequence) loading.value = false;
  }
}
function clearSelection() {
  sequence++;
  selected.value = '';
  current.value = undefined;
  error.value = '';
  loadError.value = '';
}
async function select(id: string, event?: MouseEvent) {
  if (props.compact && selected.value === id) {
    clearSelection();
    return;
  }
  if (!props.compact) {
    listScroll = root.value?.parentElement?.scrollTop ?? 0;
    listTrigger = event?.currentTarget as HTMLButtonElement | undefined;
  }
  selected.value = id;
  current.value = undefined;
  error.value = '';
  loadError.value = '';
  const version = ++sequence;
  if (!props.compact) void nextTick(() => {
    if (selected.value !== id) return;
    if (root.value?.parentElement) root.value.parentElement.scrollTop = 0;
    backButton.value?.focus({ preventScroll: true });
  });
  try {
    await detail(id, version);
  } catch (e) {
    if (isVisible() && version === sequence) loadError.value = errorText(e);
  }
}
async function back() {
  clearSelection();
  await nextTick();
  if (root.value?.parentElement) root.value.parentElement.scrollTop = listScroll;
  (listTrigger?.isConnected ? listTrigger : listTitle.value)?.focus({ preventScroll: true });
}
async function action(command: string, args: Record<string, unknown>) {
  if (busy.value || preview) return;
  busy.value = true;
  error.value = '';
  const version = ++sequence;
  try {
    const result = await call<ActionRequest | undefined>(command, args);
    if (isVisible() && version === sequence && result?.id === selected.value) current.value = result;
    await load();
  } catch (e) {
    if (isVisible() && version === sequence) error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}
function visible() {
  if (!busy.value) void load();
}
watch(() => props.active, visible);
watch(() => [props.runId, props.serverId, props.selectedRequest], () => {
  clearSelection();
  cards.value = [];
  loading.value = true;
  if (!props.compact) selected.value = props.selectedRequest ?? '';
  void load();
});
onMounted(() => {
  void load();
  timer = setInterval(visible, 15000);
  if (!preview) void listen('action-changed', visible).then(unlisten => {
    if (disposed) unlisten();
    else off = unlisten;
  }).catch(() => {});
  document.addEventListener('visibilitychange', visible);
});
onUnmounted(() => {
  disposed = true;
  sequence++;
  clearInterval(timer);
  off?.();
  document.removeEventListener('visibilitychange', visible);
});
</script>

<template>
  <section v-if="!compact || cards.length || error || loadError" ref="root" class="actions" :class="{ compact, 'detail-page': !compact && selected }" aria-label="AI action">
    <div v-if="!compact" v-show="!selected" class="action-list">
      <header class="list-header">
        <h2 ref="listTitle" tabindex="-1">AI action</h2>
        <p>AI offers action. Cyberbot executes it at your permission.</p>
      </header>
      <p v-if="loading" class="muted" role="status">Download the action…</p>
      <div v-else-if="!cards.length && !loadError" class="empty">
        <strong>No action yet</strong>
        <p>There will be AI proposals for which permission is required.</p>
      </div>
      <section v-for="group in groups" :key="group.title" class="action-group">
        <h3>{{ group.title }} <span class="count">{{ group.rows.length }}</span></h3>
        <ul class="requests">
          <li v-for="r in group.rows" :key="r.id">
            <button type="button" class="request" @click="select(r.id, $event)">
              <span class="request-main"><strong>{{ r.goal }}</strong></span>
              <span class="request-meta">
                <span class="status" :class="r.state">{{ labels[r.state] ?? r.state }}</span>
                <span class="row-date">{{ formatTimeRange(r.createdAt, r.createdAt) }}</span>
              </span>
              <UiIcon name="chevron" :size="15"/>
            </button>
            <div class="request-server"><ServerLink :id="r.serverId" :address="actionLabelAddress(r.serverLabel)"/></div>
          </li>
        </ul>
      </section>
    </div>
    <div v-else class="compact-requests">
      <div v-for="r in cards" :key="r.id" class="compact-row">
        <button type="button" class="compact-toggle" :aria-expanded="selected === r.id" @click="select(r.id)">
          <span aria-hidden="true">{{ selected === r.id ? '▾' : '▸' }}</span>
          <span class="compact-goal">{{ r.goal }}</span>
          <span class="status" :class="r.state">{{ labels[r.state] ?? r.state }}</span>
        </button>
        <button v-if="r.state === 'awaitingApproval'" type="button" class="primary" :disabled="busy || preview" @click="action('open_action_approval', { id: r.id })">Open the permit</button>
      </div>
    </div>

    <button v-if="!compact && selected" ref="backButton" type="button" class="back" @click="back">
      <UiIcon name="arrow" :size="16"/> To the action list
    </button>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <div v-if="loadError" class="load-error">
      <p class="error" role="alert">{{ loadError }}</p>
      <button type="button" :disabled="busy" @click="load">Repeat</button>
    </div>
    <p v-if="selected && !current && !loadError" class="muted" role="status">Download the action…</p>

    <article v-if="current" :key="current.id" class="detail" aria-label="Details of action">
      <header class="detail-header">
        <div class="detail-meta">
          <span class="status" :class="current.state" role="status">{{ labels[current.state] ?? current.state }}</span>
          <span class="muted">Request <RelativeDate :at="current.createdAt"/></span>
        </div>
        <component :is="compact ? 'h3' : 'h2'">{{ current.artifact.spec.goal }}</component>
      </header>
      <dl class="facts">
        <div><dt>Proposed</dt><dd>{{ author }}</dd></div>
        <div><dt>Server</dt><dd><ServerLink :id="current.serverId" :address="capturedAddress" captured/></dd></div>
      </dl>

      <section class="impact">
        <h3>{{ planning ? proposedAction?.kind === 'diagnostic' ? 'What Cyberbot will test' : 'What’s gonna change' : 'What happened' }}</h3>
        <template v-if="planning">
          <p v-if="proposedAction?.kind === 'diagnostic'">Cyberbot will calculate the result from the generated data. The code is blocked from accessing files, the network and running processes.</p>
          <p v-else-if="serviceAction">{{ serviceAction.impact }}</p>
          <p v-else-if="!current.review?.verdict.effects.length">Cyberbot will execute commands below on the specified server.</p>
          <ul v-if="current.review?.verdict.effects.length" class="effect-list">
            <li v-for="(effect, index) in current.review.verdict.effects" :key="index">{{ effect }}</li>
          </ul>
          <div v-if="current.artifact.prepared.before" class="diff" aria-label="Change of configuration">
            <code class="before">− {{ current.artifact.prepared.before }}</code>
            <code class="after">+ {{ current.artifact.prepared.after }}</code>
          </div>
        </template>
        <p v-else>{{ outcome }}</p>
        <p v-if="current.error" class="error">{{ current.error }}</p>
      </section>
      <p v-if="proposedAction?.kind === 'shell' && (planning || shellResult)" class="risk">
        <UiIcon name="incident" :size="15"/>
        <span>
          {{ planning ? 'Launch' : 'Teams launched' }} SSH
          <template v-if="shellUser">on behalf <code>{{ shellUser }}</code></template>.
        </span>
      </p>

      <div class="detail-sections">
        <details v-if="resultValue !== undefined" class="output">
          <summary>{{ shellResult ? 'Command output' : 'Outcome of implementation' }}</summary>
          <template v-if="shellResult">
            <pre v-if="shellResult.stdout">{{ shellResult.stdout }}</pre>
            <template v-if="shellResult.stderr">
              <p class="muted">Error stream (stderr)</p>
              <pre>{{ shellResult.stderr }}</pre>
            </template>
            <p v-if="!shellResult.stdout && !shellResult.stderr" class="muted">Teams did not return text output.</p>
            <p v-if="shellResult.truncated" class="muted">Output truncated to the storage limit.</p>
          </template>
          <pre v-else>{{ JSON.stringify(resultValue, null, 2) }}</pre>
        </details>
        <details class="code">
          <summary>{{ codeTitle }}</summary>
          <pre>{{ current.artifact.spec.code }}</pre>
        </details>
        <details>
          <summary>Risk verification and parameters</summary>
          <template v-if="current.review">
            <p><strong>{{ reviewLabels[current.review.verdict.decision] }}</strong> · {{ current.review.model ?? current.artifact.profile.low.model }} · {{ current.review.tokens.toLocaleString('en-US') }} token</p>
            <p>{{ current.review.verdict.explanation }}</p>
            <ul v-if="!planning && current.review.verdict.effects.length" class="effect-list">
              <li v-for="(effect, index) in current.review.verdict.effects" :key="index">{{ effect }}</li>
            </ul>
          </template>
          <p v-if="current.decision === 'once'">You only allowed this action.</p>
          <p v-else-if="current.decision === 'session'">You’ve authorized action as part of this AI launch.</p>
          <p v-if="current.artifactHash">Hash of code and parameters <code>{{ current.artifactHash }}</code></p>
          <p v-if="scope.length">Permission servers</p>
          <ul v-if="scope.length"><li v-for="target in scope" :key="target.id"><ServerLink :id="target.id" :address="target.address" captured/></li></ul>
          <details><summary>Input data and implementation limitations</summary><pre>{{ JSON.stringify({ inputs: current.artifact.inputs, isolation: current.artifact.isolation }, null, 2) }}</pre></details>
          <details v-if="serviceAction?.rollback && current.artifact.spec.rollbackPlan"><summary>An AI recovery plan</summary><p>{{ current.artifact.spec.rollbackPlan }}</p></details>
          <details v-if="current.artifact.prepared.before && !planning"><summary>Change of configuration</summary>
            <div class="diff"><code class="before">− {{ current.artifact.prepared.before }}</code><code class="after">+ {{ current.artifact.prepared.after }}</code></div>
          </details>
          <details v-if="current.result"><summary>Full result of implementation</summary><pre>{{ JSON.stringify(current.result, null, 2) }}</pre></details>
        </details>
      </div>

      <div v-if="waiting" class="approval">
        <button type="button" class="primary" :disabled="busy || preview" @click="action('open_action_approval', { id: current.id })">
          Open the permission window <UiIcon name="external" :size="14"/>
        </button>
        <p v-if="current.review?.verdict.decision === 'confirm'">In the window, you can allow the launch once or reject the request.</p>
        <p v-else>In the window you can check the details and decide whether to allow the launch.</p>
      </div>
      <div v-else class="controls">
        <button v-if="selectedCard?.sessionGranted" type="button" :disabled="busy || preview" @click="action('revoke_action_grant', { runId: current.runId })">Withdrawal of launch authorization</button>
        <button v-if="activeStates.has(current.state)" type="button" :disabled="busy || preview" @click="action('cancel_action', { id: current.id })">Cancel the request</button>
        <button v-if="current.state === 'unknown' || current.state === 'rollbackUnknown'" type="button" :disabled="busy || preview" @click="action('refresh_action_result', { id: current.id })">Check the saved result</button>
        <button v-if="rollbackAvailable" type="button" :disabled="busy || preview" @click="action('rollback_action', { id: current.id, artifactHash: current.artifactHash })">Restoring the original configuration</button>
      </div>
    </article>
  </section>
</template>

<style scoped>
.actions { min-width: 0; }
h2, h3, p, dl, dd { margin: 0; }
h2 { font-size: 20px; font-weight: 600; letter-spacing: -.02em; }
h3 { font-size: 13px; font-weight: 600; }
p, li { overflow-wrap: anywhere; line-height: 1.55; }
p, .muted, .facts dt, .row-date { color: var(--muted); font-size: 12px; }
.list-header { display: grid; gap: 4px; margin-bottom: 18px; }
.action-group + .action-group { margin-top: 16px; }
.action-group h3 { display: flex; align-items: center; gap: 8px; margin-bottom: 7px; }
.count { padding: 0 7px; border-radius: 12px; background: var(--subtle); color: var(--muted); font-size: 11px; font-weight: 500; }
.requests { margin: 0; padding: 0; list-style: none; background: var(--surface); border: 1px solid var(--line); border-radius: 9px; }
.requests > li + li { border-top: 1px solid var(--line); }
.request {
  display: grid; grid-template-columns: minmax(0, 1fr) minmax(220px, 30%) 15px;
  align-items: center; gap: 12px; width: 100%; padding: 12px 13px;
  text-align: left; border: 0; border-radius: 0; background: transparent;
}
.requests > li:first-child .request { border-start-start-radius: 8px; border-start-end-radius: 8px; }
.requests > li:last-child .request { border-end-start-radius: 8px; border-end-end-radius: 8px; }
.request:focus-visible { outline-offset: -2px; }
.request-server { padding: 0 13px 9px; font-size: 12px; }
.request-main { display: grid; min-width: 0; gap: 3px; }
.request-main strong { font-size: 13px; font-weight: 550; }
.request-meta { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 8px; min-width: 0; }
.request > svg { color: var(--muted); }
.status { display: inline-block; width: fit-content; padding: 3px 8px; border-radius: 12px; background: var(--subtle); color: var(--muted); font-size: 11px; line-height: 1.25; overflow-wrap: anywhere; }
.status.awaitingApproval, .status.unknown, .status.rollbackUnknown { background: var(--warning-bg); color: var(--warning); }
.status.succeeded, .status.rolledBack { background: var(--accent-bg); color: var(--success); }
.status.failed { background: var(--danger-bg); color: var(--danger); }
.row-date { text-align: end; font-variant-numeric: tabular-nums; }
.empty { padding-block: 10px; }
.empty p { margin-top: 4px; }
.detail-page { box-sizing: border-box; max-width: 775px; padding: 16px 18px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface); }
.back { display: inline-flex; align-items: center; gap: 6px; margin-bottom: 12px; }
.actions .back { border: 0; padding: 3px 4px; background: transparent; }
.back svg { transform: rotate(180deg); }
.detail { display: grid; gap: 12px; min-width: 0; overflow-wrap: anywhere; }
.detail-header { display: grid; gap: 5px; }
.detail-meta { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.facts { display: flex; flex-wrap: wrap; gap: 8px 24px; padding-block: 9px; border-block: 1px solid var(--line); }
.facts div { display: grid; gap: 2px; }
.facts dd { font-size: 13px; }
.impact { display: grid; gap: 4px; }
.impact p:not(.error), .effect-list { color: var(--text); font-size: 13px; }
.effect-list { margin: 0; padding-inline-start: 18px; }
.effect-list li + li { margin-top: 2px; }
.risk { display: flex; align-items: flex-start; gap: 7px; padding: 8px 10px; border-radius: 6px; color: var(--warning); background: var(--warning-bg); }
.risk svg { margin-top: 1px; }
.diff { display: grid; gap: 4px; padding: 9px 10px; border-radius: 6px; background: var(--subtle); }
.before { color: var(--danger); }
.after { color: var(--success); }
.detail-sections details { padding: 7px 0; border-bottom: 1px solid var(--line); font-size: 12px; }
.detail-sections details details { border-bottom: 0; padding-bottom: 0; padding-inline-start: 10px; }
.detail-sections details p { margin-top: 7px; }
.detail-sections ul { margin: 5px 0; padding-inline-start: 18px; }
summary { cursor: pointer; color: var(--text); }
pre {
  max-height: 260px; overflow: auto; margin: 7px 0 0; padding: 10px;
  border-radius: 6px; background: var(--subtle); color: var(--text);
  font: 12px/1.6 ui-monospace, monospace; white-space: pre-wrap; overflow-wrap: anywhere;
}
.approval { display: grid; gap: 5px; justify-items: start; }
.controls, .load-error { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.controls:empty { display: none; }
.error { color: var(--danger); }
.load-error { margin-block: 8px; }
button { font: inherit; font-size: 12px; color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: 7px 10px; background: var(--surface); cursor: pointer; }
button:disabled { opacity: .6; cursor: default; }
button.primary { display: inline-flex; align-items: center; gap: 6px; background: var(--accent); color: var(--on-accent); border-color: var(--accent); }
button:not(.primary):hover:enabled { background: var(--hover); }
button:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.compact { margin-top: 12px; }
.compact-requests { display: grid; gap: 6px; }
.compact-row { display: flex; gap: 8px; align-items: center; min-width: 0; }
.compact-toggle { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; text-align: left; border: 0; background: transparent; padding: 7px 0; }
.compact-goal { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.compact-toggle .status { flex: none; max-width: 45%; }
.compact .detail { margin-top: 8px; padding: 12px; border: 1px solid var(--line); border-radius: 7px; }
@media (max-width: 620px) {
  .request { grid-template-columns: minmax(0, 1fr) 15px; gap: 6px 8px; }
  .request > svg { grid-column: 2; grid-row: 1 / 3; }
  .request-meta { grid-column: 1; }
  .detail-page { padding: 13px; }
  .compact-row { flex-wrap: wrap; }
  .compact-toggle { flex-basis: 100%; }
}
</style>
