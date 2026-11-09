<script setup lang="ts">
import ServerLink from './ServerLink.vue';
import { serverDirectoryKey, serverLabel } from '../serverDirectory';
import { computed, inject, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { call, preview } from '../api';

type Target = { id: string; name: string; address: string };
type Row = Target & { status: 'queued' | 'running' | 'ok' | 'fail'; code: number | null; durationMs: number | null; reason: string | null };
type Batch = { id: string; revision: number; command: string; active: boolean; stopping: boolean; rows: Row[] };
type Review = { ticket: string; confirmAll: boolean; targets: Target[] };
type Output = { stdout: string; stderr: string; truncated: boolean };

const props = defineProps<{ ids: string[]; all: boolean; active: boolean }>();
const directory = inject(serverDirectoryKey, undefined);
const draft = ref('');
const batch = ref<Batch>();
const review = ref<Review>();
const reviewedCommand = ref('');
const confirmation = ref<HTMLDialogElement>();
const submitting = ref(false);
const stopping = ref(false);
const errorsOnly = ref(false);
const error = ref('');
const expanded = ref(new Set<string>());
const outputs = ref<Record<string, Output>>({});
const pendingOutputs = new Set<string>();
let timer: ReturnType<typeof setTimeout> | undefined;
let disposed = false;
let generation = 0;

const counts = computed(() => {
  const rows = batch.value?.rows ?? [];
  const ok = rows.filter(row => row.status === 'ok').length;
  const fail = rows.filter(row => row.status === 'fail').length;
  return { ok, fail, pending: rows.length - ok - fail };
});
const rows = computed(() => (batch.value?.rows ?? []).filter(row => !errorsOnly.value || row.status === 'fail'));
const available = computed(() => !preview && !submitting.value && !batch.value?.active &&
  props.ids.length > 0 && props.ids.length <= 500 && Boolean(draft.value.trim()));

function report(failure: unknown) {
  error.value = String(failure).replace(/^Error: /, '');
}
async function poll() {
  clearTimeout(timer);
  if (disposed || document.hidden || !props.active) return;
  const current = batch.value;
  const read = ++generation;
  try {
    const result = await call<Batch | null>('console_batch_status', { id: current?.id, revision: current?.revision });
    if (disposed || read !== generation) return;
    if (result) {
      if (result.id !== current?.id) resetRows();
      batch.value = result;
      for (const row of result.rows) {
        if (expanded.value.has(row.id)) void readOutput(row);
      }
    }
  } catch (failure) {
    if (!disposed && read === generation) report(failure);
  } finally {
    if (!disposed && read === generation && props.active && batch.value?.active) timer = setTimeout(poll, 800);
  }
}
function visibility() {
  if (document.hidden) clearTimeout(timer);
  else void poll();
}
onMounted(() => {
  if (preview) return;
  document.addEventListener('visibilitychange', visibility);
  void poll();
});
watch(() => props.active, active => {
  if (preview) return;
  if (active) void poll();
  else clearTimeout(timer);
});
onBeforeUnmount(() => {
  disposed = true;
  clearTimeout(timer);
  document.removeEventListener('visibilitychange', visibility);
});

function resetRows() {
  expanded.value = new Set();
  outputs.value = {};
  pendingOutputs.clear();
  errorsOnly.value = false;
}
async function submit(event: KeyboardEvent) {
  if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
  event.preventDefault();
  if (event.repeat || !available.value || review.value) return;
  const command = draft.value;
  const ids = [...props.ids];
  const all = props.all;
  submitting.value = true;
  error.value = '';
  try {
    const prepared = await call<Review>('prepare_console_batch', { serverIds: ids, command, all });
    if (disposed) return;
    if (prepared.confirmAll) {
      reviewedCommand.value = command;
      review.value = prepared;
      await nextTick();
      confirmation.value?.showModal();
    } else {
      await launch(prepared.ticket, false, command);
    }
  } catch (failure) {
    report(failure);
  } finally {
    submitting.value = false;
  }
}
async function launch(ticket: string, confirmed: boolean, command: string) {
  const result = await call<Batch>('start_console_batch', { ticket, confirmed });
  if (disposed) return;
  resetRows();
  batch.value = result;
  if (draft.value === command) draft.value = '';
  void poll();
}
function closeReview() {
  confirmation.value?.close();
  review.value = undefined;
  reviewedCommand.value = '';
}
async function confirmAll() {
  if (!review.value || submitting.value) return;
  submitting.value = true;
  try {
    await launch(review.value.ticket, true, reviewedCommand.value);
  } catch (failure) {
    report(failure);
  } finally {
    closeReview();
    submitting.value = false;
  }
}
async function stop() {
  const current = batch.value;
  if (!current?.active || current.stopping || stopping.value) return;
  stopping.value = true;
  try {
    await call('stop_console_batch', { id: current.id });
    await poll();
  } catch (failure) {
    report(failure);
  } finally {
    stopping.value = false;
  }
}
async function readOutput(row: Row) {
  const id = batch.value?.id;
  const key = `${id}:${row.id}`;
  if (!id || row.status === 'queued' || row.status === 'running' ||
    outputs.value[row.id] || pendingOutputs.has(key)) return;
  pendingOutputs.add(key);
  try {
    const output = await call<Output>('console_batch_output', { id, serverId: row.id });
    if (!disposed && id === batch.value?.id) outputs.value[row.id] = output;
  } catch (failure) {
    if (!disposed && id === batch.value?.id) report(failure);
  } finally {
    pendingOutputs.delete(key);
  }
}
function toggle(row: Row) {
  if (expanded.value.has(row.id)) expanded.value.delete(row.id);
  else {
    expanded.value.add(row.id);
    void readOutput(row);
  }
}
const statusLabel: Record<Row['status'], string> = { queued: 'Pending', running: 'Running', ok: 'OK', fail: 'Failed' };
function seconds(ms: number) {
  return `${(ms / 1000).toLocaleString('en-US', { maximumFractionDigits: 1 })} s`;
}
</script>

<template>
  <section class="commands" aria-label="SSH commands">
    <label class="prompt">
      <span aria-hidden="true">›</span>
      <textarea v-model="draft" aria-label="SSH command" rows="2" spellcheck="false"
        placeholder="For example, df -h" :readonly="submitting || Boolean(review)" @keydown="submit"/>
    </label>
    <p v-if="preview" class="hint">SSH commands are disabled in the demo.</p>
    <p v-else-if="!ids.length || ids.length > 500" class="hint">Select 1 to 500 servers.</p>
    <p v-else class="hint">Enter to run · Shift+Enter for a new line</p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>

    <template v-if="batch">
      <div class="result-bar">
        <code :title="batch.command" class="last-command">{{ batch.command }}</code>
        <div class="counts" aria-label="Command results">
          <span class="ok">{{ counts.ok }} OK</span>
          <span class="fail">{{ counts.fail }} failed</span>
          <span>{{ counts.pending }} pending</span>
        </div>
        <label class="errors-only"><input v-model="errorsOnly" type="checkbox"> Failures only</label>
        <button v-if="batch.active" class="stop" type="button" :disabled="stopping || batch.stopping" @click="stop">
          {{ batch.stopping ? 'Stopping…' : 'Stop' }}
        </button>
      </div>
      <div class="results">
        <div v-for="row in rows" :key="row.id" class="result">
          <div class="result-row" @click="toggle(row)">
            <button type="button" class="disclosure" :aria-expanded="expanded.has(row.id)" :aria-label="`Command output · ${serverLabel(row, directory?.current().resolve(row)).host}`">
              {{ expanded.has(row.id) ? '▾' : '▸' }}
            </button>
            <ServerLink :id="row.id" :name="row.name" :address="row.address"/>
            <span class="badge" :class="row.status">{{ statusLabel[row.status] }}</span>
            <small>{{ row.status === 'running' ? 'Running'
              : row.code && row.code !== 255 ? `exit code ${row.code}` : row.durationMs !== null ? seconds(row.durationMs) : '' }}</small>
          </div>
          <div v-if="expanded.has(row.id)" class="details">
            <p class="hint">{{ row.address }}<template v-if="row.code !== null"> · exit code {{ row.code }}</template></p>
            <p v-if="row.reason">{{ row.reason }}</p>
            <p v-if="row.status === 'queued' || row.status === 'running'" class="hint">Output will appear when the command finishes.</p>
            <template v-else-if="outputs[row.id]">
              <p v-if="outputs[row.id].truncated">Output was truncated.</p>
              <p v-if="!outputs[row.id].stdout && !outputs[row.id].stderr" class="hint">The command produced no output.</p>
              <template v-if="outputs[row.id].stdout"><small>stdout</small><pre>{{ outputs[row.id].stdout }}</pre></template>
              <template v-if="outputs[row.id].stderr"><small>stderr</small><pre>{{ outputs[row.id].stderr }}</pre></template>
            </template>
          </div>
        </div>
        <p v-if="!rows.length && errorsOnly" class="hint">No failures.</p>
      </div>
    </template>

    <dialog v-if="review" ref="confirmation" class="confirmation" aria-labelledby="console-confirm-title" @cancel.prevent="!submitting && closeReview()">
      <h2 id="console-confirm-title">Run on all servers?</h2>
      <pre>{{ reviewedCommand }}</pre>
      <details><summary>Servers · {{ review.targets.length }}</summary>
        <ul><li v-for="target in review.targets" :key="target.id"><ServerLink :id="target.id" :name="target.name" :address="target.address" captured/></li></ul>
      </details>
      <footer>
        <button type="button" autofocus :disabled="submitting" @click="closeReview">Cancel</button>
        <button type="button" class="confirm" :disabled="submitting" @click="confirmAll">Confirm</button>
      </footer>
    </dialog>
  </section>
</template>

<style scoped>
.commands { min-width: 0; }
.prompt { display: flex; gap: 10px; align-items: baseline; padding: 10px 12px; border: 1px solid var(--line); background: var(--surface); border-radius: 6px; color: var(--accent); }
.prompt:focus-within { border-color: var(--accent); }
.prompt textarea { flex: 1; min-width: 0; padding: 0; overflow-wrap: anywhere; resize: vertical; border: none; outline: none; background: transparent; color: var(--text); font: 13px/1.5 ui-monospace, monospace; }
.hint { font-size: 12px; color: var(--muted); margin: 6px 0; }
.error { color: var(--danger); background: var(--danger-bg); padding: 7px 9px; border-radius: 5px; }
.result-bar { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; margin: 12px 0 5px; }
.last-command { white-space: nowrap; text-overflow: ellipsis; overflow: hidden; flex: 1 1 9em; min-width: 0; }
.counts, .errors-only { display: flex; align-items: center; gap: 6px; color: var(--muted); white-space: nowrap; }
.ok { color: var(--success); }
.fail { color: var(--danger); }
button { font: inherit; color: var(--text); cursor: pointer; }
.stop, footer button { border: 1px solid var(--line); border-radius: 5px; background: var(--surface); padding: 5px 8px; }
.stop { color: var(--danger); }
button:disabled { opacity: .55; cursor: default; }
.result { border-bottom: 1px solid var(--line); }
.result-row { display: grid; grid-template-columns: 12px minmax(0, 1fr) clamp(42px, 12%, 62px) clamp(56px, 18%, 84px); gap: 6px; align-items: center; padding: 4px 6px; text-align: left; background: transparent; border: none; min-height: 29px; }
.result-row:hover, .result-row:has([aria-expanded=true]) { background: var(--hover); }
.result-row { cursor: pointer; }
.disclosure { padding: 0; border: 0; background: none; }
.badge { font-size: 11px; }
.queued, .running, small, .disclosure { color: var(--muted); }
.running { color: var(--accent); }
small { text-align: right; }
.details { padding: 4px 14px 8px 24px; overflow-wrap: anywhere; }
pre { background: var(--subtle); white-space: pre-wrap; overflow-wrap: anywhere; unicode-bidi: plaintext; padding: 8px; border-radius: 5px; max-height: 270px; overflow: auto; }
.confirmation { width: min(520px, calc(100vw - 48px)); background: var(--surface); color: var(--text); border: 1px solid var(--line); border-radius: 9px; box-shadow: var(--shadow); padding: 16px; }
.confirmation::backdrop { background: var(--overlay); }
.confirmation h2 { font-size: 17px; margin: 0 0 8px; }
.confirmation ul { max-height: 180px; overflow: auto; overflow-wrap: anywhere; padding-left: 24px; }
footer { display: flex; gap: 8px; justify-content: flex-end; margin-top: 14px; }
.confirm { color: var(--on-accent); background: var(--accent); border-color: var(--accent); }
</style>
