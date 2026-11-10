<script setup lang="ts">
import { computed, nextTick, onActivated, onDeactivated, onMounted, onUnmounted, ref, watch } from 'vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { call, preview } from '../api';
import type { AgentStatus, Investigation } from '../types';
import ActionApprovals from './ActionApprovals.vue';
import MarkdownReply from './MarkdownReply.vue';
import RelativeDate from './RelativeDate.vue';
import ServerTabBar from './ServerTabBar.vue';
import UiIcon from './UiIcon.vue';
import UiSelect from './UiSelect.vue';

const props = defineProps<{
  serverId?: string;
  fleetServerIds?: string[];
  fleetServerNames?: Record<string, string>;
  aiAgent?: string;
  ask?: { id: number; text: string };
}>();
const emit = defineEmits<{ aiSettings: []; useServers: [ids: string[]] }>();
const fleet = computed(() => props.fleetServerIds !== undefined);
const targetIds = computed(() => props.fleetServerIds ?? (props.serverId ? [props.serverId] : []));
const agents = ref<AgentStatus[]>([]);
const runs = ref<Investigation[]>([]);
const selected = ref<string | null>();
const drafts = ref<Record<string, string>>({});
const modelAlias = ref('medium');
const loaded = ref(false);
const refreshing = ref(false);
const sending = ref(false);
const error = ref('');
const messages = ref<HTMLElement>();
const input = ref<HTMLTextAreaElement>();
const agent = computed(() => agents.value.find(item => item.name === (props.aiAgent ?? 'codex')));
const ready = computed(() => Boolean(agent.value?.ready));
const activeRun = computed(() => runs.value.find(run => run.status === 'running'));
const running = computed(() => Boolean(activeRun.value));

type Chat = { id: string; title: string; turns: Investigation[] };
const chats = computed(() => {
  const groups = new Map<string, Chat>();
  for (const run of runs.value) {
    if (run.authoringId) continue;
    const fleetChat = run.chat?.scope === 'fleet';
    if (fleet.value ? !fleetChat : fleetChat || !props.serverId || !run.serverIds.includes(props.serverId)) continue;
    const id = run.chat?.id ?? run.id;
    let chat = groups.get(id);
    if (!chat) {
      const title = run.chat?.title ?? (run.groupId ? 'Incident group investigation' :
        run.origin === 'auto' ? 'Automatic investigation' : run.question.trim().replace(/\s+/g, ' ').slice(0, 80));
      chat = { id, title: title || 'AI chat', turns: [] };
      groups.set(id, chat);
    }
    chat.turns.push(run);
  }
  for (const chat of groups.values()) chat.turns.sort((a, b) => (a.chat?.turn ?? 1) - (b.chat?.turn ?? 1));
  return [...groups.values()].sort((a, b) => (b.turns.at(-1)?.startedAt ?? 0) - (a.turns.at(-1)?.startedAt ?? 0));
});
const current = computed(() => chats.value.find(chat => chat.id === selected.value));
const latest = computed(() => current.value?.turns.at(-1));
const readOnly = computed(() => Boolean(latest.value &&
  (latest.value.origin === 'auto' || latest.value.groupId || (!fleet.value && latest.value.serverIds.length !== 1))));
const scopeChanged = computed(() => {
  if (!fleet.value || !latest.value) return false;
  const targets = new Set(targetIds.value);
  return targets.size !== latest.value.serverIds.length || latest.value.serverIds.some(id => !targets.has(id));
});
const missingTargets = computed(() => Boolean(latest.value?.serverIds.some(id => !Object.hasOwn(props.fleetServerNames ?? {}, id))));
const targetCount = computed(() => latest.value?.serverIds.length ?? targetIds.value.length);
const validTargets = computed(() => targetIds.value.length > 0 && targetIds.value.length <= (fleet.value ? 500 : 1));
const draftKey = computed(() => selected.value ?? '');
const question = computed({
  get: () => drafts.value[draftKey.value] ?? '',
  set: value => { drafts.value[draftKey.value] = value; },
});
const canSend = computed(() => ready.value && !preview && !sending.value && !running.value &&
  !readOnly.value && !scopeChanged.value && validTargets.value && Boolean(question.value.trim()));
const labels: Record<string, string> = {
  running: 'AI is responding…', failed: 'Response interrupted', cancelled: 'Response stopped',
  interrupted: 'Response interrupted when the app closed', budget_exceeded: 'Token limit reached',
};

let unlisten: UnlistenFn | undefined;
let disposed = false;
let panelActive = true;
let pinned = true;
let revision = 0;
let selectionRevision = 0;
let refreshTask: Promise<boolean> | undefined;
let statusTimer: ReturnType<typeof setInterval> | undefined;
function refresh() {
  return refreshTask ??= loadRuns().finally(() => { refreshTask = undefined; });
}
async function loadRuns() {
  const requestedAt = revision;
  refreshing.value = true;
  try {
    const snapshot = await call<Investigation[]>('investigations');
    if (disposed) return false;
    if (requestedAt !== revision) return true;
    runs.value = snapshot;
    revision++;
    if (selected.value === undefined) selected.value = chats.value[0]?.id ?? null;
    else if (selected.value && !current.value) selected.value = null;
    return true;
  } catch (failure) {
    error.value = String(failure);
    return false;
  } finally {
    refreshing.value = false;
  }
}
async function update(id: string) {
  if (disposed) return false;
  try {
    const run = await call<Investigation>('investigation', { id });
    if (disposed) return false;
    const index = runs.value.findIndex(item => item.id === id);
    // A late streaming reply must not replace a completed run.
    if (index >= 0 && runs.value[index].status !== 'running' && run.status === 'running') return true;
    if (index >= 0) runs.value[index] = run;
    else runs.value = [run, ...runs.value].slice(0, 50);
    revision++;
    return true;
  } catch (failure) {
    error.value = String(failure);
    return false;
  }
}
function select(id: string | null) {
  selectionRevision++;
  pinned = true;
  selected.value = id;
  error.value = '';
}
function newChat() {
  delete drafts.value[''];
  select(null);
  void nextTick(() => input.value?.focus());
}
async function send() {
  if (disposed || !canSend.value) return;
  const id = current.value?.id;
  const draft = draftKey.value;
  const submitted = question.value;
  const selection = selectionRevision;
  sending.value = true;
  error.value = '';
  pinned = true;
  try {
    const runId = await call<string>(fleet.value ? 'start_console_chat' : 'start_investigation', {
      serverIds: [...targetIds.value], question: submitted.trim(), modelAlias: modelAlias.value,
      ...(id ? { chatId: id } : {}),
    });
    if (drafts.value[draft] === submitted && (selection === selectionRevision || draftKey.value !== draft)) {
      delete drafts.value[draft];
    }
    if (!await update(runId)) await refresh();
    if (selection === selectionRevision) selected.value = id ?? runId;
  } catch (failure) {
    error.value = String(failure);
    await refresh();
  } finally {
    sending.value = false;
  }
}
function composerKey(event: KeyboardEvent) {
  if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
  event.preventDefault();
  void send();
}
async function cancel() {
  const id = activeRun.value?.id;
  if (!id) return;
  try {
    await call('cancel_investigation', { id });
    await refresh();
  } catch (failure) {
    error.value = String(failure);
  }
}
function onScroll() {
  const el = messages.value;
  if (el) pinned = el.scrollHeight - el.scrollTop - el.clientHeight < 72;
}
function followLatest() {
  const el = messages.value;
  if (pinned && el) el.scrollTop = el.scrollHeight;
}
watch(() => [messages.value, selected.value, latest.value?.id, latest.value?.text, latest.value?.status],
  followLatest, { flush: 'post' });
onActivated(() => {
  panelActive = true;
  pinned = true;
  followLatest();
  if (loaded.value && !preview) visible();
});
onDeactivated(() => {
  panelActive = false;
  syncPolling();
});

let asked = 0;
watch(() => [props.ask?.id, loaded.value] as const, async () => {
  const request = props.ask;
  if (!request || request.id === asked || !loaded.value) return;
  asked = request.id;
  select(null);
  question.value = request.text;
  const selection = selectionRevision;
  if (await refresh() && selection === selectionRevision && question.value === request.text && canSend.value) {
    void send();
  }
}, { immediate: true });
watch(() => props.serverId, () => {
  drafts.value = {};
  select(chats.value[0]?.id ?? null);
});
function visible() {
  if (!document.hidden && panelActive) void refresh();
  syncPolling();
}
function syncPolling() {
  clearInterval(statusTimer);
  if (!preview && panelActive && !document.hidden && running.value) {
    statusTimer = setInterval(() => void refresh(), 3000);
  }
}
watch(running, syncPolling);
onMounted(async () => {
  document.addEventListener('visibilitychange', visible);
  try {
    if (!preview) {
      void listen<string>('investigation-changed', event => {
        if (panelActive && !document.hidden) void update(event.payload);
      }).then(off => {
        if (disposed) off();
        else unlisten = off;
      }).catch(() => {});
    }
    await Promise.all([refresh(), call<AgentStatus[]>('detect_agents').then(result => { agents.value = result; })]);
  } catch (failure) {
    error.value = String(failure);
  } finally {
    loaded.value = true;
  }
});
onUnmounted(() => {
  disposed = true;
  clearInterval(statusTimer);
  document.removeEventListener('visibilitychange', visible);
  unlisten?.();
});
</script>

<template>
  <section class="investigation" aria-label="AI chats">
    <template v-if="loaded && ready">
      <ServerTabBar title="AI chats">
        <span v-if="fleet">Servers · {{ targetCount }}</span>
        <RelativeDate v-if="latest" :at="latest.endedAt ?? latest.startedAt"/>
        <span v-else>New chat</span>
      </ServerTabBar>
      <div class="chat-layout">
        <aside class="sidebar">
          <button type="button" class="new-chat" :disabled="sending" @click="newChat"><UiIcon name="plus" :size="15"/>New chat</button>
          <nav class="chat-list" aria-label="Chat history">
            <button v-for="chat in chats" :key="chat.id" type="button" class="chat-link" :disabled="sending"
              :aria-current="selected===chat.id ? 'true' : undefined" :title="chat.title" @click="select(chat.id)">
              {{ chat.title }}<small v-if="fleet" class="chat-count">{{ chat.turns[0]?.serverIds.length }}</small>
            </button>
            <p v-if="!chats.length" class="empty-list">Your chats will appear here.</p>
          </nav>
        </aside>

        <div class="conversation">
          <div ref="messages" class="messages" aria-label="Conversation" @scroll.passive="onScroll">
            <div v-if="!current" class="welcome">
              <h3>{{ fleet ? 'How can I help with these servers?' : 'How can I help with this server?' }}</h3>
              <p>{{ fleet ? 'Ask a question about the selected servers or describe the task.' : 'Ask a question about the status of the server or describe the task.' }}</p>
            </div>
            <div v-else class="transcript">
              <article v-for="turn in current.turns" :key="turn.id" class="exchange">
                <p class="user-message" aria-label="Your message">{{ readOnly ? current.title : turn.question }}</p>
                <div class="assistant-message">
                  <div class="speaker">
                    <strong>{{ turn.agent === 'claude' ? 'Claude Code' : 'Codex' }}</strong>
                    <details v-if="turn.audit.length || turn.modelProfile || turn.usage" class="turn-details">
                      <summary aria-label="Response details" title="Response details"><UiIcon name="info" :size="14"/></summary>
                      <div class="turn-details-panel">
                        <p v-if="turn.modelProfile">{{ turn.modelProfile.alias }} · {{ turn.actualModel ?? turn.modelProfile.primary.model }}</p>
                        <ul v-if="turn.audit.length"><li v-for="(item, i) in turn.audit" :key="i"><code>{{ item.tool }}</code> · {{ item.ok ? 'Succeeded' : 'Failed' }}</li></ul>
                        <pre v-if="turn.usage && Object.keys(turn.usage).length">{{ JSON.stringify(turn.usage, null, 2) }}</pre>
                        <p v-if="!turn.usageComplete">The CLI reported incomplete token usage.</p>
                      </div>
                    </details>
                  </div>
                  <MarkdownReply v-if="turn.text" :text="turn.text"/>
                  <p v-if="labels[turn.status]" class="reply-status" role="status">{{ labels[turn.status] }}</p>
                  <p v-if="turn.error" class="error">{{ turn.error }}</p>
                  <ActionApprovals :run-id="turn.id" :server-id="serverId" compact/>
                </div>
              </article>
            </div>
          </div>
          <div class="composer-area">
            <div v-if="scopeChanged" class="scope-note">
              <span>{{ missingTargets ? 'Some servers in this chat are no longer available. Start a new chat.' : 'This chat uses a different set of servers.' }}</span>
              <button v-if="!missingTargets" type="button" :disabled="sending"
                @click="latest && emit('useServers', [...latest.serverIds])">Use servers from this chat</button>
            </div>
            <p v-else-if="fleet && !validTargets" class="busy-note">Choose from 1 to 500 servers.</p>
            <p v-if="error" class="error" role="alert">{{ error }}</p>
            <form v-if="!readOnly" class="composer" @submit.prevent="send">
              <textarea ref="input" v-model="question" rows="2" maxlength="4000" :disabled="sending || scopeChanged || !validTargets"
                placeholder="Write a message" aria-label="Message to AI" @keydown="composerKey"/>
              <div class="composer-actions">
                <UiSelect v-model="modelAlias" compact aria-label="Model" :disabled="sending||running">
                  <option value="low">low</option><option value="medium">medium</option><option value="high">high</option>
                </UiSelect>
                <button v-if="latest?.status==='running'" type="button" @click="cancel">Stop it</button>
                <button v-else type="submit" class="primary" :disabled="!canSend">Send message</button>
              </div>
              <div v-if="running && activeRun?.id!==latest?.id" class="scope-note busy-session">
                <span>The agent is busy with another task. Send your draft when that task finishes.</span>
                <button type="button" @click="cancel">Stop current task</button>
              </div>
            </form>
            <div v-else-if="running" class="read-only-actions"><button type="button" @click="cancel">Stop it</button></div>
          </div>
        </div>
      </div>
    </template>
    <div v-else class="setup">
      <template v-if="!loaded"><p role="status">Checking AI settings…</p></template>
      <template v-else>
        <h3>Set up an AI agent</h3>
        <p>{{ agent?.reason || error || 'Select and configure an agent to start a chat.' }}</p>
        <button type="button" class="primary" @click="emit('aiSettings')">Open AI settings</button>
      </template>
    </div>
  </section>
</template>

<style scoped>
.investigation{display:flex;flex-direction:column;flex:1;min-height:0;min-width:0}
.chat-layout{display:grid;grid-template-columns:clamp(142px,24%,220px) minmax(0,1fr);flex:1;min-height:0;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--surface)}
.sidebar{min-width:0;min-height:0;display:flex;flex-direction:column;gap:10px;padding:10px;background:var(--subtle);border-right:1px solid var(--line)}
button{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:7px 10px;cursor:pointer}
button:hover:enabled{background:var(--hover)}
button:disabled{opacity:.5;cursor:default}
button:focus-visible,summary:focus-visible,textarea:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.new-chat{display:flex;align-items:center;gap:7px;justify-content:center;font-weight:600;white-space:nowrap}
.chat-list{min-height:0;overflow:auto;display:flex;flex-direction:column;gap:2px}
.chat-link{width:100%;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-color:transparent;background:none}
.chat-link[aria-current=true]{background:var(--hover);color:var(--text);font-weight:600}
.chat-count{margin-left:6px;color:var(--muted);font-weight:400}
.scope-note{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 8px;color:var(--muted);font-size:12px}
.empty-list{margin:2px 8px;color:var(--muted);font-size:12px}
.conversation{min-width:0;min-height:0;display:flex;flex-direction:column}
.messages{flex:1;min-height:0;overflow:auto;scrollbar-color:var(--line-strong) transparent}
.welcome,.setup{display:grid;justify-items:center;align-content:center;text-align:center;padding:24px;min-height:180px}
.welcome{height:100%;box-sizing:border-box}
.setup{flex:1}
.welcome h3,.setup h3{margin:0;font-size:19px;font-weight:600}
.welcome p,.setup p{margin:8px 0;color:var(--muted)}
.setup button{margin-top:10px}
.transcript{width:min(100%,760px);box-sizing:border-box;margin-inline:auto;padding:22px clamp(14px,3vw,30px)}
.exchange{display:flex;flex-direction:column;gap:18px;margin-bottom:26px}
.user-message{align-self:flex-end;max-width:85%;margin:0;padding:9px 13px;border-radius:14px;background:var(--subtle);white-space:pre-wrap;overflow-wrap:anywhere}
.assistant-message{min-width:0;overflow-wrap:anywhere}
.speaker{display:grid;grid-template-columns:max-content minmax(0,1fr);align-items:start;gap:4px;margin-bottom:6px;font-size:12px;line-height:20px;color:var(--muted)}
.speaker strong{font-weight:600}
.reply-status{color:var(--muted);font-size:12px;margin:8px 0 0}
.turn-details summary{display:grid;place-items:center;width:20px;height:20px;list-style:none;border-radius:4px;cursor:pointer}
.turn-details summary::-webkit-details-marker{display:none}
.turn-details summary:hover,.turn-details[open] summary{background:var(--hover);color:var(--text)}
.turn-details-panel{width:fit-content;max-width:100%;box-sizing:border-box;margin:4px 0;padding:8px 10px;border:1px solid var(--line);border-radius:7px;background:var(--subtle)}
.turn-details-panel > *{margin:0}
.turn-details-panel > * + *{margin-top:6px}
.turn-details-panel ul{padding-inline-start:16px}
.turn-details pre{white-space:pre-wrap}
.composer-area{width:min(100%,760px);box-sizing:border-box;margin-inline:auto;padding:8px clamp(10px,2vw,20px) 14px}
.composer{padding:9px 10px;border:1px solid var(--line-strong);border-radius:14px;background:var(--surface)}
.composer textarea{display:block;width:100%;box-sizing:border-box;padding:4px 5px;border:0;background:none;resize:vertical;max-height:150px;color:var(--text);font:inherit;line-height:1.55}
.composer textarea::placeholder{color:var(--muted)}
.composer-actions{display:flex;justify-content:space-between;align-items:center;gap:8px;padding-top:5px}
.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.primary:hover:enabled{background:var(--accent);filter:brightness(1.08)}
.busy-note{display:block;color:var(--muted);margin:4px 0}
.busy-session{margin:8px 0 0}
.error{background:var(--danger-bg);color:var(--danger);padding:8px 10px;border-radius:7px;overflow-wrap:anywhere}
.read-only-actions{text-align:right}
@media(max-width:520px){.chat-layout{grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr)}.sidebar{flex-direction:row;border-right:0;border-bottom:1px solid var(--line)}.chat-list{flex:1;flex-direction:row;align-items:center}.chat-link{width:auto;max-width:150px;flex-shrink:0}.empty-list{white-space:nowrap}}
</style>
