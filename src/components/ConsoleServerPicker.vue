<script setup lang="ts">
import ServerLink from './ServerLink.vue';
import { serverAddress, serverDisplayHost, serverHint } from '../serverDirectory';
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import type { Server } from '../types';
import UiIcon from './UiIcon.vue';

const props = defineProps<{ servers: Server[] }>();
const selection = defineModel<string[] | null>({ required: true });
const opened = ref(false);
const query = ref('');
const active = ref(-1);
const root = ref<HTMLElement>();
const trigger = ref<HTMLButtonElement>();
const input = ref<HTMLInputElement>();
let anchor: string | undefined;

const sorted = computed(() => [...props.servers].sort((a, b) =>
  serverDisplayHost(a.name, a.endpoint.host).localeCompare(serverDisplayHost(b.name, b.endpoint.host), 'en-US', { numeric: true })
  || a.id.localeCompare(b.id)));
const selected = computed(() => new Set(selection.value ?? []));
const chosen = computed(() => sorted.value.filter(server => selected.value.has(server.id)));
const matches = computed(() => {
  const term = query.value.trim().toLowerCase();
  return sorted.value.filter(server =>
    [server.name, server.endpoint.host].some(value => value.toLowerCase().includes(term)));
});
watch(query, () => {
  active.value = -1;
  anchor = undefined;
});

async function togglePicker() {
  if (opened.value) return close(true);
  query.value = '';
  active.value = -1;
  anchor = undefined;
  opened.value = true;
  await nextTick();
  input.value?.focus();
}
function close(focus: boolean) {
  opened.value = false;
  if (focus) trigger.value?.focus();
}
function outside(event: MouseEvent) {
  if (opened.value && !root.value?.contains(event.target as Node)) close(false);
}
onMounted(() => document.addEventListener('mousedown', outside));
onBeforeUnmount(() => document.removeEventListener('mousedown', outside));

function mark(server: Server, extend: boolean) {
  const next = new Set(selected.value);
  const index = matches.value.findIndex(item => item.id === server.id);
  const from = anchor ? matches.value.findIndex(item => item.id === anchor) : -1;
  if (extend && from >= 0) {
    for (const item of matches.value.slice(Math.min(from, index), Math.max(from, index) + 1)) {
      next.add(item.id);
    }
  } else {
    if (next.has(server.id)) next.delete(server.id);
    else next.add(server.id);
    anchor = server.id;
  }
  selection.value = [...next];
  active.value = index;
}
function addMatches() {
  selection.value = [...new Set([...selected.value, ...matches.value.map(server => server.id)])];
}
function useAll() {
  selection.value = null;
  close(true);
}
async function searchKey(event: KeyboardEvent) {
  if (event.isComposing) return;
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    if (!matches.value.length) return;
    event.preventDefault();
    const step = event.key === 'ArrowDown' ? 1 : -1;
    active.value = active.value < 0 && step < 0 ? matches.value.length - 1
      : Math.max(0, Math.min(matches.value.length - 1, active.value + step));
    await nextTick();
    root.value?.querySelector('[data-active=true]')?.scrollIntoView?.({ block: 'nearest' });
    return;
  }
  const server = matches.value[active.value];
  if ((event.key === ' ' || event.key === 'Enter') && server) {
    event.preventDefault();
    mark(server, event.shiftKey);
  }
}
</script>

<template>
  <div ref="root" class="picker" @keydown.esc.stop.prevent="close(true)">
    <button ref="trigger" class="trigger" type="button" aria-label="Server selection"
      :aria-expanded="opened" aria-controls="console-server-picker" @click="togglePicker">
      <UiIcon name="servers" :size="15"/>
      {{ selection === null ? 'All servers' : chosen.length ? `Servers · ${chosen.length}` : 'Select servers' }}
      <UiIcon class="chevron" name="chevron" :size="13"/>
    </button>
    <span v-if="chosen.length" class="selection">
      <ServerLink v-for="server in chosen.slice(0, 3)" :key="server.id" class="chip" :id="server.id" :name="server.name" :address="serverAddress(server.endpoint)"/>
      <span v-if="chosen.length > 3" class="count">+{{ chosen.length - 3 }}</span>
    </span>
    <div v-if="opened" id="console-server-picker" class="popover">
      <label class="search">
        <UiIcon name="search" :size="15"/>
        <input ref="input" v-model="query" type="search" role="combobox" aria-label="Find a server"
          placeholder="Name or address" aria-expanded="true" aria-autocomplete="list"
          aria-controls="console-server-options" autocomplete="off"
          :aria-activedescendant="matches[active] ? `console-target-${active}` : undefined" @keydown="searchKey">
      </label>
      <div class="actions">
        <button type="button" :disabled="!matches.length" @click="addMatches">Select matching servers · {{ matches.length }}</button>
        <button type="button" @click="useAll">All servers</button>
      </div>
      <div id="console-server-options" class="options" role="listbox" aria-label="Servers" aria-multiselectable="true">
        <div v-for="(server, index) in matches" :id="`console-target-${index}`" :key="server.id"
          class="option" role="option" :aria-selected="selected.has(server.id)" :data-active="active === index"
          @mousedown.prevent @click="mark(server, $event.shiftKey)">
          <span class="tick" aria-hidden="true"><UiIcon v-if="selected.has(server.id)" name="check" :size="12"/></span>
          <span class="name" :title="serverHint(server)">{{ serverDisplayHost(server.name, server.endpoint.host) }}</span>
        </div>
        <p v-if="!matches.length" class="nothing">No servers found</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.picker { position: relative; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; min-width: 0; }
button { font: inherit; color: var(--text); cursor: pointer; }
.trigger { display: inline-flex; align-items: center; gap: 8px; flex: none; padding: 7px 9px; border: 1px solid var(--line); border-radius: 6px; background: var(--surface); }
.chevron { transform: rotate(90deg); color: var(--muted); }
.selection { display: flex; align-items: center; gap: 5px; overflow: hidden; min-width: 0; max-width: 100%; }
.chip { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; background: var(--subtle); padding: 3px 6px; border-radius: 4px; min-width: 0; }
.count, .nothing { color: var(--muted); }
.count { flex: none; }
.popover { position: absolute; z-index: 4; top: calc(100% + 5px); left: 0; box-sizing: border-box; width: min(410px, 100%); background: var(--surface); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); padding: 7px; }
.search { display: flex; align-items: center; gap: 7px; padding: 6px 8px; border: 1px solid var(--line); border-radius: 5px; color: var(--muted); }
.search:focus-within { border-color: var(--accent); }
.search input { flex: 1; min-width: 0; font: inherit; color: var(--text); background: transparent; border: none; outline: none; }
.actions { display: flex; flex-wrap: wrap; gap: 5px; justify-content: space-between; margin: 5px 0; }
.actions button { background: transparent; border: none; border-radius: 4px; padding: 5px 7px; color: var(--accent); }
.actions button:hover:not(:disabled), .option:hover, .option[data-active=true] { background: var(--hover); }
.actions button:disabled { color: var(--muted); cursor: default; }
.options { max-height: min(330px, 45vh); overflow: auto; overscroll-behavior: contain; }
.option { display: flex; align-items: center; gap: 8px; padding: 5px 7px; min-height: 27px; border-radius: 4px; cursor: pointer; user-select: none; }
.tick { width: 15px; height: 15px; border: 1px solid var(--line-strong); border-radius: 3px; display: grid; place-items: center; flex: none; }
.option[aria-selected=true] .tick { background: var(--accent); color: var(--on-accent); border-color: var(--accent); }
.name { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.nothing { padding-inline: 7px; }
</style>
