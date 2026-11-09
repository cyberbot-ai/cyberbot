<script setup lang="ts">
import UiInput from './UiInput.vue';
import { computed, reactive, ref, watch } from 'vue';
import { call, preview } from '../api';
import { serverDisplayHost } from '../serverDirectory';
import type { ServerDependencies } from '../types';

const props = defineProps<{ serverId: string }>();
type Editor = ServerDependencies & {
  id: string; loading: boolean; saving: boolean; loadError: string; saveError: string;
  revision: number; storedRevision: number; failedRevision: number;
};
const editor = ref<Editor>();
const search = ref('');
const visible = computed(() => {
  const query = search.value.trim().toLocaleLowerCase();
  return editor.value?.available.filter(s => [s.host, s.name].some(value => value?.toLocaleLowerCase().includes(query))) ?? [];
});
const message = (e: unknown) => String(e).replace(/^Error: /, '');
const displayHost = ({ name, host }: ServerDependencies['available'][number]) => serverDisplayHost(name, host ?? name);

async function load(id: string) {
  const current = reactive<Editor>({ id, available: [], dependsOn: [], loading: true, saving: false,
    loadError: '', saveError: '', revision: 0, storedRevision: 0, failedRevision: -1 });
  editor.value = current;
  search.value = '';
  try {
    const result = await call<ServerDependencies>('server_dependencies', { id });
    const selected = new Set(result.dependsOn);
    // Show existing links first on load; toggling a checkbox never moves its row.
    current.available = result.available.filter(s => s.id !== id).sort((a, b) =>
      Number(selected.has(b.id)) - Number(selected.has(a.id)) || displayHost(a).localeCompare(displayHost(b), 'en-US', { numeric: true }));
    const allowed = new Set(current.available.map(s => s.id));
    current.dependsOn = [...new Set(result.dependsOn.filter(id => allowed.has(id)))];
  } catch (e) { current.loadError = message(e); }
  finally { current.loading = false; }
}
watch(() => props.serverId, id => { void load(id); }, { immediate: true });

function toggle(id: string, checked: boolean) {
  const current = editor.value;
  if (!current || preview || current.loading || current.loadError || !current.available.some(s => s.id === id)) return;
  if (checked) {
    if (current.dependsOn.includes(id) || current.dependsOn.length >= 64) return;
    current.dependsOn = [...current.dependsOn, id];
  } else current.dependsOn = current.dependsOn.filter(selected => selected !== id);
  current.revision++;
  current.saveError = '';
  void persist(current);
}

async function persist(current: Editor) {
  if (preview || current.saving || current.loading || current.loadError || current.revision === current.storedRevision || current.revision === current.failedRevision) return;
  const revision = current.revision;
  const dependsOn = [...current.dependsOn];
  current.saving = true;
  current.saveError = '';
  try {
    await call('save_server_dependencies', { id: current.id, dependsOn });
    current.storedRevision = revision;
  } catch (e) {
    current.failedRevision = revision;
    current.saveError = message(e);
  } finally {
    current.saving = false;
    // Drain newer selections, also after the panel closes. Every request keeps its original server ID.
    if (current.revision !== revision) void persist(current);
  }
}
function retry() {
  if (!editor.value) return;
  editor.value.failedRevision = -1;
  void persist(editor.value);
}
</script>

<template>
  <section class="dependencies" :aria-busy="editor?.loading || editor?.saving">
    <p class="description">Select the servers this server depends on.</p>
    <p v-if="editor?.loading" role="status">Loading servers…</p>
    <div v-else-if="editor?.loadError" class="error" role="alert">
      <p>Could not load dependencies: {{ editor.loadError }}</p>
      <button type="button" @click="load(serverId)">Retry</button>
    </div>
    <template v-else-if="editor">
      <template v-if="editor.available.length">
        <UiInput v-model="search" class="search" type="search" aria-label="Find a server" placeholder="Find the server" maxlength="200"/>
        <div class="server-list" role="group" aria-label="Servers this server depends on">
          <label v-for="server in visible" :key="server.id" class="server-option" :class="{ selected: editor.dependsOn.includes(server.id) }">
            <input type="checkbox" :value="server.id" :checked="editor.dependsOn.includes(server.id)"
              :disabled="preview || (!editor.dependsOn.includes(server.id) && editor.dependsOn.length >= 64)"
              @change="toggle(server.id, ($event.target as HTMLInputElement).checked)">
            <span :title="[server.name, server.address].filter(Boolean).join(' · ')">{{ displayHost(server) }}</span>
          </label>
          <p v-if="!visible.length" class="empty">No servers found.</p>
        </div>
        <p v-if="editor.dependsOn.length >= 64" class="limit">Select up to 64 servers. Deselect one to add another.</p>
        <div v-if="editor.saveError" class="error" role="alert">
          <p>Unsaved dependencies: {{ editor.saveError }}</p>
          <button type="button" @click="retry">Retry</button>
        </div>
        <p v-else class="status" role="status">{{ preview ? 'Edit dependencies in the desktop app.' : editor.saving ? 'Saving…' : editor.storedRevision > 0 ? 'Save' : 'Changes are saved automatically.' }}</p>
      </template>
      <p v-else class="empty">Add another server to configure dependencies.</p>
    </template>
  </section>
</template>

<style scoped>
.dependencies{min-width:0;max-width:520px;font-size:12px;line-height:1.6}.description{margin:10px 0 12px;color:var(--muted)}.search{--field-width:100%;margin-bottom:8px}.server-list{max-height:240px;overflow:auto;overscroll-behavior:contain;border:1px solid var(--line);border-radius:7px;padding:3px;scrollbar-color:var(--line-strong) transparent}.server-option{display:flex;align-items:center;gap:9px;min-width:0;padding:7px 8px;border-radius:4px;cursor:pointer;color:var(--text)}.server-option:hover{background:var(--hover)}.server-option.selected{background:var(--accent-bg)}.server-option input{flex:0 0 auto;width:15px;height:15px;min-height:0;margin:0;padding:0;accent-color:var(--accent);cursor:inherit}.server-option span{min-width:0;overflow-wrap:anywhere}.empty{margin:10px 8px;color:var(--muted)}.status{min-height:20px;margin:8px 0 0;color:var(--muted);font-size:11px}.limit{color:var(--muted);margin:8px 0}.error{color:var(--danger);margin-top:8px;overflow-wrap:anywhere}.error p{margin:0 0 6px}.error button{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:6px 10px;cursor:pointer}.server-option input:focus-visible,.error button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.server-option input:disabled{cursor:default;opacity:.5}
</style>
