<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue';
import type { Server } from '../types';
import ConsoleServerPicker from './ConsoleServerPicker.vue';
import ConsoleCommands from './ConsoleCommands.vue';
import InvestigationPanel from './InvestigationPanel.vue';

const props = defineProps<{ servers: Server[]; aiAgent?: string }>();
const emit = defineEmits<{ aiSettings: [] }>();
const selection = defineModel<string[] | null>({ required: true });
const tab = ref<'console' | 'ai'>('console');
const openedChat = ref(false);
const tabs = ref<HTMLElement>();
const names = computed(() => Object.fromEntries(props.servers.map(server => [server.id, server.name])));
function selectTab(next: 'console' | 'ai') {
  tab.value = next;
  if (next === 'ai') openedChat.value = true;
}
async function switchTab(event: KeyboardEvent) {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  event.preventDefault();
  selectTab(event.key === 'Home' ? 'console' : event.key === 'End' ? 'ai' : tab.value === 'console' ? 'ai' : 'console');
  await nextTick();
  tabs.value?.querySelector<HTMLElement>('[aria-selected=true]')?.focus();
}
const ids = computed(() => {
  if (selection.value === null) return props.servers.map(server => server.id);
  const present = new Set(props.servers.map(server => server.id));
  return selection.value.filter(id => present.has(id));
});
watch(() => props.servers, () => {
  if (selection.value !== null && ids.value.length !== selection.value.length) selection.value = ids.value;
});
</script>

<template>
  <section class="console-page">
    <ConsoleServerPicker v-model="selection" :servers="servers"/>
    <div ref="tabs" class="tabs" role="tablist" aria-label="Console mode" @keydown="switchTab">
      <button id="console-commands-tab" type="button" role="tab" aria-controls="console-commands-panel"
        :aria-selected="tab === 'console'" :tabindex="tab === 'console' ? 0 : -1" @click="selectTab('console')">Console</button>
      <button id="console-ai-tab" type="button" role="tab" aria-controls="console-ai-panel"
        :aria-selected="tab === 'ai'" :tabindex="tab === 'ai' ? 0 : -1" @click="selectTab('ai')">Conversations</button>
    </div>
    <div v-show="tab === 'console'" id="console-commands-panel" role="tabpanel" aria-labelledby="console-commands-tab">
      <ConsoleCommands :ids="ids" :all="selection === null" :active="tab === 'console'"/>
    </div>
    <div v-show="tab === 'ai'" id="console-ai-panel" class="chat" role="tabpanel" aria-labelledby="console-ai-tab">
      <InvestigationPanel v-if="openedChat" :fleet-server-ids="ids" :fleet-server-names="names" :ai-agent="aiAgent"
        @use-servers="selection = $event" @ai-settings="emit('aiSettings')"/>
    </div>
  </section>
</template>

<style scoped>
.console-page { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr); align-content: start; gap: 12px; padding-bottom: 18px; }
.tabs { display: flex; gap: 16px; border-bottom: 1px solid var(--line); }
.tabs button { border: none; border-bottom: 2px solid transparent; background: transparent; color: var(--muted); font: inherit; padding: 6px 2px 8px; cursor: pointer; }
.tabs button[aria-selected=true] { border-color: var(--accent); color: var(--text); }
.tabs button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.chat { display: flex; min-width: 0; height: max(420px, calc(100vh - 216px)); }
</style>
