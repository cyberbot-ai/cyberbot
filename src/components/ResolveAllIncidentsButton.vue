<script setup lang="ts">
import { computed, ref } from 'vue';
import { call, preview } from '../api';
import type { Incident } from '../types';
import UiIcon from './UiIcon.vue';

const props = defineProps<{ incidents: Incident[]; title: string }>();
const emit = defineEmits<{ updated: []; error: [message: string] }>();
const open = computed(() => props.incidents.filter(incident => incident.status === 'open'));
const busy = ref(false);

async function resolveAll() {
  if (busy.value || preview || !open.value.length) return;
  const episodes = open.value.map(incident => ({
    id: incident.id,
    episode: incident.episode || `${incident.id}:${incident.openedAt}`,
  }));
  busy.value = true;
  try {
    await call('resolve_incidents', { episodes });
  } catch (error) {
    emit('error', `Failed to mark all incidents resolved. ${String(error).replace(/^Error: /, '')}`);
  } finally {
    emit('updated');
    busy.value = false;
  }
}
</script>

<template>
  <button v-if="open.length || busy" type="button" class="resolve-all" :disabled="busy || preview"
    :aria-busy="busy" :title="title" @click="resolveAll">
    <UiIcon name="resolve" :size="16" />{{ busy ? 'Resolving…' : 'Mark all resolved' }}
  </button>
</template>

<style scoped>
.resolve-all{display:inline-flex;align-items:center;gap:7px;min-height:34px;padding:6px 11px;border:1px solid var(--line);border-radius:7px;background:var(--surface);color:var(--text);font:inherit;white-space:nowrap;cursor:pointer}
.resolve-all:hover:enabled{background:var(--hover)}.resolve-all:disabled{opacity:.45;cursor:default}.resolve-all:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
</style>
