<script setup lang="ts">
import RefreshButton from './RefreshButton.vue';

defineProps<{ title?: string; busy?: boolean; disabled?: boolean }>();
defineEmits<{ refresh: [] }>();
</script>

<template>
  <header class="tab-bar">
    <div class="meta"><h3 v-if="title" :title="title">{{ title }}</h3><slot /></div>
    <div class="tab-actions">
      <slot name="actions" />
      <slot name="refresh">
        <RefreshButton :disabled="disabled || busy" :aria-busy="busy || undefined" @click="$emit('refresh')">
          {{ busy ? 'Update…' : 'Refresh' }}
        </RefreshButton>
      </slot>
    </div>
  </header>
</template>

<style scoped>
.tab-bar{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:34px;margin-bottom:16px}
.meta{display:flex;align-items:center;gap:8px;min-width:0;overflow:hidden;padding:3px 2px;margin:-3px -2px;white-space:nowrap;font-size:12px;color:var(--muted)}
.meta h3{min-width:0;overflow:hidden;text-overflow:ellipsis;color:var(--text);font-size:inherit;font-weight:600;margin:0}
.tab-actions{display:flex;align-items:center;gap:6px;flex-shrink:0;margin-left:auto}
.refresh-button{min-height:34px;padding:6px 11px;font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;white-space:nowrap;cursor:pointer}
.refresh-button:hover:enabled{background:var(--hover)}
.refresh-button:disabled{opacity:.5;cursor:default}
.refresh-button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
</style>
