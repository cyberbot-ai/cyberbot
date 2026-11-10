<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <header class="tab-bar">
    <div class="meta"><h3 v-if="title" :title="title">{{ title }}</h3><slot /></div>
    <div class="tab-actions">
      <slot name="actions" />
    </div>
  </header>
</template>

<style scoped>
.tab-bar{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:34px;margin-bottom:16px}
.meta{display:flex;align-items:center;gap:8px;min-width:0;overflow:hidden;padding:3px 2px;margin:-3px -2px;white-space:nowrap;font-size:12px;color:var(--muted)}
.meta h3{min-width:0;overflow:hidden;text-overflow:ellipsis;color:var(--text);font-size:inherit;font-weight:600;margin:0}
.tab-actions{display:flex;align-items:center;gap:6px;flex-shrink:0;margin-left:auto}
</style>
