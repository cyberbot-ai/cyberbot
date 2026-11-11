<script setup lang="ts">
import type { ActionReview } from '../types';
import UiIcon from './UiIcon.vue';

defineProps<{ verdict: ActionReview['verdict'] }>();
</script>

<template>
  <div class="risk-warning">
    <UiIcon name="incident" :size="16"/>
    <div>
      <strong>One-time approval required</strong>
      <p v-if="verdict.decision === 'uncertain'">Cyberbot could not assess this command.</p>
      <p>{{ verdict.explanation }}</p>
      <ul v-if="verdict.effects.length">
        <li v-for="(effect, index) in verdict.effects" :key="index">{{ effect }}</li>
      </ul>
    </div>
  </div>
</template>

<style scoped>
.risk-warning {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 10px 12px;
  border-radius: 7px;
  background: var(--danger-bg);
  color: var(--danger);
  font-size: 12px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.risk-warning svg { flex: none; margin-top: 1px; }
.risk-warning p { margin: 4px 0 0; }
.risk-warning ul { margin: 4px 0 0; padding-inline-start: 16px; }
</style>
