<script setup lang="ts">
import UiInput from './UiInput.vue';
import { useSettingsAutosave } from '../useSettingsAutosave';
import { automationBudgetError } from '../automationSettings';
import type { Settings } from '../types';

const props = defineProps<{ settings: Settings }>();
const open = defineModel<boolean>('open', { default: false });
const emit = defineEmits<{ saved: [settings: Settings] }>();
const fields = ['dailyTokenLimit', 'dailyRunLimit', 'runTokenLimit'] as const;
const { draft, saving, error, edited, flush } = useSettingsAutosave(
  () => ({
    ...props.settings,
    dailyTokenLimit: props.settings.dailyTokenLimit ?? 0,
    dailyRunLimit: props.settings.dailyRunLimit ?? 0,
  }),
  fields,
  (draft, dirty, current) => {
    const patch: Partial<Settings> = {};
    for (const field of dirty) patch[field] = String(draft[field]) === '' ? NaN : Number(draft[field]);
    const error = automationBudgetError({ ...current, ...patch }) ?? '';
    return { patch: error ? {} : patch, error };
  },
  settings => emit('saved', settings),
);
</script>

<template>
  <details :open="open" @toggle="open = ($event.currentTarget as HTMLDetailsElement).open">
    <summary>Limits</summary>
    <form novalidate :aria-busy="saving" @submit.prevent="flush">
      <p>Limits apply to manual and automatic runs. Set a limit to 0 to disable it.</p>
      <div class="fields">
        <label>Tokens per day<UiInput v-model.number="draft.dailyTokenLimit" data-test="daily-tokens" type="number" min="0" max="1000000000" style="--field-width:140px" @input="edited('dailyTokenLimit')" @blur="flush"/></label>
        <label>Runs per day<UiInput v-model.number="draft.dailyRunLimit" data-test="daily-runs" type="number" min="0" max="1000" @input="edited('dailyRunLimit')" @blur="flush"/></label>
      </div>
      <label>Tokens per run<UiInput v-model.number="draft.runTokenLimit" data-test="run-tokens" type="number" style="--field-width:140px" @input="edited('runTokenLimit')" @blur="flush"/></label>
      <p v-if="saving" role="status">Saving…</p>
      <p v-if="error" class="error" role="alert">{{ error }}</p>
    </form>
  </details>
</template>

<style scoped>
details { border-top: 1px solid var(--line); }
summary { cursor: pointer; padding: 10px 0; font-weight: 550; }
form { display: grid; gap: 14px; padding: 0 0 18px; font-size: 12px; }
label { display: flex; flex-direction: column; gap: 6px; }
.fields { display: flex; flex-wrap: wrap; gap: 14px 24px; }
p { line-height: 1.6; color: var(--muted); margin: 0; }
.error { color: var(--danger); background: var(--danger-bg); padding: 10px; border-radius: 6px; overflow-wrap: anywhere; }
summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
</style>
