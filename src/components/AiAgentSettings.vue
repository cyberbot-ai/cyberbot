<script setup lang="ts">
import UiSelect from './UiSelect.vue';
import {useSettingsAutosave} from '../useSettingsAutosave';
import type {Settings} from '../types';
const props=defineProps<{settings:Settings}>();
const emit=defineEmits<{saved:[settings:Settings]}>();
const {draft,saving,error,edited,flush}=useSettingsAutosave(()=>props.settings,['autoAgent'],draft=>({patch:{autoAgent:draft.autoAgent},error:''}),settings=>emit('saved',settings));
</script>
<template>
<section class="agent-choice">
  <h2>Agent provider</h2>
  <div class="agent-choice-row">
    <label>AI agent<UiSelect v-model="draft.autoAgent" aria-label="AI agent" @change="edited('autoAgent')" @blur="flush"><option value="codex">Codex</option><option value="claude">Claude Code</option></UiSelect></label>
    <p>The selected agent handles chats, automatic investigations, check authoring, and risk reviews. Runs already in progress continue with their current agent.</p>
  </div>
  <p v-if="saving" role="status">Saving…</p><p v-if="error" class="error" role="alert">{{error}}</p>
</section>
</template>
<style scoped>
.agent-choice { margin: 0 0 14px; }
h2 { font-size: 16px; font-weight: 600; margin: 0 0 10px; }
.agent-choice-row { display: flex; align-items: end; flex-wrap: wrap; gap: 8px 18px; }
label { display: flex; flex-direction: column; gap: 5px; font-size: 12px; }
p { font-size: 12px; line-height: 1.6; color: var(--muted); max-width: 70ch; }
.agent-choice-row p { flex: 1 1 250px; margin: 0; }
.error { color: var(--danger); overflow-wrap: anywhere; }
</style>
