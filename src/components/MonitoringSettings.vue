<script setup lang="ts">
import UiInput from './UiInput.vue';
import { computed } from 'vue';
import { useSettingsAutosave } from '../useSettingsAutosave';
import type { Settings } from '../types';

const props = defineProps<{ settings: Settings }>();
const emit = defineEmits<{ saved: [settings: Settings] }>();
const fields = ['pollSeconds', 'logPollSeconds', 'concurrency', 'connectivityProbe'] as const;
const defaultProbe = { host: 'cloudflare-dns.com', backupHost: 'www.microsoft.com' };
const ranges = { pollSeconds: [30, 86400], logPollSeconds: [60, 86400], concurrency: [1, 16] } as const;
const names = { pollSeconds: 'Server polling', logPollSeconds: 'Log analysis', concurrency: 'Concurrent SSH connections' };
const { draft, saving, error, edited, flush } = useSettingsAutosave(
  () => props.settings, fields, (draft, dirty) => {
    const patch: Partial<Settings> = {}, errors: string[] = [];
    for (const field of dirty) {
      if (field === 'connectivityProbe') {
        const probe = draft.connectivityProbe ?? defaultProbe;
        const host = probe.host.trim();
        if (host) patch.connectivityProbe = { host, backupHost: probe.backupHost?.trim() || null };
        else errors.push('Enter the primary probe host.');
        continue;
      }
      const value = draft[field], [min, max] = ranges[field];
      if (!Number.isSafeInteger(value) || value < min || value > max) errors.push(`${names[field]}: enter an integer from ${min} to ${max}.`);
      else patch[field] = value;
    }
    return { patch, error: errors.join(' ') };
  }, settings => emit('saved', settings),
);
const probeHost = computed({
  get: () => (draft.connectivityProbe ?? defaultProbe).host,
  set: host => {
    draft.connectivityProbe = { ...(draft.connectivityProbe ?? defaultProbe), host };
    edited('connectivityProbe');
  },
});
const backupHost = computed({
  get: () => (draft.connectivityProbe ?? defaultProbe).backupHost ?? '',
  set: backupHost => {
    draft.connectivityProbe = { ...(draft.connectivityProbe ?? defaultProbe), backupHost };
    edited('connectivityProbe');
  },
});
</script>

<template>
  <div :aria-busy="saving">
    <div class="fields">
      <label>Poll servers every<UiInput v-model.number="draft.pollSeconds" type="number" unit="seconds" min="30" max="86400" step="1" @input="edited('pollSeconds')" @blur="flush"/></label>
      <label>Analyze logs every<UiInput v-model.number="draft.logPollSeconds" type="number" unit="seconds" min="60" max="86400" step="1" @input="edited('logPollSeconds')" @blur="flush"/></label>
      <label>Concurrent SSH connections<UiInput v-model.number="draft.concurrency" type="number" min="1" max="16" step="1" @input="edited('concurrency')" @blur="flush"/></label>
    </div>
    <fieldset>
      <legend>Internet checks</legend>
      <p>Cyberbot checks TCP port 443.</p>
      <div class="fields">
        <label>Main host<UiInput v-model="probeHost" maxlength="253" required @blur="flush"/></label>
        <label>Backup host<UiInput v-model="backupHost" maxlength="253" placeholder="Optional" @blur="flush"/></label>
      </div>
    </fieldset>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
  </div>
</template>

<style scoped>
.fields{display:flex;gap:16px 32px;margin:20px 0;flex-wrap:wrap}label{display:flex;flex-direction:column;gap:8px;font-size:12px;color:var(--muted)}.error{color:var(--danger);background:var(--danger-bg);border-radius:7px;padding:10px 12px;font-size:12px;line-height:1.6;margin:12px 0 0}
fieldset{margin:0;padding:0;border:0;min-width:0}legend{padding:0;font-weight:600}fieldset p{color:var(--muted);font-size:12px}
</style>
