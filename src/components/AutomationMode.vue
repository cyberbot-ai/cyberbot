<script setup lang="ts">
import { computed, ref } from 'vue';
import { updateSettings } from '../settings';
import UiIcon from './UiIcon.vue';
import type { Settings } from '../types';

const props = defineProps<{ settings: Settings; compact?: boolean }>();
const emit = defineEmits<{ saved: [settings: Settings] }>();
const enabled = computed(() => props.settings.mode === 'auto');
const busy = ref(false), error = ref('');
async function select(mode: Settings['mode']) {
  if (busy.value || mode === props.settings.mode) return;
  error.value = '';
  busy.value = true;
  try { emit('saved', await updateSettings({ mode })); }
  catch (e) { error.value = String(e).replace(/^Error: /, ''); }
  finally { busy.value = false; }
}
</script>

<template>
  <div class="mode-control" :class="{ compact }">
    <div class="mode-row">
      <h1 v-if="!compact">AI</h1>
      <button type="button" class="ai-switch" role="switch" :aria-label="compact ? 'AI' : 'Automatic launches'" :aria-checked="enabled" :aria-busy="busy" :disabled="busy" :title="enabled ? 'Turn off the AI. Current automatic start-up will stop.' : 'Enable automatic AI investigations.'" @click="select(enabled ? 'manual' : 'auto')">
        <span v-if="compact" class="caption">AI</span><span class="switch-track" aria-hidden="true"><span class="switch-thumb"></span></span>
      </button>
      <span v-if="compact && enabled && settings.paused" class="pause-indicator" role="status" aria-label="Automatic investigations paused" title="Monitoring on pause: automatic tasks do not start"><UiIcon name="pause" :size="14"/></span>
      <slot name="badge"/>
    </div>
    <p v-if="!compact" class="mode-help">{{ enabled ? `AI is parsing new significant incidents within limits — ${settings.autoAgent === 'codex' ? 'Codex' : 'Claude Code'}.` : 'Automatic launches are off. Start a manual investigation from a server’s AI tab or an incident group card.' }}</p>
    <p v-if="!compact && settings.paused" class="pause-notice" role="status"><UiIcon name="pause" :size="14"/>Monitoring is paused. Automatic tasks are not started.</p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
  </div>
</template>

<style scoped>
.mode-control { min-width: 0; color: var(--text); }
.mode-row { display: flex; align-items: center; gap: 12px; }
h1 { font-size: 23px; font-weight: 600; letter-spacing: -.5px; margin: 0; }
.mode-help, .pause-notice { font-size: 12px; line-height: 1.6; margin: 6px 0 0; max-width: 70ch; }
.mode-help { color: var(--muted); }
.pause-notice { color: var(--warning); display: flex; align-items: baseline; gap: 6px; }
.pause-notice svg { flex-shrink: 0; align-self: center; }
.ai-switch { display: inline-flex; align-items: center; gap: 9px; padding: 7px 9px; min-height: 32px; font: inherit; color: var(--text); border: 1px solid var(--line); border-radius: 7px; background: var(--surface); cursor: pointer; white-space: nowrap; }
.ai-switch:hover:enabled { background: var(--hover); border-color: var(--line-strong); }
.caption { color: var(--muted); }
.switch-track { position: relative; width: 28px; height: 16px; flex-shrink: 0; border-radius: 10px; background: var(--line-strong); }
.switch-thumb { position: absolute; top: 2px; left: 2px; width: 12px; height: 12px; border-radius: 50%; background: var(--surface); transition: transform .15s; }
.ai-switch[aria-checked=true] .switch-track { background: var(--accent); }
.ai-switch[aria-checked=true] .switch-thumb { transform: translateX(12px); background: var(--on-accent); }
button:disabled { opacity: .5; cursor: default; }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
.compact { position: relative; flex-shrink: 0; }
.compact .mode-row { gap: 6px; }
.compact .ai-switch { padding: 5px 8px; min-height: 30px; border-color: transparent; background: none; gap: 7px; }
.compact .caption { font-size: 11px; }
.pause-indicator { display: flex; color: var(--warning); }
.error { font-size: 12px; color: var(--danger); line-height: 1.5; background: var(--danger-bg); padding: 10px; border-radius: 6px; margin: 8px 0 0; overflow-wrap: anywhere; }
.compact > .error { position: absolute; right: 0; top: 100%; z-index: 3; max-width: 360px; box-shadow: var(--shadow); }
@media (max-width: 700px) { .compact > .error { left: 0; right: auto; width: min(320px, calc(100vw - 110px)); max-width: none; box-sizing: border-box; } }
@media (max-width: 560px) { h1 { font-size: 20px; } }
@media (prefers-reduced-motion: reduce) { .switch-thumb { transition: none; } }
</style>
