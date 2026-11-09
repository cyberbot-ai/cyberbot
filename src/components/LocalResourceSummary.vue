<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { call } from '../api';
import type { LocalResourceSample } from '../types';

const cadenceMs = 5000;
const sample = ref<LocalResourceSample>();
const received = ref<number | null>(null);
const sent = ref<number | null>(null);
let timer: ReturnType<typeof setTimeout> | undefined;
let generation = 0;
let running = false;
let disposed = false;

const numbers = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });
const scope = 'Cyberbot, its subsidiaries, and the SSH pool. WebKit processes are counted as confirmed Cyberbot membership. CPU as a percentage of one core. TCP/UDP network outside loopback. Size in bytes, step between 1024 units. Volume sums up the available measurements per view.';

async function measure() {
  if (disposed || document.hidden || running) return;
  const request = generation;
  const started = performance.now();
  running = true;
  try {
    const next = await call<LocalResourceSample>('local_resource_sample');
    if (disposed || document.hidden || request !== generation) return;
    sample.value = next;
    if (next.rxBytes != null) received.value = (received.value ?? 0) + next.rxBytes;
    if (next.txBytes != null) sent.value = (sent.value ?? 0) + next.txBytes;
  } catch {
    if (!disposed && request === generation) sample.value = undefined;
  } finally {
    running = false;
    if (!disposed && !document.hidden) {
      timer = setTimeout(measure, Math.max(0, cadenceMs - (performance.now() - started)));
    }
  }
}

function visibility() {
  generation++;
  clearTimeout(timer);
  if (document.hidden) sample.value = undefined;
  else void measure();
}

onMounted(() => {
  document.addEventListener('visibilitychange', visibility);
  void measure();
});
onBeforeUnmount(() => {
  disposed = true;
  clearTimeout(timer);
  document.removeEventListener('visibilitychange', visibility);
});

function bytes(value: number | null | undefined, suffix = '') {
  if (value == null || !Number.isFinite(value)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return numbers.format(value) + ' ' + units[unit] + suffix;
}

function rate(value: number | null | undefined) {
  const duration = sample.value?.durationMs ?? 0;
  return bytes(value != null && duration > 0 ? value * 1000 / duration : null, '/s');
}

const cpu = computed(() => sample.value?.cpuPercent == null ? '—' : numbers.format(sample.value.cpuPercent) + '%');
const ram = computed(() => bytes(sample.value?.memoryBytes));
</script>

<template>
  <section class="local-resources" aria-label="Cyberbot Resources" :title="scope">
    <dl class="readings">
      <div><dt>CPU</dt><dd>{{cpu}}</dd></div>
      <div><dt>RAM</dt><dd>{{ram}}</dd></div>
      <div><dt>↓ Entrance</dt><dd>{{rate(sample?.rxBytes)}}</dd></div>
      <div><dt>↑ Exit</dt><dd>{{rate(sample?.txBytes)}}</dd></div>
    </dl>
    <p class="totals">Considered for viewing <span aria-label="Input volume">↓ {{bytes(received)}}</span> <span aria-label="Outgoing volume">↑ {{bytes(sent)}}</span></p>
  </section>
</template>

<style scoped>
.local-resources{min-width:0;color:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}
.readings{display:flex;flex-wrap:wrap;gap:3px 12px;margin:0}
.readings>div{display:flex;gap:4px;white-space:nowrap}
dd{margin:0;color:var(--text);font-weight:500}
.totals{display:flex;flex-wrap:wrap;gap:3px 8px;margin:4px 0 0;white-space:nowrap}
</style>
