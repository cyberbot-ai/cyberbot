<script setup lang="ts">
import { serverHint } from '../serverDirectory';
import { computed } from 'vue';
import { health, healthLabel, serverHealthLabel, partialHealthReason } from '../health';
import { exactMetric, formatMetric } from '../metrics';
import { dashboardConnectors, hideServiceUnit, serviceAvailabilityLabels, servicePriority } from '../services';
import type { Health, Server } from '../types';

const props = defineProps<{ server: Server; now: number; interval: number; alternate?: boolean }>();
defineEmits<{ select: [server: Server] }>();
const status = computed(() => health(props.server, props.now, props.interval));
const pending = computed(() => Boolean(props.server.networkOffline || props.server.awaitingFirstCheck));
const unavailable = computed(() => pending.value || ['stale', 'unreachable'].includes(status.value));
const resourceState = (value: number | null | undefined) => value == null || !Number.isFinite(value) ? 'unknown' : value >= 97 ? 'critical' : value >= 90 ? 'warning' : 'healthy';
const metrics = computed(() => {
  const o = props.server.observation;
  const metric = (key: string, label: string, help: string, raw: number|null|undefined, state = 'healthy', unit = '%', precision = 0) => ({ key, label, help, value: unavailable.value ? '—' : formatMetric(raw,precision,unit), exact: unavailable.value ? '—' : exactMetric(raw,unit), state: pending.value ? 'unknown' : unavailable.value ? 'unavailable' : raw == null || !Number.isFinite(raw) ? 'unknown' : state });
  const list = [
    metric('cpu', 'CPU', 'CPU usage', o?.cpuPercent, resourceState(o?.cpuPercent)),
    // Load has no percentage threshold: the collector does not supply a CPU count.
    metric('load', 'LA', '1-minute load average', o?.load, o?.load == null ? 'unknown' : 'healthy', '', 1),
    metric('ram', 'RAM', 'Memory usage', o?.memoryPercent, resourceState(o?.memoryPercent)),
  ];
  if (o?.swapPercent != null) list.push(metric('swap', 'SWP', 'Swap usage', o.swapPercent));
  for (const disk of o?.disks ?? []) {
    list.push(metric(`disk:${disk.mount}`, disk.mount === '/' ? 'DISK' : disk.mount, `Disk usage on ${disk.mount}`, disk.usedPercent, resourceState(disk.usedPercent)));
    if (disk.inodePercent != null) list.push(metric(`inode:${disk.mount}`, 'INO', `Inode usage on ${disk.mount}`, disk.inodePercent));
  }
  if (!o?.disks.length) list.push(metric('disk', 'DISK', 'Disk data not available', null, 'unknown'));
  return list;
});
const services = computed(() => {
  if (props.server.networkOffline) return [];
  const list: { key: string; name: string; state: string; value?: string; exact?: string; unitFailure?: string }[] = [];
  const kinds = new Set<string>();
  for (const card of dashboardConnectors(props.server, status.value)) {
    kinds.add(card.kind);
    const metric = ['unknown', 'stale'].includes(card.status) ? undefined : card.metric;
    const unit = metric ? ' ' + metric.unit : '';
    const availability = card.availability && serviceAvailabilityLabels[unavailable.value ? 'unknown' : card.availability];
    list.push({
      key: `${card.kind}:${card.instanceId ?? 'default'}`, name: card.name, state: card.state, unitFailure: card.unitFailure,
      value: metric ? formatMetric(metric.value, 1, unit) : availability, exact: metric ? exactMetric(metric.value, unit) : availability,
    });
  }
  for (const s of props.server.observation?.services ?? []) {
    if (hideServiceUnit(s.name, kinds)) continue;
    const name = s.name.replace(/\.service$/, '');
    list.push({ key: `systemd:${s.name}`, name, state: s.state === 'active' ? 'healthy' : s.state === 'failed' ? 'critical' : 'unknown' });
  }
  list.sort((a, b) => servicePriority(a.state) - servicePriority(b.state));
  if (props.server.vulnerabilities?.affected) list.push({ key: 'cve', name: 'CVE', value: formatMetric(props.server.vulnerabilities.affected,0), exact: exactMetric(props.server.vulnerabilities.affected), state: 'critical' });
  // Keep categories with no service tile visible when they affect the overall state.
  for (const [key, name, state] of [['logs', 'Logs', props.server.logStatus], ['checks', 'Checks', props.server.checkStatus]] as const) {
    if (state && state !== 'healthy') list.push({ key, name, state });
  }
  return list.map(s => {
    if (!unavailable.value) return s;
    const confirmed = !s.key.startsWith('systemd:') && (s.state === 'critical' || s.state === 'warning');
    if (s.key === 'cve') return s;
    return { ...s, state: confirmed ? s.state : pending.value ? 'unknown' : 'unavailable', value: s.value == null ? undefined : '—', exact: undefined };
  });
});
const stateLabel = (state: string) => state === 'unavailable' ? 'no current data' : healthLabel[state as Health] ?? 'No data';
const description = computed(() => {
  if (props.server.networkOffline) return `${serverHint(props.server)}\nNo data`;
  const reason = pending.value ? 'Waiting for the first check after launch or wake-up.' : status.value === 'stale' ? 'No new metrics, server availability unconfirmed.'
    : props.server.lastError ?? partialHealthReason(props.server, status.value) ?? serverHealthLabel(props.server, status.value);
  return `${serverHint(props.server)}\n${reason}${props.server.observation?.missing.length ? '\nUnavailable: ' + props.server.observation.missing.join(', ') : ''}`;
});
</script>

<template>
  <button type="button" class="ribbon" :class="[status, { alternate }]" :title="description" :aria-label="`${server.endpoint.host}, ${serverHealthLabel(server,status)}. Open diagnostics`" @click="$emit('select', server)">
    <span class="identity"><span class="status-dot" aria-hidden="true"></span><strong>{{ server.endpoint.host }}</strong></span>
    <span class="indicators">
      <span v-for="m in metrics" :key="m.key" class="metric indicator" :class="m.state" :data-metric="m.key" :title="`${m.help}: ${m.exact}`" :aria-label="`${m.help}: ${m.exact}`"><span class="code">{{ m.label }}</span><b>{{ m.value }}</b></span>
      <span v-for="(s, index) in services" :key="s.key" class="service indicator" :class="[s.state, { 'first-service': index === 0, 'with-value': s.value!=null }]" :data-service="s.key" :title="[`${s.name}: ${stateLabel(s.state)}`, s.exact, s.unitFailure].filter(Boolean).join(' · ')"><span>{{ s.name }}</span><b v-if="s.value">{{ s.value }}</b></span>
      <span v-if="status === 'unknown' && server.observation?.missing.length && !unavailable" class="coverage" :title="'Unavailable: ' + server.observation.missing.join(', ')" aria-label="Incomplete check">?</span>
    </span>
  </button>
</template>

<style scoped>
.ribbon{--tone:var(--success);display:grid;grid-template-columns:clamp(108px,12vw,160px) minmax(0,1fr);align-items:center;gap:7px;box-sizing:border-box;width:100%;min-height:32px;padding:3px 8px;border:0;border-radius:0;background:color-mix(in srgb,var(--tone) 10%,var(--surface));color:var(--text);text-align:left;font:inherit;cursor:pointer}
.ribbon.healthy.alternate{background:color-mix(in srgb,var(--tone) 15%,var(--surface))}
.ribbon.warning{--tone:var(--warning);background:color-mix(in srgb,var(--tone) 15%,var(--surface))}
.ribbon.critical,.ribbon.stale,.ribbon.unreachable{--tone:var(--danger);background:color-mix(in srgb,var(--tone) 17%,var(--surface))}
.ribbon.unknown{--tone:var(--muted);background:var(--subtle)}
.ribbon:hover{background:color-mix(in srgb,var(--tone) 23%,var(--surface))}
.ribbon:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.identity{display:flex;align-items:center;gap:6px;min-width:0}
.identity strong{font:600 11px/15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.status-dot{width:5px;height:5px;flex-shrink:0;border-radius:50%;background:var(--tone)}
.indicators{display:flex;align-items:center;flex-wrap:wrap;gap:2px;min-width:0}
.indicator{display:inline-flex;flex-direction:column;align-items:center;justify-content:center;box-sizing:border-box;min-height:24px;padding:2px 4px;border-radius:2px;white-space:nowrap;max-width:100%;line-height:11px}
.metric{flex:0 0 36px;width:36px;min-width:0;overflow:hidden;padding-inline:2px}.code{font:8px/9px ui-monospace,SFMono-Regular,monospace;color:var(--muted);max-width:100%;overflow:hidden;text-overflow:ellipsis}.indicator b{font:500 10px/11px ui-monospace,SFMono-Regular,monospace;font-variant-numeric:tabular-nums;min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis}
.service{font:10px/12px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-width:0;max-width:min(144px,100%);overflow:hidden}.service>span{max-width:100%;overflow:hidden;text-overflow:ellipsis}.service.with-value{flex:0 0 64px;width:64px}.first-service{margin-inline-start:5px}.service b{font-size:9px}
.indicator.warning{background:var(--warning-bg);color:var(--warning)}.indicator.critical{background:#bd3542;color:#fff}.indicator.critical .code{color:inherit}.indicator.unknown,.indicator.stale,.indicator.unavailable{background:color-mix(in srgb,var(--muted) 12%,var(--surface));color:var(--muted)}.indicator.unavailable{color:var(--danger);background:color-mix(in srgb,var(--danger) 10%,var(--surface))}
.service.warning{box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--warning) 55%,transparent)}
.coverage{font:600 10px/16px ui-monospace,monospace;color:var(--muted);padding-inline:4px}
@media(max-width:480px){.ribbon{grid-template-columns:92px minmax(0,1fr);gap:4px;padding-inline:5px}.identity strong{font-size:10px}.indicator{padding-inline:3px}.metric{padding-inline:2px}.first-service{margin-inline-start:2px}}
</style>
