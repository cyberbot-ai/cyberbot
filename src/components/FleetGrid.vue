<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch, type ComponentPublicInstance } from 'vue';
import ServerCard from './ServerCard.vue';
import ServerRibbon from './ServerRibbon.vue';
import type { Server } from '../types';

const props = defineProps<{ servers: Server[]; now: number; interval: number; compact: boolean }>();
defineEmits<{ select: [server: Server] }>();
const root = ref<HTMLElement>();
const width = ref(1000), height = ref(600), top = ref(0), measuredVersion = ref(0);
const measured = new Map<string, number>(), elements = new Map<string, Element>();
const columns = computed(() => props.compact ? 1 : Math.max(1, Math.floor((width.value + 12) / 270)));
// Only visible rows are measured. Prefix offsets also cover wrapped service lists.
const offsets = computed(() => {
  void measuredVersion.value;
  const positions = [0];
  for (const server of props.servers) positions.push(positions[positions.length - 1] + (measured.get(server.id) ?? 32));
  return positions;
});
function rowAt(position: number) {
  let low = 0, high = props.servers.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (offsets.value[mid + 1] <= position) low = mid + 1;
    else high = mid;
  }
  return low;
}
const first = computed(() => props.compact ? Math.max(0, rowAt(top.value) - 2) : Math.max(0, Math.floor(top.value / 178) - 2) * columns.value);
const end = computed(() => Math.min(props.servers.length, props.compact ? rowAt(top.value + height.value) + 3 : first.value + (Math.ceil(height.value / 178) + 4) * columns.value));
const visible = computed(() => props.servers.slice(first.value, end.value));
const before = computed(() => props.compact ? offsets.value[first.value] : Math.floor(first.value / columns.value) * 178);
const after = computed(() => props.compact ? offsets.value[props.servers.length] - offsets.value[end.value] : Math.max(0, Math.ceil(props.servers.length / columns.value) - Math.ceil(end.value / columns.value)) * 178);
let viewportObserver: ResizeObserver | undefined, rowObserver: ResizeObserver | undefined;

function preserveAnchor(change: () => void) {
  const anchor = Math.min(rowAt(top.value), props.servers.length - 1);
  const within = anchor < 0 ? 0 : top.value - offsets.value[anchor];
  change();
  measuredVersion.value++;
  if (anchor >= 0) {
    top.value = offsets.value[anchor] + Math.min(within, offsets.value[anchor + 1] - offsets.value[anchor] - 1);
    // Apply after spacer heights update, otherwise the old scroll extent can
    // clamp the anchor near the end of the list.
    void nextTick(() => { if (root.value) root.value.scrollTop = top.value; });
  }
}
function observeRow(element: Element | ComponentPublicInstance | null, id: string) {
  const previous = elements.get(id);
  if (previous === element) return;
  if (previous) rowObserver?.unobserve(previous);
  elements.delete(id);
  if (element instanceof Element) {
    elements.set(id, element);
    rowObserver?.observe(element);
  }
}
onMounted(() => {
  viewportObserver = new ResizeObserver(([entry]) => {
    if (width.value !== entry.contentRect.width) {
      if (props.compact) preserveAnchor(() => measured.clear());
      else { measured.clear(); measuredVersion.value++; }
      // Observe again even if a visible row kept its height at the new width.
      for (const element of elements.values()) { rowObserver?.unobserve(element); rowObserver?.observe(element); }
    }
    width.value = entry.contentRect.width;
    height.value = entry.contentRect.height;
  });
  rowObserver = new ResizeObserver(entries => {
    const changes = entries.filter(e => e.contentRect.height > 0 && measured.get((e.target as HTMLElement).dataset.id!) !== e.contentRect.height);
    if (props.compact && changes.length) preserveAnchor(() => {
      for (const e of changes) measured.set((e.target as HTMLElement).dataset.id!, e.contentRect.height);
    });
  });
  if (root.value) viewportObserver.observe(root.value);
  for (const element of elements.values()) rowObserver.observe(element);
});
onBeforeUnmount(() => { viewportObserver?.disconnect(); rowObserver?.disconnect(); });
watch([() => props.servers.map(s => s.id).join(','), () => props.compact], () => {
  const ids = new Set(props.servers.map(s => s.id));
  for (const id of measured.keys()) if (!ids.has(id)) measured.delete(id);
  measuredVersion.value++;
  top.value = 0;
  if (root.value) root.value.scrollTop = 0;
});
</script>

<template>
  <div class="fleet-grid">
    <div ref="root" class="viewport" :class="{ ribbon: compact }" @scroll="top = ($event.target as HTMLElement).scrollTop">
      <div aria-hidden="true" :style="{ height: `${before}px` }"></div>
      <div class="grid" :class="{ ribbon: compact }" :style="{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }" :role="compact ? 'list' : undefined" aria-label="Servers">
        <template v-if="compact">
          <div v-for="(server, index) in visible" :key="server.id" :ref="element => observeRow(element, server.id)" class="ribbon-slot" :data-id="server.id" role="listitem" :aria-posinset="first + index + 1" :aria-setsize="servers.length">
            <ServerRibbon :server="server" :now="now" :interval="interval" :alternate="(first + index) % 2 === 1" @select="$emit('select', $event)" />
          </div>
        </template>
        <template v-else><ServerCard v-for="server in visible" :key="server.id" :server="server" :now="now" :interval="interval" @select="$emit('select', $event)" /></template>
      </div>
      <div aria-hidden="true" :style="{ height: `${after}px` }"></div>
    </div>
  </div>
</template>

<style scoped>
.fleet-grid{height:100%;display:flex;flex-direction:column;min-height:0}.viewport{flex:1;min-height:0;overflow:auto;padding:2px 3px 8px;box-sizing:border-box;scrollbar-color:var(--line-strong) transparent;scrollbar-width:thin}.grid{display:grid;gap:12px}.grid.ribbon{gap:0}.viewport.ribbon{padding:0;overflow-anchor:none}.ribbon-slot{min-width:0}
</style>
