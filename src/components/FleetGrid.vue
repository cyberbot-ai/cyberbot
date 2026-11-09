<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch, type ComponentPublicInstance } from 'vue';
import ServerCard from './ServerCard.vue';
import ServerRibbon from './ServerRibbon.vue';
import type { Server } from '../types';

const props = defineProps<{
  servers: Server[];
  projectStarts?: ReadonlyMap<string, string>;
  now: number;
  interval: number;
  compact: boolean;
  scrollResetKey?: string;
}>();
defineEmits<{ select: [server: Server] }>();
const root = ref<HTMLElement>();
const width = ref(1000), height = ref(600), top = ref(0), measuredVersion = ref(0);
const measured = new Map<string, number>(), elements = new Map<string, Element>();
const cardRowHeight = 178;
const projectHeadingHeight = 24;
const projectHeadingSize = `${projectHeadingHeight}px`;
const projectGap = 8;
const columns = computed(() => props.compact ? 1 : Math.max(1, Math.floor((width.value + 12) / 270)));
const rows = computed(() => props.servers.map((server, index) => {
  const project = props.compact ? props.projectStarts?.get(server.id) : undefined;
  const leading = project ? projectHeadingHeight + (index > 0 ? projectGap : 0) : 0;
  return { server, project, leading };
}));
// Heading space is known even when its server is outside the viewport.
function rowOffsets(layout: typeof rows.value) {
  const positions = [0];
  for (const row of layout) {
    positions.push(positions[positions.length - 1] + row.leading + (measured.get(row.server.id) ?? 32));
  }
  return positions;
}
const offsets = computed(() => {
  void measuredVersion.value;
  return rowOffsets(rows.value);
});
function rowAt(position: number, positions = offsets.value) {
  let low = 0, high = positions.length - 1;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (positions[mid + 1] <= position) low = mid + 1;
    else high = mid;
  }
  return low;
}
function rowOffset(index: number, positions?: number[]) {
  return positions ? positions[index] : Math.floor(index / columns.value) * cardRowHeight;
}
const first = computed(() => props.compact ? Math.max(0, rowAt(top.value) - 2) : Math.max(0, Math.floor(top.value / cardRowHeight) - 2) * columns.value);
const end = computed(() => Math.min(props.servers.length, props.compact ? rowAt(top.value + height.value) + 3 : first.value + (Math.ceil(height.value / cardRowHeight) + 4) * columns.value));
const visible = computed(() => rows.value.slice(first.value, end.value));
const before = computed(() => rowOffset(first.value, props.compact ? offsets.value : undefined));
const after = computed(() => props.compact ? offsets.value[props.servers.length] - offsets.value[end.value] : Math.max(0, Math.ceil(props.servers.length / columns.value) - Math.ceil(end.value / columns.value)) * cardRowHeight);
let viewportObserver: ResizeObserver | undefined, rowObserver: ResizeObserver | undefined;

function scrollTo(position: number, focused?: HTMLElement) {
  top.value = Math.max(0, position);
  if (top.value === 0 && !focused) {
    if (root.value) root.value.scrollTop = 0;
    return;
  }
  // The new virtual spacers must be in place before the browser clamps scrollTop.
  void nextTick(() => {
    const viewport = root.value;
    if (!viewport) return;
    viewport.scrollTop = top.value;
    top.value = viewport.scrollTop;
    if (focused && viewport.contains(focused) && viewport.ownerDocument.activeElement === viewport.ownerDocument.body) {
      focused.focus({ preventScroll: true });
    }
  });
}

function preserveAnchor(change: () => void) {
  const anchor = Math.min(rowAt(top.value), props.servers.length - 1);
  const within = anchor < 0 ? 0 : top.value - offsets.value[anchor];
  change();
  measuredVersion.value++;
  if (anchor >= 0) {
    scrollTo(offsets.value[anchor] + Math.min(within, offsets.value[anchor + 1] - offsets.value[anchor] - 1));
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
watch([rows, () => props.compact, () => props.scrollResetKey], ([layout, compact, resetKey], [previousLayout, previousCompact, previousResetKey]) => {
  const reset = compact !== previousCompact || resetKey !== previousResetKey;
  if (!reset && layout.length === previousLayout.length && layout.every((row, index) =>
    row.server.id === previousLayout[index].server.id && row.leading === previousLayout[index].leading)) return;

  const ids = layout.map(row => row.server.id);
  const remaining = new Set(ids);
  let position = 0;
  let focused: HTMLElement | undefined;
  if (!reset) {
    // Prefer the focused server when it moves away from the first visible row.
    const active = root.value?.ownerDocument.activeElement;
    if (active instanceof HTMLElement && root.value?.contains(active)) focused = active;
    const focusedId = focused?.closest<HTMLElement>('[data-id]')?.dataset.id;
    const previousOffsets = compact ? rowOffsets(previousLayout) : undefined;
    const firstVisible = previousOffsets ? rowAt(top.value, previousOffsets) : Math.floor(top.value / cardRowHeight) * columns.value;
    const anchorId = focusedId && remaining.has(focusedId) ? focusedId : previousLayout[firstVisible]?.server.id;
    const nextIndex = anchorId === undefined ? -1 : ids.indexOf(anchorId);
    if (nextIndex >= 0) {
      const previousIndex = previousLayout.findIndex(row => row.server.id === anchorId);
      position = top.value - rowOffset(previousIndex, previousOffsets) + rowOffset(nextIndex, compact ? offsets.value : undefined);
    }
  }
  for (const id of measured.keys()) if (!remaining.has(id)) measured.delete(id);
  scrollTo(position, focused);
});
</script>

<template>
  <div class="fleet-grid">
    <div ref="root" class="viewport" :class="{ ribbon: compact }" @scroll="top = ($event.target as HTMLElement).scrollTop">
      <div aria-hidden="true" :style="{ height: `${before}px` }"></div>
      <div class="grid" :class="{ ribbon: compact }" :style="{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }" :role="compact ? 'list' : undefined" aria-label="Servers">
        <template v-if="compact">
          <div v-for="({ server, project, leading }, index) in visible" :key="server.id" :ref="element => observeRow(element, server.id)" class="ribbon-slot" :style="project ? { paddingTop: `${leading}px` } : undefined" :data-id="server.id" role="listitem" :aria-posinset="first + index + 1" :aria-setsize="servers.length">
            <h2 v-if="project" class="ribbon-project" :style="{ top: `${leading - projectHeadingHeight}px` }" :title="project">{{ project }}</h2>
            <ServerRibbon :server="server" :now="now" :interval="interval" :alternate="(first + index) % 2 === 1" @select="$emit('select', $event)" />
          </div>
        </template>
        <template v-else><ServerCard v-for="{ server } in visible" :key="server.id" :data-id="server.id" :server="server" :now="now" :interval="interval" @select="$emit('select', $event)" /></template>
      </div>
      <div aria-hidden="true" :style="{ height: `${after}px` }"></div>
    </div>
  </div>
</template>

<style scoped>
.fleet-grid{height:100%;display:flex;flex-direction:column;min-height:0}.viewport{flex:1;min-height:0;overflow:auto;overflow-anchor:none;padding:2px 3px 8px;box-sizing:border-box;scrollbar-color:var(--line-strong) transparent;scrollbar-width:thin}.grid{display:grid;gap:12px}.grid.ribbon{gap:0}.viewport.ribbon{padding:0}
/* ResizeObserver measures the content box, so the cached server height excludes the heading. */
.ribbon-slot { min-width: 0; position: relative; }
.ribbon-project {
  position: absolute;
  inset-inline: 0;
  margin: 0;
  padding-inline: 8px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text);
  font-size: 12px;
  font-weight: 600;
  line-height: v-bind(projectHeadingSize);
}
</style>
