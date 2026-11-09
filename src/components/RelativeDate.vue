<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, useId, watch } from 'vue';
import { dateMillis, exactDate, relativeDate, type DateUnit } from '../dateTime';
import { useClock } from '../useClock';
import { activateDatePopover, releaseDatePopover } from '../datePopover';

defineOptions({ inheritAttrs: false });
const props = withDefaults(defineProps<{
  at?: number | null; unit?: DateUnit; empty?: string; calendarDay?: boolean;
}>(), { unit: 'seconds', empty: '—', calendarDay: false });
const now = useClock();
const ms = computed(() => dateMillis(props.at, props.unit));
const label = computed(() => {
  // Subscribe to the shared tick, but use the actual time when fresh data arrives between ticks.
  void now.value;
  return ms.value == null ? props.empty : relativeDate(ms.value, Date.now(), props.calendarDay);
});
const precise = computed(() => ms.value == null ? '' : exactDate(ms.value, props.unit === 'milliseconds', props.calendarDay));
const iso = computed(() => ms.value == null ? undefined : new Date(ms.value).toISOString());
const trigger = ref<HTMLElement>(), popup = ref<HTMLElement>();
const opened = ref(false), target = ref<HTMLElement>();
const position = ref({ left: '0px', top: '0px', visibility: 'hidden' as 'hidden' | 'visible' });
const id = `date-${useId()}`;
let hideTimer: ReturnType<typeof setTimeout> | undefined;
function close() {
  clearTimeout(hideTimer);
  opened.value = false;
  releaseDatePopover(close);
  window.removeEventListener('resize', close);
  window.removeEventListener('scroll', close, true);
  document.removeEventListener('keydown', escape, true);
  document.removeEventListener('pointerdown', outside, true);
  document.removeEventListener('visibilitychange', close);
}
function escape(event: KeyboardEvent) {
  if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); }
}
function outside(event: Event) {
  const node = event.target as Node;
  if (!trigger.value?.contains(node) && !popup.value?.contains(node)) close();
}
function keep() { clearTimeout(hideTimer); }
function leave() { keep(); hideTimer = setTimeout(close, 120); }
async function open() {
  keep();
  if (ms.value == null || opened.value || !trigger.value) return;
  activateDatePopover(close);
  // Stay in the modal's top layer and inherit the current app theme.
  target.value = trigger.value.closest<HTMLElement>('dialog[open]')
    ?? trigger.value.closest<HTMLElement>('.app') ?? document.body;
  position.value.visibility = 'hidden';
  opened.value = true;
  window.addEventListener('resize', close);
  window.addEventListener('scroll', close, true);
  document.addEventListener('keydown', escape, true);
  document.addEventListener('pointerdown', outside, true);
  document.addEventListener('visibilitychange', close);
  await nextTick();
  if (!opened.value || !popup.value || !trigger.value) return;
  const anchor = trigger.value.getBoundingClientRect(), box = popup.value.getBoundingClientRect();
  const left = Math.max(8, Math.min(anchor.left + (anchor.width - box.width) / 2, window.innerWidth - box.width - 8));
  const below = anchor.bottom + 7;
  const top = Math.max(8, below + box.height <= window.innerHeight - 8 ? below : anchor.top - box.height - 7);
  position.value = { left: `${left}px`, top: `${top}px`, visibility: 'visible' };
}
function tap(event: MouseEvent) {
  // A date inside a clickable server/incident should reveal its time, not open it.
  if (!trigger.value?.querySelector('select')) { event.stopPropagation(); void open(); }
}
watch(ms, close);
onBeforeUnmount(close);
</script>

<template>
  <span ref="trigger" v-bind="$attrs" class="relative-date" :class="{available:ms!=null}"
    :tabindex="ms!=null&&!$slots.default?0:undefined" :aria-describedby="opened?id:undefined"
    @mouseenter="open" @mouseleave="leave" @focusin="open" @focusout="leave" @click="tap">
    <slot :description="opened?id:undefined"><time :datetime="iso">{{label}}</time></slot>
  </span>
  <Teleport v-if="opened&&target" :to="target">
    <span :id="id" ref="popup" class="date-popover" role="tooltip" :style="position"
      @mouseenter="keep" @mouseleave="leave">{{precise}}</span>
  </Teleport>
</template>

<style scoped>
.relative-date{display:inline-block;white-space:nowrap;font:inherit;color:inherit;vertical-align:baseline}
.available{cursor:help}
.relative-date:focus-visible{outline:2px solid var(--accent,#247b50);outline-offset:3px;border-radius:3px}
.date-popover{position:fixed;z-index:10000;box-sizing:border-box;max-width:calc(100vw - 16px);padding:8px 10px;border:1px solid var(--line,#d9dfda);border-radius:7px;background:var(--surface,#fff);color:var(--text,#202722);box-shadow:0 5px 20px #0002;font:12px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;white-space:normal;overflow-wrap:anywhere;user-select:text;cursor:text}
</style>
