<script setup lang="ts">
import { computed, useAttrs } from 'vue';
defineOptions({ inheritAttrs: false });
// Without boolean in model Value type: otherwise, Vue leads the missing prop to false.
const props = defineProps<{ modelValue?: string | number | null; inherited?: boolean; compact?: boolean }>();
const emit = defineEmits<{ 'update:modelValue': [value: string | number | null] }>();
const attrs = useAttrs();
const fieldAttrs = computed(() => {
  const { class: _class, style: _style, value: _value, ...rest } = attrs;
  return rest;
});
// It also supports v-model, and :value + @change: native v-model correctly
// resets the selected value during asynchronous change of options.
const model = computed({
  get: () => (props.modelValue !== undefined ? props.modelValue : (attrs.value as string | number | null | undefined)) ?? '',
  set: value => emit('update:modelValue', value),
});
</script>
<template>
  <span class="ui-select" :class="[attrs.class, { inherited, compact }]" :style="attrs.style as never">
    <select v-model="model" v-bind="fieldAttrs"><slot /></select>
    <svg class="chevron" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M5 6.5l3 3 3-3" /></svg>
  </span>
</template>
<style scoped>
.ui-select{position:relative;display:inline-flex;width:fit-content;min-width:120px;max-width:min(320px,100%);flex:none}
select{appearance:none;-webkit-appearance:none;width:100%;min-width:0;height:32px;margin:0;padding:0 30px 0 10px;font:inherit;font-size:13px;line-height:30px;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;box-sizing:border-box;cursor:pointer;text-overflow:ellipsis;white-space:nowrap;overflow:hidden;transition:border-color .15s,box-shadow .15s}
select:hover:not(:disabled){border-color:var(--line-strong)}
select:focus{outline:none}
select:focus-visible{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
select:disabled{cursor:default}
.ui-select:has(select:disabled){opacity:.5}
.inherited select{color:var(--muted)}
.chevron{position:absolute;right:8px;top:50%;margin-top:-8px;pointer-events:none;fill:none;stroke:var(--muted);stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.compact{min-width:90px}
.compact select{height:28px;line-height:26px;font-size:12px;padding:0 26px 0 8px}
.compact .chevron{right:6px}
</style>
