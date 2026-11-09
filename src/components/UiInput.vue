<script setup lang="ts">
import { computed, ref, useAttrs } from 'vue';
import UiIcon from './UiIcon.vue';
defineOptions({ inheritAttrs: false });
const props = defineProps<{ modelValue?: string | number | null; unit?: string; compact?: boolean }>();
const emit = defineEmits<{ 'update:modelValue': [value: string | number] }>();
const attrs = useAttrs();
const input = ref<HTMLInputElement>();
const type = computed(() => (attrs.type as string | undefined) ?? 'text');
const fieldAttrs = computed(() => {
  const { class: _class, style: _style, value: _value, ...rest } = attrs;
  return rest;
});
// Supports and v-model (including .number), and :value + @input.
const model = computed({
  get: () => (props.modelValue !== undefined ? props.modelValue : (attrs.value as string | number | null | undefined)) ?? '',
  set: value => emit('update:modelValue', value),
});
defineExpose({ focus: () => input.value?.focus(), el: input });
</script>
<template>
  <span class="ui-input" :class="[attrs.class, `type-${type}`, { compact }]" :style="attrs.style as never">
    <span class="box">
      <UiIcon v-if="type==='search'" class="icon" name="search" :size="compact?14:15" />
      <input ref="input" v-model="model" v-bind="fieldAttrs">
    </span>
    <span v-if="unit" class="unit">{{ unit }}</span>
  </span>
</template>
<style scoped>
.ui-input{display:inline-flex;align-items:center;gap:8px;max-width:100%;width:var(--field-width,240px);flex:none;font-size:13px;color:var(--text)}
.ui-input.type-number{width:fit-content}
.ui-input.type-search{width:var(--field-width,220px)}
.ui-input.type-time{width:fit-content}
.box{display:flex;align-items:center;gap:6px;flex:1;min-width:0;height:32px;padding:0 10px;background:var(--surface);border:1px solid var(--line);border-radius:7px;box-sizing:border-box;transition:border-color .15s,box-shadow .15s}
.type-number .box{flex:none;width:var(--field-width,96px);max-width:100%}
.box:hover{border-color:var(--line-strong)}
.box:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
.ui-input:has(input:disabled){opacity:.5}
.ui-input:has(input:disabled) .box{border-color:var(--line)}
input{flex:1;width:100%;min-width:0;height:100%;margin:0;padding:0;font:inherit;color:inherit;background:none;border:0;outline:none;box-shadow:none;border-radius:0;font-variant-numeric:tabular-nums}
input::placeholder{color:var(--muted)}
input:disabled{cursor:default}
input[type=number]{appearance:textfield;-moz-appearance:textfield}
input::-webkit-inner-spin-button,input::-webkit-outer-spin-button{-webkit-appearance:none;margin:0}
input[type=search]::-webkit-search-decoration{-webkit-appearance:none}
.icon{flex:none;color:var(--muted)}
.unit{white-space:nowrap}
.compact{font-size:12px}
.compact .box{height:28px;padding:0 8px}
</style>
