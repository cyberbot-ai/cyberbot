<script setup lang="ts">
import { computed } from 'vue';
import RelativeDate from './RelativeDate.vue';
import UiSelect from './UiSelect.vue';
import { dateMillis, relativeDate } from '../dateTime';
import { useClock } from '../useClock';
const props = defineProps<{
  modelValue: string; options: {value:string; label:string; at?:number|null}[];
  label: string; disabled?: boolean;
}>();
const emit = defineEmits<{ 'update:modelValue':[value:string]; change:[] }>();
const now = useClock();
const current = computed(() => props.options.find(option => option.value === props.modelValue));
function date(at?: number|null) {
  void now.value;
  const ms = dateMillis(at);
  return ms == null ? '' : ` · ${relativeDate(ms, Date.now())}`;
}
function choose(value: string | number | null) {
  emit('update:modelValue', String(value ?? ''));
  emit('change');
}
</script>
<template>
  <RelativeDate v-slot="{description}" class="dated-select" :at="current?.at">
    <UiSelect class="field" :model-value="modelValue" :aria-label="label" :aria-describedby="description" :disabled="disabled" @update:model-value="choose">
      <option v-for="option in options" :key="option.value" :value="option.value">{{option.label}}{{date(option.at)}}</option>
    </UiSelect>
  </RelativeDate>
</template>
<style scoped>
.dated-select{min-width:0;max-width:100%}
.dated-select .field{max-width:min(480px,100%)}
</style>
