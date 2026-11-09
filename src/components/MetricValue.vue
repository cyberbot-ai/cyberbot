<script setup lang="ts">
import { exactMetric, formatMetric } from '../metrics';
withDefaults(defineProps<{ value?:number|null; precision?:number; unit?:string; empty?:string; exact?:string; trim?:boolean }>(), {
  precision: 1, unit: '', empty: '—', trim:false,
});
</script>
<template>
  <span class="metric-value" :title="exact??exactMetric(value,unit,empty)" :aria-label="exact??exactMetric(value,unit,empty)">{{formatMetric(value,precision,unit,empty,trim)}}</span>
</template>
<style scoped>
.metric-value{display:inline-block;min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom;font-variant-numeric:tabular-nums}
</style>
