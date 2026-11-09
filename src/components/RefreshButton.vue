<script setup lang="ts">
import UiIcon from './UiIcon.vue';
</script>

<template>
  <button type="button" class="refresh-button">
    <UiIcon name="refresh" :size="15"/>
    <slot/>
  </button>
</template>

<style scoped>
.refresh-button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
</style>
