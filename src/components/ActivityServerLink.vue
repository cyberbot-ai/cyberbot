<script setup lang="ts">
import { computed, inject } from 'vue';
import type { ActivityEvent } from '../types';
import { activityServerReference, isInternalId, serverDirectoryKey } from '../serverDirectory';
import ServerLink from './ServerLink.vue';

const props = defineProps<{ event: ActivityEvent; empty: string }>();
const directory = inject(serverDirectoryKey, undefined);
const reference = computed(() => activityServerReference(props.event, directory?.current()));
</script>

<template>
  <ServerLink v-if="reference" v-bind="reference"/>
  <span v-else>{{ event.target ? (isInternalId(event.target) ? 'Context unavailable' : event.target) : empty }}</span>
</template>
