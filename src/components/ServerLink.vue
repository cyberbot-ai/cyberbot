<script setup lang="ts">
import { computed, inject, ref } from 'vue';
import { serverAddress, serverDirectoryKey, serverLabel, type ServerReference, type ServerSection } from '../serverDirectory';

const props = defineProps<ServerReference & { section?: ServerSection; captured?: boolean }>();
const directory = inject(serverDirectoryKey, undefined);
const server = computed(() => directory?.current().resolve(props));
const label = computed(() => serverLabel(props, server.value));
const changedAddress = computed(() => props.captured && props.address && server.value && props.address !== serverAddress(server.value.endpoint));
const error = ref('');
async function open() {
  const current = server.value;
  if (!current || !directory) return;
  error.value = '';
  try {
    await directory.open(current.id, props.section);
  } catch (failure) {
    error.value = String(failure).replace(/^Error: /, '');
  }
}
</script>

<template>
  <span class="server-reference">
    <button v-if="server" class="server-link" type="button" :title="label.hint || undefined" @click.stop="open">{{ label.host }}</button>
    <span v-else :title="label.hint || undefined">{{ label.host }}</span>
    <small v-if="changedAddress" class="captured">Address at the time of request: {{ address }}</small>
    <small v-if="error" class="error" role="alert">{{ error }}</small>
  </span>
</template>

<style scoped>
.server-link{padding:0;border:0;background:none;color:var(--accent);font:inherit;text-align:left;cursor:pointer;text-decoration:underline;text-underline-offset:3px;overflow-wrap:anywhere}
.server-reference{min-width:0;overflow-wrap:anywhere}
.server-link:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.captured,.error{display:block}
.captured{color:var(--muted)}
.error{color:var(--danger)}
</style>
