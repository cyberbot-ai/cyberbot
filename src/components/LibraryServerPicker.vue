<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue';
import { serverLabel } from '../serverDirectory';
import type { Server } from '../types';
import UiIcon from './UiIcon.vue';
import UiInput from './UiInput.vue';

const props = defineProps<{ servers: Server[]; disabled?: boolean }>();
const selection = defineModel<string>({ required: true });
const emit = defineEmits<{ change: [] }>();
const id = `library-servers-${useId()}`;
const allServers = { id: '', host: 'All servers', hint: '' };
const root = ref<HTMLElement>();
const trigger = ref<HTMLButtonElement>();
const input = ref<InstanceType<typeof UiInput>>();
const opened = ref(false);
const query = ref('');
const activeId = ref<string>();

const options = computed(() => [allServers, ...props.servers.map(server => ({
  id: server.id, ...serverLabel({}, server),
}))]);
const selected = computed(() => options.value.find(option => option.id === selection.value) ?? allServers);
const matches = computed(() => {
  const terms = query.value.trim().toLowerCase().split(/\s+/);
  return options.value.filter(({ host, hint }) => {
    const text = `${host} ${hint}`.toLowerCase();
    return terms.every(term => text.includes(term));
  });
});
const activeIndex = computed(() => matches.value.findIndex(option => option.id === activeId.value));

watch(query, () => {
  if (opened.value) activeId.value = matches.value[0]?.id;
});
watch(() => props.disabled, disabled => { if (disabled) close(); });

function scrollToActive() {
  root.value?.querySelector('[data-active="true"]')?.scrollIntoView?.({ block: 'nearest' });
}

async function open() {
  if (props.disabled || opened.value) return;
  activeId.value = selected.value.id;
  opened.value = true;
  await nextTick();
  input.value?.focus();
  scrollToActive();
}

function close(restoreFocus = false) {
  opened.value = false;
  query.value = '';
  if (restoreFocus) trigger.value?.focus();
}

function closeOutside(event: PointerEvent | FocusEvent) {
  if (!opened.value) return;
  const target = event instanceof FocusEvent ? event.relatedTarget : event.target;
  if (!root.value?.contains(target as Node | null)) close();
}

onMounted(() => document.addEventListener('pointerdown', closeOutside, true));
onBeforeUnmount(() => document.removeEventListener('pointerdown', closeOutside, true));

function choose(id: string) {
  if (id !== selection.value) {
    selection.value = id;
    emit('change');
  }
  close(true);
}

async function searchKey(event: KeyboardEvent) {
  if (event.isComposing) return;
  if (event.key === 'Escape') {
    event.preventDefault();
    event.stopPropagation();
    close(true);
  } else if (event.key === 'Enter') {
    event.preventDefault();
    const option = matches.value[activeIndex.value];
    if (option) choose(option.id);
  } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    const last = matches.value.length - 1;
    const step = event.key === 'ArrowDown' ? 1 : -1;
    const index = activeIndex.value < 0 ? (step > 0 ? 0 : last) : Math.max(0, Math.min(last, activeIndex.value + step));
    activeId.value = matches.value[index]?.id;
    await nextTick();
    scrollToActive();
  }
}
</script>

<template>
  <div ref="root" class="server-picker" @focusout="closeOutside">
    <button ref="trigger" type="button" class="trigger" :disabled="disabled"
      :aria-label="`Servers: ${selected.host}`" :title="selected.hint || undefined"
      :aria-expanded="opened" :aria-controls="opened ? id : undefined"
      @click="opened ? close() : open()" @keydown.down.prevent="open">
      <span>{{ selected.host }}</span>
      <UiIcon name="chevron" :size="13" class="chevron"/>
    </button>
    <div v-if="opened" :id="id" class="popover">
      <UiInput ref="input" v-model="query" class="search" type="search" role="combobox" aria-label="Find a server"
        placeholder="Name or address" autocomplete="off" aria-expanded="true" aria-autocomplete="list"
        :aria-controls="`${id}-options`" :aria-activedescendant="activeIndex < 0 ? undefined : `${id}-option-${activeIndex}`"
        @keydown="searchKey"/>
      <div :id="`${id}-options`" class="options" role="listbox" aria-label="Servers">
        <div v-for="(option, index) in matches" :id="`${id}-option-${index}`" :key="option.id"
          class="option" role="option" :aria-selected="option.id === selection" :data-active="activeIndex === index"
          :title="option.hint || undefined" @mousedown.prevent @click="choose(option.id)">
          <span class="option-label">
            <span>{{ option.host }}</span>
            <small v-if="option.hint">{{ option.hint }}</small>
          </span>
          <UiIcon v-if="option.id === selection" name="check" :size="14"/>
        </div>
      </div>
      <p v-if="!matches.length" class="empty" role="status">No servers found</p>
    </div>
  </div>
</template>

<style scoped>
.server-picker{position:relative;flex:none;width:280px;min-width:min(120px,100%);max-width:100%}
.trigger{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;height:32px;padding:0 10px;font:inherit;font-size:13px;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;cursor:pointer}
.trigger span,.option-label>*{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.trigger:hover:not(:disabled){border-color:var(--line-strong)}
.trigger:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.trigger:disabled{opacity:.5;cursor:default}
.chevron{transform:rotate(90deg);color:var(--muted);flex:none}
.popover{position:absolute;z-index:4;top:calc(100% + 5px);left:0;box-sizing:border-box;width:100%;padding:7px;background:var(--surface);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow)}
.search{--field-width:100%}
.options{max-height:min(300px,40vh);overflow:auto;overscroll-behavior:contain}
.options:not(:empty){margin-top:5px}
.option{display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:29px;padding:4px 7px;border-radius:4px;cursor:pointer}
.option[data-active="true"],.option:hover{background:var(--hover)}
.option[aria-selected="true"] svg{flex:none;color:var(--accent)}
.option-label{min-width:0}
.option-label small,.empty{color:var(--muted)}
.empty{margin:5px 0 0;padding:4px 7px}
</style>
