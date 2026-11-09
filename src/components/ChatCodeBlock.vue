<script lang="ts">
import bash from 'highlight.js/lib/languages/bash';
import css from 'highlight.js/lib/languages/css';
import diff from 'highlight.js/lib/languages/diff';
import dockerfile from 'highlight.js/lib/languages/dockerfile';
import go from 'highlight.js/lib/languages/go';
import ini from 'highlight.js/lib/languages/ini';
import javascript from 'highlight.js/lib/languages/javascript';
import json from 'highlight.js/lib/languages/json';
import nginx from 'highlight.js/lib/languages/nginx';
import python from 'highlight.js/lib/languages/python';
import rust from 'highlight.js/lib/languages/rust';
import sql from 'highlight.js/lib/languages/sql';
import typescript from 'highlight.js/lib/languages/typescript';
import xml from 'highlight.js/lib/languages/xml';
import yaml from 'highlight.js/lib/languages/yaml';
import { createLowlight } from 'lowlight';
import { computed, defineComponent, h, onBeforeUnmount, ref, type VNode } from 'vue';
import UiIcon from './UiIcon.vue';

const highlighter = createLowlight({
  bash, css, diff, dockerfile, go, ini, javascript, json, nginx, python, rust, sql, typescript, xml, yaml,
});
highlighter.registerAlias({ bash: ['shell', 'zsh'] });

type HighlightedNode = ReturnType<typeof highlighter.highlight>['children'][number];

function renderToken(node: HighlightedNode): string | VNode {
  if (node.type === 'text') return node.value;
  if (node.type === 'element') return h('span', { class: node.properties.className }, node.children.map(renderToken));
  return '';
}

export default defineComponent({
  props: {
    code: { type: String, required: true },
    language: { type: String, default: '' },
  },
  setup(props) {
    const tokens = computed(() => {
      const language = props.language.toLowerCase();
      return highlighter.registered(language) ? highlighter.highlight(language, props.code).children : null;
    });
    const state = ref<'idle' | 'copying' | 'copied' | 'failed'>('idle');
    const label = computed(() => ({
      idle: 'Copy',
      copying: 'Copy it…',
      copied: 'Copied',
      failed: 'Failed to copy',
    })[state.value]);
    let reset: ReturnType<typeof setTimeout> | undefined;
    let disposed = false;
    async function copy() {
      if (state.value === 'copying') return;
      clearTimeout(reset);
      state.value = 'copying';
      try {
        await navigator.clipboard.writeText(props.code);
        state.value = 'copied';
      } catch {
        state.value = 'failed';
      }
      if (!disposed) reset = setTimeout(() => { state.value = 'idle'; }, 1800);
    }
    onBeforeUnmount(() => {
      disposed = true;
      clearTimeout(reset);
    });

    return () => h('div', { class: 'chat-code' }, [
      h('div', { class: 'code-toolbar' }, [
        h('span', { class: 'code-language' }, props.language || 'Code'),
        h('button', { type: 'button', disabled: state.value === 'copying', onClick: copy }, [
          h(UiIcon, { name: state.value === 'copied' ? 'check' : 'copy', size: 14 }),
          h('span', { 'aria-live': 'polite' }, label.value),
        ]),
      ]),
      h('pre', [h('code', tokens.value ? tokens.value.map(renderToken) : props.code)]),
    ]);
  },
});
</script>

<style scoped>
.chat-code { margin: 0 0 0.75em; min-width: 0; border: 1px solid var(--line); border-radius: 8px; background: var(--subtle); }
.code-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 4px 8px 4px 12px; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 12px; }
.code-language { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
button { display: inline-flex; flex-shrink: 0; align-items: center; gap: 5px; padding: 4px 6px; border: 0; border-radius: 4px; background: transparent; color: inherit; font: inherit; cursor: pointer; }
button:hover:enabled { background: var(--hover); color: var(--text); }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
pre { margin: 0; padding: 10px 12px; overflow-x: auto; font-size: 12px; line-height: 1.6; }
.hljs-comment, .hljs-quote { color: var(--muted); font-style: italic; }
.hljs-keyword, .hljs-selector-tag, .hljs-tag, .hljs-deletion { color: var(--danger); }
.hljs-string, .hljs-regexp, .hljs-addition { color: var(--success); }
.hljs-number, .hljs-literal, .hljs-meta, .hljs-variable { color: var(--warning); }
.hljs-title, .hljs-built_in, .hljs-attr, .hljs-attribute, .hljs-type { color: var(--accent); }
.hljs-emphasis { font-style: italic; }
.hljs-strong { font-weight: 700; }
</style>
