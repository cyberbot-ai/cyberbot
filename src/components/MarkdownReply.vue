<script lang="ts">
import MarkdownIt, { type Token } from 'markdown-it';
import { computed, defineComponent, h, type VNode } from 'vue';
import ChatCodeBlock from './ChatCodeBlock.vue';

const markdown = new MarkdownIt({ html: false });
markdown.validateLink = url => /^https?:\/\//i.test(url);

type Content = string | VNode;

function renderTokens(tokens: Token[]): Content[] {
  const root: Content[] = [];
  const stack: { token: Token; children: Content[] }[] = [];
  for (const token of tokens) {
    if (token.hidden) continue;
    if (token.nesting === 1) {
      stack.push({ token, children: [] });
      continue;
    }

    let content: Content[];
    if (token.nesting === -1) {
      const frame = stack.pop()!;
      const tag = frame.token.tag;
      const props = tag === 'a'
        ? { href: frame.token.attrGet('href'), target: '_blank', rel: 'noopener noreferrer' }
        : tag === 'ol' ? { start: frame.token.attrGet('start') } : null;
      const node = h(tag, props, frame.children);
      content = [tag === 'table' ? h('div', { class: 'table-scroll' }, [node]) : node];
    } else if (token.children && token.type === 'inline') {
      content = renderTokens(token.children);
    } else if (token.type === 'fence' || token.type === 'code_block') {
      const language = token.info.trim().split(/\s+/, 1)[0];
      content = [h(ChatCodeBlock, { code: token.content, language })];
    } else if (token.type === 'code_inline') {
      content = [h('code', token.content)];
    } else if (token.type === 'hr' || token.type === 'softbreak' || token.type === 'hardbreak') {
      content = [h(token.type === 'hr' ? 'hr' : 'br')];
    } else {
      // Image tokens contribute their alt text, so rendering a reply never fetches an image.
      content = [token.content];
    }
    (stack.at(-1)?.children ?? root).push(...content);
  }
  return root;
}

export default defineComponent({
  props: { text: { type: String, required: true } },
  setup(props) {
    const tokens = computed(() => markdown.parse(props.text, {}));
    return () => h('div', { class: 'message-text' }, renderTokens(tokens.value));
  },
});
</script>

<style scoped>
.message-text { font-size: 14px; line-height: 1.65; }
p, ul, ol, blockquote, .table-scroll, hr { margin: 0 0 0.75em; }
.message-text > :last-child { margin-bottom: 0; }
h1, h2, h3, h4, h5, h6 { margin: 1em 0 0.4em; font-weight: 650; line-height: 1.3; }
.message-text > :first-child { margin-top: 0; }
h1 { font-size: 1.4em; }
h2 { font-size: 1.25em; }
h3 { font-size: 1.12em; }
h4, h5, h6 { font-size: 1em; }
ul, ol { padding-inline-start: 1.6em; }
li + li { margin-top: 0.2em; }
li > ul, li > ol, li > p:last-child, blockquote > :last-child { margin-bottom: 0; }
blockquote { padding-inline-start: 12px; border-inline-start: 3px solid var(--line-strong); color: var(--muted); }
a { color: var(--accent); text-underline-offset: 0.18em; }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
code { padding: 0.12em 0.32em; border-radius: 4px; background: var(--subtle); font-size: 0.9em; }
.table-scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 0.94em; }
th, td { padding: 6px 10px; text-align: start; vertical-align: top; }
th { background: var(--subtle); }
td { border-top: 1px solid var(--line); }
hr { border: 0; border-top: 1px solid var(--line); }
</style>
