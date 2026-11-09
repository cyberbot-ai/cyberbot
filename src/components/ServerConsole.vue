<script setup lang="ts">
import { Channel } from '@tauri-apps/api/core';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import terminalCss from '@xterm/xterm/css/xterm.css?inline';
import { nextTick, onActivated, onBeforeUnmount, onDeactivated, ref } from 'vue';
import { call, preview } from '../api';

const props = defineProps<{ serverId: string }>();
const host = ref<HTMLDivElement>();
const phase = ref<'idle' | 'connecting' | 'connected' | 'closing' | 'ended'>('idle');
const error = ref('');
const exitCode = ref<number | null>(null);
const labels = {
  idle: 'Ready to connect',
  connecting: 'Connecting via SSH…',
  connected: 'SSH connected',
  closing: 'Disconnecting…',
  ended: 'Session ended',
};

type Size = { rows: number; cols: number };
type ConsoleEvent =
  | { kind: 'ready' }
  | { kind: 'output'; sequence: number; bytes: number[] }
  | { kind: 'end'; code: number | null; error: string | null };
type Message =
  | { kind: 'input'; bytes: number[] }
  | { kind: 'resize'; size: Size }
  | { kind: 'ack'; sequence: number };
type Session = {
  open: Promise<string>;
  closing?: Promise<void>;
  terminal: Terminal;
  input: Uint8Array[];
  inputBytes: number;
  writing: boolean;
  size?: Size;
  resizing: boolean;
};

const chunkSize = 16 * 1024;
const maxQueuedInput = 256 * 1024;
const encoder = new TextEncoder();
let session: Session | undefined;
let terminal: Terminal | undefined;
let fitAddon: FitAddon | undefined;
let observer: ResizeObserver | undefined;
let frame = 0;
let visible = true;
let disposed = false;

function initTerminal(element: HTMLDivElement) {
  observer?.disconnect();
  terminal?.dispose();
  const root = element.shadowRoot ?? element.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = terminalCss;
  const viewport = document.createElement('div');
  viewport.style.width = '100%';
  viewport.style.height = '100%';
  root.replaceChildren(style, viewport);
  const term = new Terminal({
    disableStdin: true,
    fontFamily: 'ui-monospace, Menlo, monospace',
    scrollback: 3000,
    theme: { background: '#171b19', foreground: '#eef3ee', cursor: '#d0e5d0' },
  });
  terminal = term;
  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.parser.registerOscHandler(52, () => true);
  term.parser.registerOscHandler(8, () => true);
  term.open(viewport);
  term.textarea?.setAttribute('aria-label', 'SSH command input');
  term.attachCustomKeyEventHandler(event => {
    if (event.key === 'Escape' && event.type === 'keydown') {
      event.preventDefault();
      event.stopPropagation();
    }
    return true;
  });
  term.onData(data => enqueueInput(encoder.encode(data)));
  term.onBinary(data => enqueueInput(Uint8Array.from(data, char => char.charCodeAt(0))));
  observer = new ResizeObserver(scheduleFit);
  observer.observe(element);
  fit();
  return term;
}

function sizeOf(term: Terminal): Size {
  return { cols: term.cols, rows: term.rows };
}

function fit() {
  if (!visible || !host.value?.clientWidth || !host.value.clientHeight || !terminal) return;
  const size = fitAddon?.proposeDimensions();
  if (!size) return;
  const cols = Math.min(1024, size.cols);
  const rows = Math.min(512, size.rows);
  if (cols === terminal.cols && rows === terminal.rows) return;
  terminal.resize(cols, rows);
  if (session && phase.value === 'connected') resize(session);
}

function scheduleFit() {
  if (frame || !visible) return;
  frame = requestAnimationFrame(() => {
    frame = 0;
    fit();
  });
}

async function send(current: Session, message: Message) {
  const id = await current.open;
  if (session === current && !current.closing) await call('console_send', { id, message });
}

function resize(current: Session) {
  current.size = sizeOf(current.terminal);
  if (!current.resizing) void flushSize(current);
}

async function flushSize(current: Session) {
  current.resizing = true;
  try {
    while (session === current && !current.closing && current.size) {
      const size = current.size;
      current.size = undefined;
      await send(current, { kind: 'resize', size });
    }
  } catch {
    // A closing channel reports its final state through the event stream.
  } finally {
    current.resizing = false;
  }
}

function enqueueInput(data: Uint8Array) {
  const current = session;
  if (!current || phase.value !== 'connected' || !data.length) return;
  if (current.inputBytes + data.length > maxQueuedInput) {
    error.value = 'Input is too large. Paste smaller chunks of text.';
    return;
  }
  error.value = '';
  current.input.push(data);
  current.inputBytes += data.length;
  if (!current.writing) void flushInput(current);
}

async function flushInput(current: Session) {
  current.writing = true;
  try {
    while (session === current && !current.closing && current.input.length) {
      const data = current.input.shift()!;
      for (let offset = 0; offset < data.length && session === current && !current.closing; offset += chunkSize) {
        await send(current, { kind: 'input', bytes: Array.from(data.subarray(offset, offset + chunkSize)) });
      }
      current.inputBytes -= data.length;
    }
  } catch (cause) {
    if (session === current && !current.closing) {
      error.value = String(cause);
      disconnect();
    }
  } finally {
    current.writing = false;
  }
}

function receive(current: Session, event: ConsoleEvent) {
  if (session !== current) return;
  if (event.kind === 'end') {
    current.terminal.options.disableStdin = true;
    exitCode.value = event.code;
    if (event.error) error.value = event.error;
    session = undefined;
    phase.value = 'ended';
    return;
  }
  if (current.closing) return;
  if (event.kind === 'ready') {
    phase.value = 'connected';
    current.terminal.options.disableStdin = false;
    resize(current);
    if (visible) current.terminal.focus();
  } else {
    current.terminal.write(Uint8Array.from(event.bytes), () => {
      void send(current, { kind: 'ack', sequence: event.sequence }).catch(() => {});
    });
  }
}

async function connect() {
  if (preview || session || phase.value === 'connecting' || !host.value) return;
  phase.value = 'connecting';
  error.value = '';
  exitCode.value = null;
  await nextTick();
  if (disposed || !host.value) return;
  let current: Session | undefined;
  try {
    const term = initTerminal(host.value);
    const onEvent = new Channel<ConsoleEvent>(event => {
      if (current) receive(current, event);
    });
    const open = call<string>('console_open', { serverId: props.serverId, size: sizeOf(term), onEvent });
    current = { open, terminal: term, input: [], inputBytes: 0, writing: false, resizing: false };
    session = current;
    await open;
  } catch (cause) {
    if (session === current) {
      if (!current?.closing) error.value = String(cause);
      session = undefined;
      phase.value = 'ended';
    }
  }
}

function close(current: Session) {
  current.terminal.options.disableStdin = true;
  current.closing ??= current.open.then(id => call<void>('console_close', { id }));
  return current.closing;
}

function disconnect() {
  const current = session;
  if (!current) return;
  phase.value = 'closing';
  void close(current).catch(cause => {
    if (session === current) {
      error.value = String(cause);
      current.closing = undefined;
      phase.value = 'connected';
      current.terminal.options.disableStdin = false;
    }
  });
}

onActivated(() => {
  visible = true;
  void nextTick(() => {
    fit();
    if (visible && phase.value === 'connected') terminal?.focus();
  });
});
onDeactivated(() => { visible = false; });
onBeforeUnmount(() => {
  disposed = true;
  visible = false;
  if (session) void close(session).catch(() => {});
  session = undefined;
  cancelAnimationFrame(frame);
  observer?.disconnect();
  terminal?.dispose();
});
</script>

<template>
  <section class="console" aria-label="Server console">
    <header v-if="!preview" class="toolbar">
      <span role="status">{{ labels[phase] }}<template v-if="exitCode !== null"> · exit code {{ exitCode }}</template></span>
      <button v-if="phase === 'idle' || phase === 'ended'" type="button" @click="connect">
        {{ phase === 'idle' ? 'Connect' : 'Connect again' }}
      </button>
      <button v-else type="button" :disabled="phase === 'closing'" @click="disconnect">Disconnect</button>
    </header>
    <p v-if="preview" class="notice">SSH console is available in the Cyberbot desktop app.</p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <div v-if="!preview" v-show="phase !== 'idle'" ref="host" class="terminal"/>
  </section>
</template>

<style scoped>
.console{display:flex;flex:1;flex-direction:column;gap:10px;min-width:0;min-height:0}
.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;color:var(--muted);font-size:12px}
button{min-height:34px;padding:6px 11px;font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:7px;cursor:pointer}
button:hover{background:var(--hover)}
button:disabled{opacity:.45;cursor:default}
button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.terminal{flex:1;min-width:0;min-height:0;overflow:hidden;border:1px solid var(--line);border-radius:7px;padding:8px;background:#171b19}
.terminal:focus-within{border-color:var(--accent)}
.notice,.error{margin:0;overflow-wrap:anywhere}
.notice{color:var(--muted)}
.error{color:var(--danger)}
</style>
