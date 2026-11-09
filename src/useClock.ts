import { onBeforeUnmount, onMounted, readonly, ref } from 'vue';

// One clock for the entire visible WebView, regardless of the number of timestamps.
const now = ref(Date.now() / 1000);
let users = 0;
let timer: ReturnType<typeof setInterval> | undefined;
function tick() { if (!document.hidden) now.value = Date.now() / 1000; }
function visibility() {
  clearInterval(timer);
  timer = undefined;
  if (!document.hidden) { tick(); timer = setInterval(tick, 15000); }
}

export function useClock() {
  onMounted(() => {
    if (users++ === 0) {
      document.addEventListener('visibilitychange', visibility);
      window.addEventListener('focus', tick);
      visibility();
    }
  });
  onBeforeUnmount(() => {
    if (--users === 0) {
      clearInterval(timer);
      timer = undefined;
      document.removeEventListener('visibilitychange', visibility);
      window.removeEventListener('focus', tick);
    }
  });
  return readonly(now);
}
