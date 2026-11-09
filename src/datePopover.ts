// Opening another date dismisses the previous popover without a watcher per row.
let dismiss: (() => void) | undefined;
export function activateDatePopover(close: () => void) {
  if (dismiss !== close) dismiss?.();
  dismiss = close;
}
export function releaseDatePopover(close: () => void) {
  if (dismiss === close) dismiss = undefined;
}
