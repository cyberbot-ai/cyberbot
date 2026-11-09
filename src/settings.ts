import { call } from './api';
import type { Settings } from './types';

let queue: Promise<void> = Promise.resolve();
const listeners = new Set<(settings: Settings) => void>();

export function onSettingsSaved(listener: (settings: Settings) => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

// Serialize writers in this window; the backend atomically merges partial
// updates from all windows. A failed write must not block subsequent edits.
export function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  const result = queue.then(async () => {
    const settings = await call<Settings>('update_settings', { patch });
    for (const listener of listeners) listener(settings);
    return settings;
  });
  queue = result.then(() => {}, () => {});
  return result;
}
