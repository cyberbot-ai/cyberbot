import { onBeforeUnmount, reactive, ref, watch } from 'vue';
import { updateSettings } from './settings';
import type { Settings } from './types';

type Validation = { patch: Partial<Settings>; error: string };

export function useSettingsAutosave<K extends keyof Settings>(
  current: () => Settings,
  fields: readonly K[],
  validate: (draft: Settings, dirty: ReadonlySet<K>, current: Settings) => Validation,
  saved: (settings: Settings) => void,
  automatic: () => boolean = () => true,
) {
  const draft = reactive({ ...current() });
  const saving = ref(false), error = ref('');
  const dirty = new Map<K, number>();
  let revision = 0, failedRevision = -1, timer: ReturnType<typeof setTimeout> | undefined, disposed = false;
  watch(current, settings => {
    for (const field of fields) if (!dirty.has(field)) Object.assign(draft, { [field]: settings[field] });
  });

  function edited(field: K) {
    dirty.set(field, ++revision);
    error.value = '';
    clearTimeout(timer);
    if (automatic()) timer = setTimeout(() => { void flush(); }, 250);
  }

  async function flush() {
    clearTimeout(timer);
    if (!automatic() || saving.value || !dirty.size || revision === failedRevision) return;
    const result = validate(draft, new Set(dirty.keys()), current());
    error.value = result.error;
    const patch: Partial<Settings> = {};
    for (const field of fields) {
      if (!Object.prototype.hasOwnProperty.call(result.patch, field)) continue;
      if (result.patch[field] === current()[field]) dirty.delete(field);
      else Object.assign(patch, { [field]: result.patch[field] });
    }
    if (!Object.keys(patch).length) return;
    const sent = new Map(dirty), sentRevision = revision;
    saving.value = true;
    try {
      const settings = await updateSettings(patch);
      for (const field of fields) {
        if (Object.prototype.hasOwnProperty.call(patch, field) && dirty.get(field) === sent.get(field)) {
          dirty.delete(field);
          Object.assign(draft, { [field]: settings[field] });
        }
      }
      if (!disposed) saved(settings);
    } catch (e) {
      failedRevision = sentRevision;
      if (!disposed) error.value = String(e).replace(/^Error: /, '');
    } finally {
      saving.value = false;
      // Drain newer edits only. Failed unchanged values are never retried.
      if (revision !== sentRevision) void flush();
    }
  }

  onBeforeUnmount(() => { void flush(); disposed = true; clearTimeout(timer); });
  return { draft, saving, error, edited, flush };
}
