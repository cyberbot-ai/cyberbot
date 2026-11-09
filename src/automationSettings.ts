import type { Settings } from './types';

export function automationBudgetError(settings: Settings): string | null {
  if (!Number.isSafeInteger(settings.runTokenLimit) || settings.runTokenLimit < 0)
    return 'Enter a nonnegative whole number of tokens per run.';
  const runs = settings.dailyRunLimit ?? 0;
  if (!Number.isSafeInteger(runs) || runs < 0 || runs > 1000)
    return 'Enter 1 to 1,000 runs per day, or 0 for no limit.';
  const tokens = settings.dailyTokenLimit ?? 0;
  if (tokens !== 0 && (!Number.isSafeInteger(tokens) || tokens < 1000 || tokens > 1000000000))
    return 'Enter 1,000 to 1,000,000 tokens per day, or 0 for no limit.';
  return null;
}
