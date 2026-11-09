import type { Settings } from './types';

export function automationBudgetError(settings: Settings): string | null {
  if (!Number.isSafeInteger(settings.runTokenLimit) || settings.runTokenLimit < 0)
    return 'Enter an integer non-negative number for a single launch budget.';
  const runs = settings.dailyRunLimit ?? 0;
  if (!Number.isSafeInteger(runs) || runs < 0 || runs > 1000)
    return 'Specify 0 without limit or 1 to 1,000 launches per day.';
  const tokens = settings.dailyTokenLimit ?? 0;
  if (tokens !== 0 && (!Number.isSafeInteger(tokens) || tokens < 1000 || tokens > 1000000000))
    return 'Specify 0 without limit or from 1,000 to 1,000,000 tokens per day.';
  return null;
}
