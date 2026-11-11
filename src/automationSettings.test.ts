import { describe, expect, it } from 'vitest';
import { automationBudgetError } from './automationSettings';
import type { Settings } from './types';
const settings: Settings = {mode:'auto',dailyRunLimit:4,dailyTokenLimit:200000,runTokenLimit:50000,autoAgent:'codex',pollSeconds:180,logPollSeconds:600,concurrency:4,paused:false, dockBadgeEnabled: true};
describe('automation setup budget', () => {
  it('accepts zero limits and legacy unset daily limits in AUTO', () => {
    expect(automationBudgetError({...settings,dailyRunLimit:0,dailyTokenLimit:0,runTokenLimit:0})).toBeNull();
    expect(automationBudgetError({...settings,dailyRunLimit:null,dailyTokenLimit:null})).toBeNull();
  });
  it.each([1, 1000001])('allows session budgets outside the previous bounds (%d)', runTokenLimit => {
    expect(automationBudgetError({...settings,runTokenLimit})).toBeNull();
  });
  it.each([{dailyRunLimit:1.5},{dailyTokenLimit:NaN},{runTokenLimit:-1},{runTokenLimit:1.5},{runTokenLimit:Number.MAX_SAFE_INTEGER+1}])('rejects an unusable budget %j', patch => {
    expect(automationBudgetError({...settings,...patch})).not.toBeNull();
  });
});
