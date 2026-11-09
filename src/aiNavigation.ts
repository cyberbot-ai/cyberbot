import type { AgentStatus, Settings, Snapshot } from './types';

export type AiTab = 'sessions' | 'actions' | 'settings';
type CliChecks = Partial<Record<Settings['autoAgent'], boolean>>;
export const cliChecksKey = 'cyberbot.ai-cli-check.v1';

export function readCliChecks(): CliChecks {
  try {
    const value = JSON.parse(localStorage.getItem(cliChecksKey) ?? 'null');
    const checks: CliChecks = {};
    for (const agent of ['codex', 'claude'] as const) {
      if (typeof value?.[agent] === 'boolean') checks[agent] = value[agent];
    }
    return checks;
  } catch {
    return {};
  }
}

export function rememberCliChecks(previous: CliChecks, results: AgentStatus[]): CliChecks {
  const checks = { ...previous };
  for (const { name, ready } of results) {
    if ((name === 'codex' || name === 'claude') && typeof ready === 'boolean') checks[name] = ready;
  }
  try {
    localStorage.setItem(cliChecksKey, JSON.stringify(checks));
  } catch {
    // Keep the result in this window if local preferences are unavailable.
  }
  return checks;
}

export function initialAiTab(snapshot: Snapshot, checks: CliChecks): AiTab {
  if (checks[snapshot.settings.autoAgent] !== true) return 'settings';
  return snapshot.pendingActions ? 'actions' : 'sessions';
}
