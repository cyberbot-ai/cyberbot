import { serviceCatalog } from './services';
import type { SupervisedAction } from './types';

export interface ServiceActionPresentation {
  headline: string;
  approval: string;
  impact: string;
  success: string;
  risky: boolean;
  rollback: boolean;
}

type PresentAction = (action: SupervisedAction) => ServiceActionPresentation | undefined;
const presenters = import.meta.glob<PresentAction>('./components/service-panels/*Action.ts', {
  eager: true, import: 'default',
});

export function presentServiceAction(action?: SupervisedAction): ServiceActionPresentation | undefined {
  if (!action) return;
  const spec = Object.values(serviceCatalog).find(entry => entry.mutationKind === action.kind);
  if (!spec?.actionPresentation) return;
  return presenters[`./components/service-panels/${spec.actionPresentation}.ts`]?.(action);
}
