import type { ServiceActionPresentation } from '../../serviceActions';
import type { SupervisedAction } from '../../types';

export default function presentAction(action: SupervisedAction): ServiceActionPresentation | undefined {
  if (action.kind !== 'nginx_workers') return;
  const { workerProcesses, activation } = action;
  const risky = activation !== 'none';
  const activationText = activation === 'reload' ? ' Cyberbot will reload Nginx.'
    : activation === 'restart' ? ' Cyberbot will restart nginx.service.' : '';
  return {
    headline: `Nginx: worker_processes → ${workerProcesses}`,
    approval: `Cyberbot will back up, validate, and replace the Nginx configuration.${activationText}`,
    impact: `Cyberbot will back up the Nginx configuration, validate the change, and set worker_processes to ${workerProcesses}.${activationText}${risky ? ' Connections may drop.' : ''}`,
    success: 'Nginx configuration applied and verified.',
    risky,
    rollback: true,
  };
}
