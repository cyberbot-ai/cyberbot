import type { Component } from 'vue';
import ServicePanel from './components/ServicePanel.vue';
import { serviceCatalog } from './services';

const panels = import.meta.glob<Component>('./components/service-panels/*.vue', {
  eager: true, import: 'default',
});

export function servicePanel(kind: string): Component {
  const panel = serviceCatalog[kind]?.panel;
  return panels[`./components/service-panels/${panel}.vue`] ?? ServicePanel;
}
