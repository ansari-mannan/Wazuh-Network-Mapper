// The dashboard's core services (HTTP, chrome, notifications, ui settings,
// history), handed
// down to every component through a React context.
import { createContext, useContext } from 'react';
import { CoreStart, ScopedHistory } from '../../../../src/core/public';

export interface Services {
  http: CoreStart['http'];
  chrome: CoreStart['chrome'];
  notifications: CoreStart['notifications'];
  uiSettings: CoreStart['uiSettings'];
  history: ScopedHistory;
}

const ServicesContext = createContext<Services | null>(null);

export const ServicesProvider = ServicesContext.Provider;

export function useServices(): Services {
  const services = useContext(ServicesContext);
  if (!services) throw new Error('useServices must be used inside ServicesProvider');
  return services;
}
