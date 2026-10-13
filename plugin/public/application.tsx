// Mounts the React app into the element the dashboard gives it, with the
// core services the pages use.
import React from 'react';
import ReactDOM from 'react-dom';
import { AppMountParameters, CoreStart } from '../../../src/core/public';
import { VulnmapperApp } from './components/app';

export const renderApp = (
  { http, chrome, notifications }: CoreStart,
  { element, history }: AppMountParameters
) => {
  ReactDOM.render(
    <VulnmapperApp services={{ http, chrome, notifications, history }} />,
    element
  );

  return () => ReactDOM.unmountComponentAtNode(element);
};
