import React from 'react';
import ReactDOM from 'react-dom';
import { AppMountParameters, CoreStart } from '../../../src/core/public';
import { VulnmapperApp } from './components/app';

export const renderApp = ({ http }: CoreStart, { appBasePath, element }: AppMountParameters) => {
  ReactDOM.render(<VulnmapperApp basename={appBasePath} http={http} />, element);

  return () => ReactDOM.unmountComponentAtNode(element);
};
