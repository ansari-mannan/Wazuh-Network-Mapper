/**
 * @jest-environment jsdom
 */
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';

const graph = {
  nodes: [],
  edges: [],
  metadata: {
    warnings: [{ type: 'snmp_fallback', devices: ['CYFOR-HP-Switch', 'L2-Switch'] }],
    snmp: { entered: ['device:a'], server: ['device:b', 'device:c'] },
  },
};
jest.mock('../../lib/graph', () => ({ useGraph: () => ({ graph, loading: false, error: null, reload: async () => {} }) }));
jest.mock('../../lib/services', () => ({ useServices: () => ({ history: { push: () => {} } }) }));
jest.mock('./SinceLastScan', () => ({ SinceLastScan: () => null }));
jest.mock('./SummaryPanels', () => ({ SummaryPanels: () => null }));
jest.mock('../layout/ThemeToggle', () => ({ ThemeToggle: () => null }));

import { Overview } from './Overview';

it('lists an SNMP fallback in the warnings callout, without a dismiss button', () => {
  const root = document.createElement('div');
  act(() => {
    ReactDOM.render(<Overview />, root);
  });
  const callout = root.querySelector('[data-test-subj="vmScanWarnings"]');
  expect(callout?.textContent).toContain(
    "The community you entered didn't work on CYFOR-HP-Switch, L2-Switch; the server's SNMP settings were used for them."
  );
  expect(callout?.querySelector('button')).toBeNull();
  ReactDOM.unmountComponentAtNode(root);
});
