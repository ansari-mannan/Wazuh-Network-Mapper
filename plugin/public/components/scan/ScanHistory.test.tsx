/**
 * @jest-environment jsdom
 */
// The history panel and the overview card on two archived lab scans, where
// laptop-07's agent disconnected in the newer one.
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import labGraph from '../../../test/fixtures/lab.graph.json';
import labVulns from '../../../test/fixtures/lab.vulnerabilities.json';

const entry = (id: string, trigger: string) => ({
  id,
  time: '2026-10-13T10:00:00.000Z',
  trigger,
  files: ['graph.json', 'vulnerabilities.json'],
  counts: { devices: 5, endpoints: 6, cvesConfirmed: 20, cvesPotential: 7, configFindings: 4 },
  stages: labGraph.metadata.stages,
});
const newer = entry('2026-10-13T11-00-00-000Z', 'scheduled');
const older = entry('2026-10-13T10-00-00-000Z', 'manual');
const offlineGraph = {
  ...labGraph,
  nodes: labGraph.nodes.map((n: any) => (n.node_id === 'endpoint:104' ? { ...n, status: 'disconnected' } : n)),
};
const mockGet = jest.fn(async (url: string) => {
  if (url === '/api/vulnmapper/history') return [newer, older];
  return {
    current: { entry: newer, graph: offlineGraph, vulns: labVulns, attackPaths: null },
    previous: { entry: older, graph: labGraph, vulns: labVulns, attackPaths: null },
  };
});
const mockPush = jest.fn();
// one object, as in the app: hooks that depend on http must not refetch per render
const mockServices = { http: { get: mockGet }, history: { location: { search: '' }, push: mockPush } };
jest.mock('../../lib/services', () => ({ useServices: () => mockServices }));
jest.mock('../../lib/scan', () => ({ useScan: () => ({ scan: null }) }));

import { ScanHistory } from './ScanHistory';
import { SinceLastScan } from '../overview/SinceLastScan';

async function render(el: React.ReactElement) {
  const root = document.body.appendChild(document.createElement('div')); // React 16 listens on document
  await act(async () => {
    ReactDOM.render(el, root);
  });
  await act(async () => undefined); // the changes request
  return root;
}

it('lists the scans and shows what changed in the newest, with its stages', async () => {
  const root = await render(<ScanHistory />);
  expect(root.querySelectorAll('[data-test-subj^="vmHistoryRow-"]').length).toBe(2);
  expect(root.textContent).toMatch(/Scheduled/);
  const changes = root.querySelector('[data-test-subj="vmHistoryChanges"]')!.textContent;
  expect(changes).toMatch(/Went offline\s*laptop-07/);
  expect(changes).not.toMatch(/Removed/);
  expect(root.querySelector('[data-test-subj="vmScanStages"]')).not.toBeNull();
  expect(mockGet).toHaveBeenCalledWith(`/api/vulnmapper/history/${newer.id}/changes`);
});

it('sums the newest change up on the overview and links to it', async () => {
  const root = await render(<SinceLastScan />);
  expect(root.textContent).toMatch(/Since the last scan: 1 went offline\./);
  act(() => {
    (root.querySelector('button, a') as HTMLElement).click();
  });
  expect(mockPush).toHaveBeenCalledWith(`/scan?history=${newer.id}`);
});
