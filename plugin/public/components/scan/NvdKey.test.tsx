/**
 * @jest-environment jsdom
 */
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';

let mockState: unknown = { source: 'none', savedAt: null };
const mockServices = { http: { get: async () => mockState }, notifications: {} };
jest.mock('../../lib/services', () => ({ useServices: () => mockServices }));

import { NvdKey, nvdKeyText } from './NvdKey';

it('shows the field, its buttons and only the status', async () => {
  mockState = { source: 'env', savedAt: null };
  const root = document.createElement('div');
  await act(async () => {
    ReactDOM.render(<NvdKey />, root);
  });
  expect(root.querySelector('[data-test-subj="vmNvdKeyStatus"]')?.textContent).toBe("Key from the server's environment");
  expect((root.querySelector('[data-test-subj="vmNvdKeyField"]') as HTMLInputElement).type).toBe('password');
  expect((root.querySelector('[data-test-subj="vmNvdKeyField"]') as HTMLInputElement).value).toBe('');
  expect(root.textContent).toContain('Get a free key at nvd.nist.gov/developers/request-an-api-key. Saved on the server, used for NVD lookups.');
  expect((root.querySelector('[data-test-subj="vmNvdKeyRemove"]') as HTMLButtonElement).disabled).toBe(true);
  expect((root.querySelector('[data-test-subj="vmNvdKeyTest"]') as HTMLButtonElement).disabled).toBe(false);
  ReactDOM.unmountComponentAtNode(root);
});

it('words each status', () => {
  expect(nvdKeyText({ source: 'saved', savedAt: '2026-10-26T09:00:00Z' })).toBe(
    `Key set (saved here on ${new Date('2026-10-26T09:00:00Z').toLocaleDateString()})`
  );
  expect(nvdKeyText({ source: 'env', savedAt: null })).toBe("Key from the server's environment");
  expect(nvdKeyText({ source: 'none', savedAt: null })).toBe('No key (slower lookups)');
});
