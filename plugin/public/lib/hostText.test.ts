import { EndpointNode, GraphNode } from '../../common';
import { coverageText, manufacturerText, nameSourceText, unmanagedText } from './hostText';

const host = (fields: Partial<EndpointNode>): GraphNode =>
  ({ node_id: 'host:x', kind: 'endpoint', agent_id: null, top_cves: [], ...fields } as GraphNode);

describe('unmanagedText', () => {
  it('says no agent reports from the machine', () => {
    expect(unmanagedText(host({ unmanaged: true }))).toBe(
      'No Wazuh agent reports from this machine, so its software and vulnerabilities are not known.'
    );
  });

  it('adds what an SNMP answer changes', () => {
    expect(unmanagedText(host({ unmanaged: true, snmp: true }))).toMatch(/answered the scan over SNMP/);
  });

  it('is empty for an agent and for a device', () => {
    expect(unmanagedText(host({ unmanaged: false, agent_id: '001' }))).toBe('');
    expect(unmanagedText({ node_id: 'device:a', kind: 'device' } as GraphNode)).toBe('');
  });
});

describe('manufacturerText', () => {
  it('names the maker, or says the address is randomised or virtual', () => {
    expect(manufacturerText(host({ mac_type: 'global', mac_vendor: 'Dell Inc.' }))).toBe('Dell Inc.');
    // a phone's private address and a virtual machine look the same: never "phone"
    expect(manufacturerText(host({ mac_type: 'local', mac_vendor: null }))).toBe(
      'Randomised or virtual address (names no manufacturer)'
    );
    expect(manufacturerText(host({ mac_type: 'global', mac_vendor: null }))).toBe('Not in the IEEE registry');
    expect(manufacturerText(host({}))).toBe('');
  });
});

describe('nameSourceText', () => {
  it('says where a name not from Wazuh came from', () => {
    expect(nameSourceText('dns')).toBe('Reverse DNS');
    expect(nameSourceText('snmp')).toBe('Its own SNMP system name');
    expect(nameSourceText(undefined)).toBe('');
  });
});

describe('coverageText', () => {
  it('counts the hosts with an agent', () => {
    expect(coverageText({ hosts: 10, managed: 7, unmanaged: 3, managed_share: 0.7 })).toBe(
      '7 of 10 hosts have a Wazuh agent'
    );
    expect(coverageText({ hosts: 1, managed: 1, unmanaged: 0, managed_share: 1 })).toBe(
      '1 of 1 host has a Wazuh agent'
    );
    expect(coverageText({ hosts: 0, managed: 0, unmanaged: 0, managed_share: null })).toBe('No hosts in this graph');
  });
});
