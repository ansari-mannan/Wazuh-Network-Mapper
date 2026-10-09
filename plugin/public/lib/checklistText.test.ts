import { ConfigReference, ConfigSummary, DeviceNode, GraphNode } from '../../common';
import {
  configFindingCounts,
  evidenceLines,
  noChecklistText,
  portList,
  referenceText,
  severityLabel,
  shortPort,
  sortFindings,
  summaryLine,
} from './checklistText';

const summary = (over: Partial<ConfigSummary> = {}): ConfigSummary => ({
  checks: 8,
  results: { pass: 0, fail: 5, not_applicable: 0, unknown: 2, not_checked: 1 },
  findings: { high: 0, medium: 3, low: 0, advisory: 2 },
  ...over,
});

const stig: ConfigReference = {
  source: 'DISA',
  document: 'Cisco IOS Switch L2S STIG',
  release: 'V3R3 (2026-09-01)',
  rule_id: 'V-220630',
  stig_id: 'CISC-L2-000100',
  srg_id: 'SRG-NET-000362-L2S-000022',
  title: 'BPDU Guard',
  url: 'https://cyber.trackr.live/stig/Cisco_IOS_Switch_L2S/3/3/V-220630',
  severity: 'medium',
  category: 'CAT II',
  cci: 'CCI-002385',
  nist: 'SC-5 a',
  relation: 'requires',
};

function device(over: Partial<DeviceNode> = {}): GraphNode {
  return {
    node_id: 'device:aa',
    kind: 'device',
    ip: null,
    hostname: 'sw1',
    vendor: 'Cisco',
    model: null,
    firmware: null,
    serial: null,
    mac: null,
    discovery_method: 'snmp_lldp',
    status: 'online',
    risk_score: null,
    discovery_order: 0,
    parent_id: null,
    role: 'l2-switch',
    pollable: true,
    ...over,
  } as GraphNode;
}

describe('summaryLine', () => {
  it('counts the failures by severity, then the rest', () => {
    expect(summaryLine(summary())).toBe('5 of 8 checks failed (3 medium, 2 advisory); 2 unknown, 1 not checked.');
  });

  it('says when nothing failed', () => {
    expect(
      summaryLine(
        summary({
          results: { pass: 3, fail: 0, not_applicable: 4, unknown: 0, not_checked: 1 },
          findings: { high: 0, medium: 0, low: 0, advisory: 0 },
        })
      )
    ).toBe('None of 8 checks failed; 3 passed, 1 not checked, 4 not applicable.');
  });

  it('puts high first', () => {
    expect(
      summaryLine(
        summary({
          results: { pass: 0, fail: 4, not_applicable: 2, unknown: 1, not_checked: 1 },
          findings: { high: 2, medium: 1, low: 0, advisory: 1 },
        })
      )
    ).toBe('4 of 8 checks failed (2 high, 1 medium, 1 advisory); 1 unknown, 1 not checked, 2 not applicable.');
  });
});

describe('severity', () => {
  it('shows a check with no published severity as Advisory', () => {
    expect(severityLabel(null)).toBe('Advisory');
    expect(severityLabel('medium')).toBe('Medium');
  });

  it('lists advisories after the rated findings', () => {
    const f = (id: string, severity: 'high' | 'medium' | null) =>
      ({ id, severity } as Parameters<typeof sortFindings>[0][number]);
    expect(sortFindings([f('a', null), f('b', 'medium'), f('c', 'high')]).map((x) => x.id)).toEqual(['c', 'b', 'a']);
  });
});

describe('ports', () => {
  it('shortens Ethernet names as the map does', () => {
    expect(shortPort('FastEthernet1/0/3')).toBe('Fa1/0/3');
    expect(shortPort('GigabitEthernet0')).toBe('Gi0');
    expect(shortPort('Port-channel1')).toBe('Port-channel1');
  });

  it('names a few and counts the rest from the total', () => {
    expect(portList(['FastEthernet1/0/3'])).toBe('Fa1/0/3');
    expect(portList(['Fa1/0/3', 'Fa1/0/7'])).toBe('Fa1/0/3 and Fa1/0/7');
    expect(portList(['Fa1/0/3', 'Fa1/0/7', 'Fa1/0/8'])).toBe('Fa1/0/3, Fa1/0/7 and Fa1/0/8');
    // the evidence holds at most 20 names; the total is the real count
    const twenty = Array.from({ length: 20 }, (_, i) => `Fa0/${i + 1}`);
    expect(portList(twenty, 48)).toBe('Fa0/1, Fa0/2, Fa0/3 and 45 more');
  });
});

describe('evidenceLines', () => {
  it('names spare ports with their VLAN and says how many are shut down', () => {
    expect(
      evidenceLines('spare-ports-in-used-vlan', {
        ports: [
          { port: 'FastEthernet1/0/5', vlan: 40 },
          { port: 'GigabitEthernet1/0/1', vlan: 1 },
        ],
        total: 2,
        enabled: 1,
        shut_down: 1,
        down_recently_not_counted: 0,
      })
    ).toEqual([
      '2 ports: Fa1/0/5 (VLAN 40) and Gi1/0/1 (VLAN 1).',
      'None has had a link since the device started; 1 is enabled, 1 shut down.',
    ]);
    expect(
      evidenceLines('spare-ports-in-used-vlan', {
        ports: [{ port: 'Fa0/2', vlan: 10 }],
        total: 1,
        enabled: 1,
        shut_down: 0,
        down_recently_not_counted: 2,
      })[2]
    ).toBe('2 ports lost their link later and are not counted: it may be a computer that is switched off.');
  });

  it('tells a port found by the connection test from a listed one', () => {
    expect(evidenceLines('mgmt-telnet-enabled', { port: 23 })).toEqual(['The device lists TCP port 23 as in use.']);
    expect(
      evidenceLines('mgmt-telnet-enabled', { port: 23, found_by: 'the port answered a connection test' })
    ).toEqual(['TCP port 23 accepted a connection from the scanner.']);
  });

  it('says how many default-VLAN ports have a device attached', () => {
    expect(evidenceLines('access-ports-default-vlan', { ports: ['Gi1/0/1', 'Gi1/0/2'], total: 2, with_link: 0 })).toEqual([
      '2 ports: Gi1/0/1 and Gi1/0/2.',
      'None of them has a device attached at the moment.',
    ]);
    expect(evidenceLines('access-ports-default-vlan', { ports: ['Fa0/3'], total: 1, with_link: 1 })[1]).toBe(
      '1 has a device attached and is listed first.'
    );
  });

  it('describes services and SNMP', () => {
    expect(evidenceLines('mgmt-telnet-enabled', { port: 23 })).toEqual(['The device lists TCP port 23 as in use.']);
    expect(evidenceLines('snmp-no-auth', { snmp_version: 'v2c' })).toEqual(['The scan polled it with SNMP v2c.']);
    expect(
      evidenceLines('snmp-default-community', { communities: ['public'], found_by: 'the default-name probe' })
    ).toEqual(['It answers to “public”, found by the default-name probe.']);
    expect(evidenceLines('x', null)).toEqual([]);
  });
});

describe('referenceText', () => {
  it('names the publisher, rule and category', () => {
    expect(referenceText(stig)).toBe('DISA STIG V-220630, CAT II');
    expect(referenceText({ ...stig, document: 'Layer 2 Switch SRG', rule_id: 'V-206655' })).toBe(
      'DISA SRG V-206655, CAT II'
    );
    expect(referenceText({ ...stig, relation: 'related', rule_id: 'V-220641' })).toBe(
      'Related: DISA STIG V-220641, CAT II'
    );
  });

  it('gives NVD’s own CVSS score', () => {
    expect(
      referenceText({
        ...stig,
        source: 'NVD',
        document: 'National Vulnerability Database',
        rule_id: 'CVE-1999-0517',
        category: null,
        cvss: { version: '2.0', score: 7.5, vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P', source: 'nvd@nist.gov' },
      })
    ).toBe('NVD CVE-1999-0517, CVSS 2.0 7.5');
  });
});

describe('noChecklistText', () => {
  const meta = { checklist: { devices_checked: 4, results: summary().results, findings: summary().findings, probe_enabled: false, source: 'scan' } };

  it('is empty when the device has its checks', () => {
    expect(noChecklistText(device({ config_checks: [] }), meta)).toBe('');
  });

  it('explains each reason for having none', () => {
    expect(noChecklistText(device({ pollable: false }), meta)).toMatch(/never polled/);
    expect(noChecklistText(device(), {})).toBe('This graph has no configuration checks; the next scan adds them.');
    expect(
      noChecklistText(device(), { checklist: { ...meta.checklist, source: 'captures 2026-10-08' } })
    ).toBe('The configuration checks in this graph come from captures 2026-10-08; this device was not among them.');
  });
});

describe('configFindingCounts', () => {
  it('adds up the checked devices only', () => {
    const nodes = [
      device({ config_summary: summary() }),
      device({ node_id: 'device:bb', config_summary: summary({ findings: { high: 2, medium: 1, low: 0, advisory: 1 } }) }),
      device({ node_id: 'device:cc' }),
    ];
    expect(configFindingCounts(nodes)).toEqual({
      counts: { high: 2, medium: 4, low: 0, advisory: 3 },
      devices: 2,
      withFindings: 2,
      total: 9,
    });
  });
});
