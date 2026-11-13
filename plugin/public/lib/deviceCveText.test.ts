import { CveLookup } from '../../common';
import {
  hasDeviceFindings,
  lookupDate,
  osvText,
  plural,
  potentialText,
  staleText,
  undecidedText,
  unscoredReason,
} from './deviceCveText';

const base: CveLookup = {
  status: 'ok',
  match: 'cpe',
  product: 'Cisco IOS 12.2(55)SE12',
  cpe: 'cpe:2.3:o:cisco:ios:12.2\\(55\\)se12:*:*:*:*:*:*:*',
  source: 'nvd',
  fetched_at: '2026-10-09T08:00:06+00:00',
  stale: false,
  total: 90,
};
const at = (l: Partial<CveLookup>) => ({ ...base, ...l });
const junos = (l: Partial<CveLookup> = {}) =>
  at({
    product: 'Juniper Junos JUNOS 20.2R2-S3.4',
    cpe: 'cpe:2.3:o:juniper:junos:20.2:r2-s3:*:*:*:*:*:*',
    source: 'juniper-cna+nvd',
    ...l,
  });

describe('potentialText', () => {
  it('says what the match rests on', () => {
    expect(potentialText(base)).toBe(
      'Potential: matched by software version (Cisco IOS 12.2(55)SE12) against NVD on 9 Oct 2026. ' +
        'A version match does not confirm the affected feature is in use.'
    );
  });

  it('says when only the product name matched', () => {
    expect(potentialText(at({ match: 'keyword', product: 'HP Comware 5.20.99 Release 1107', cpe: null }))).toBe(
      'Potential: matched by product name and version (HP Comware 5.20.99 Release 1107) in NVD descriptions ' +
        'on 9 Oct 2026. A version match does not confirm the affected feature is in use.'
    );
  });

  it('says when a service scan detected it', () => {
    expect(potentialText(at({ source: 'nmap', potential: true, product: 'OpenSSH 8.2p1' }))).toBe(
      'Potential, from service detection: nmap detected OpenSSH 8.2p1, looked up against NVD on 9 Oct 2026. ' +
        'A version match does not confirm the affected feature is in use.'
    );
  });

  it("says when a Junos device was matched against Juniper's own records", () => {
    expect(potentialText(junos())).toBe(
      "Potential: matched by software version (Juniper Junos JUNOS 20.2R2-S3.4) against Juniper's own CVE " +
        'records and NVD on 9 Oct 2026. A version match does not confirm the affected feature is in use.'
    );
  });

  it('is empty when nothing was matched', () => {
    expect(potentialText(at({ status: 'unavailable' }))).toBe('');
  });
});

describe('unscoredReason', () => {
  const dev = (cve_lookup?: CveLookup, pollable = true) => ({ kind: 'device', pollable, cve_lookup });

  it('says when Wazuh has no software inventory for a host', () => {
    expect(unscoredReason({ kind: 'endpoint', unscored_reason: 'no_inventory' })).toBe(
      'Wazuh has no software inventory for this host.'
    );
    expect(unscoredReason({ kind: 'endpoint' })).toBe('');
  });

  it('adds why the Wazuh server was not matched with OSV.dev', () => {
    const osv = { status: 'unavailable' as const, reason: 'OSV unavailable' };
    expect(unscoredReason({ kind: 'endpoint', unscored_reason: 'no_inventory', osv })).toBe(
      'Wazuh has no software inventory for this host. Its own package list was not matched with OSV.dev: OSV unavailable.'
    );
  });

  it('one sentence per status', () => {
    expect(unscoredReason(dev(at({ status: 'unidentified', match: null, product: null })))).toBe(
      'Its software could not be identified: the vendor, software family or version is missing.'
    );
    expect(unscoredReason(dev(at({ status: 'unidentified', match: null, product: null }), false))).toBe(
      'It was only seen in a neighbour’s table, never polled, so its software is unknown.'
    );
    expect(unscoredReason(dev(at({ status: 'unavailable' })))).toBe(
      'NVD could not be reached and nothing was cached; it will be looked up again on the next scan.'
    );
    expect(unscoredReason(dev(at({ status: 'unverified' })))).toBe(
      'NVD does not list Cisco IOS 12.2(55)SE12, so the lookup could not be confirmed.'
    );
    expect(unscoredReason(dev(at({ match: 'keyword', product: 'HP Comware 5.20.99 Release 1107', total: 0 })))).toBe(
      'NVD has no exact identifier for HP Comware 5.20.99 Release 1107, and no NVD entry names this product line and version.'
    );
  });

  it("says why a Junos device has no answer", () => {
    for (const reason of ['juniper_index_unavailable', 'juniper_records_incomplete']) {
      expect(unscoredReason(dev(junos({ status: 'unavailable', reason })))).toBe(
        "Juniper's CVE records are not all fetched yet; it will be looked up again on the next scan."
      );
    }
    expect(unscoredReason(dev(junos({ status: 'unavailable', reason: 'unreachable' })))).toBe(
      'NVD could not be reached and nothing was cached; it will be looked up again on the next scan.'
    );
    expect(
      unscoredReason(dev(junos({ status: 'unverified', reason: 'version_not_comparable', product: 'Juniper Junos JUNOS 15.1X49-D200.5' })))
    ).toBe(
      "Juniper Junos JUNOS 15.1X49-D200.5 is not a regular Junos release, so it cannot be compared with Juniper's CVE records."
    );
  });

  it('says why an identified device was not looked up', () => {
    expect(
      unscoredReason(dev(at({ status: 'unverified', reason: 'no_cpe_rule', match: 'none', cpe: null, product: 'Brocade Network OS 7.2.0a' })))
    ).toBe('Brocade Network OS 7.2.0a is identified, but NVD has no product name that fits it, so its CVEs are not looked up.');
    expect(
      unscoredReason(dev(at({ status: 'unverified', reason: 'model_not_mapped', product: 'ArubaOS-Switch 16.04.0024' })))
    ).toBe(
      'NVD files part of the CVEs for ArubaOS-Switch 16.04.0024 under the switch model, and this model is not known, so the lookup would be incomplete.'
    );
  });

  it('explains an older graph', () => {
    expect(unscoredReason(dev(undefined))).toBe(
      'This graph has no CVE lookup for devices; the next scan adds one.'
    );
  });

  it('has nothing to say for a scored device or an endpoint', () => {
    expect(unscoredReason(dev(base))).toBe('');
    expect(unscoredReason({ kind: 'endpoint' })).toBe('');
  });
});

describe('staleText and lookupDate', () => {
  it('marks a stale result with the date of the answer used', () => {
    expect(staleText(at({ stale: true }))).toBe(
      'NVD could not be reached; this is its answer from 9 Oct 2026.'
    );
    expect(staleText(base)).toBe('');
  });

  it("names Juniper's records for a stale Junos result", () => {
    expect(staleText(junos({ stale: true }))).toBe(
      "Juniper's CVE records or NVD could not all be refreshed; some answers are older (NVD's from 9 Oct 2026)."
    );
  });

  it('writes dates the same way everywhere', () => {
    // the viewer's own date: midday UTC is 9 Oct anywhere within 11 hours of UTC
    expect(lookupDate('2026-10-09T12:00:00+00:00')).toBe('9 Oct 2026');
    expect(lookupDate(null)).toBe('an unknown date');
    expect(lookupDate('garbage')).toBe('an unknown date');
  });
});

describe('hasDeviceFindings and plural', () => {
  it('lists findings for an exact match, or a keyword match that found some', () => {
    expect(hasDeviceFindings(base)).toBe(true);
    expect(hasDeviceFindings(at({ total: 0 }))).toBe(true);           // NVD lists none: say so
    expect(hasDeviceFindings(at({ match: 'keyword', total: 0 }))).toBe(false);
    expect(hasDeviceFindings(at({ match: 'keyword', total: 2 }))).toBe(true);
    expect(hasDeviceFindings(at({ status: 'unverified' }))).toBe(false);
    expect(hasDeviceFindings(undefined)).toBe(false);
  });

  it('counts in words', () => {
    expect(plural(1, 'device')).toBe('1 device');
    expect(plural(0, 'endpoint')).toBe('0 endpoints');
    expect(plural(5, 'network device')).toBe('5 network devices');
  });
});

describe('osvText', () => {
  it('names the source only when OSV gave results', () => {
    expect(osvText({ osv: { status: 'ok', reason: null } })).toBe(
      "Findings from the server's own package list (Wazuh doesn't index the manager), matched with OSV.dev; potential."
    );
    expect(osvText({ osv: { status: 'unavailable', reason: 'OSV unavailable' } })).toBe('');
    expect(osvText({})).toBe('');
  });
});

describe('undecidedText', () => {
  it("lists the CVEs Juniper's records make no claim on", () => {
    expect(undecidedText(junos({ undecided: ['CVE-2023-28985'] }))).toBe(
      "Juniper's records do not say whether this release is affected by 1 CVE: CVE-2023-28985. Check them by hand."
    );
    expect(undecidedText(junos({ undecided: ['CVE-2023-28985', 'CVE-2024-0001'] }))).toContain('by 2 CVEs: ');
  });

  it('is empty without undecided CVEs or an answer', () => {
    expect(undecidedText(junos({ undecided: [] }))).toBe('');
    expect(undecidedText(base)).toBe('');
    expect(undecidedText(junos({ status: 'unavailable', undecided: ['CVE-2023-28985'] }))).toBe('');
  });
});
