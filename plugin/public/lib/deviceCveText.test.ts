import { CveLookup } from '../../common';
import { hasDeviceFindings, lookupDate, plural, potentialText, staleText, unscoredReason } from './deviceCveText';

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

  it('is empty when nothing was matched', () => {
    expect(potentialText(at({ status: 'unavailable' }))).toBe('');
  });
});

describe('unscoredReason', () => {
  const dev = (cve_lookup?: CveLookup, pollable = true) => ({ kind: 'device', pollable, cve_lookup });

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
