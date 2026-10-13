/**
 * @jest-environment jsdom
 */
import { printWithTitle, reportFileName } from './print';

describe('printWithTitle', () => {
  let events: string[];
  let docTitle: { change: jest.Mock };

  beforeEach(() => {
    events = [];
    document.title = 'Vulnerability report - Network Topology Mapper - Wazuh';
    // like the dashboard's service: the base title is appended
    docTitle = {
      change: jest.fn((t: string | string[]) => {
        const parts = typeof t === 'string' ? [t] : t;
        document.title = [...parts, 'Wazuh'].join(' - ');
        events.push(`title: ${parts.join(' / ')}`);
      }),
    };
    jest.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      cb(0);
      return 0;
    });
  });
  afterEach(() => jest.restoreAllMocks());

  it('sets the name, prints with exactly that title, restores after printing', async () => {
    jest.spyOn(window, 'print').mockImplementation(() => {
      events.push(`print: ${document.title}`);
      window.dispatchEvent(new Event('afterprint'));
    });
    const name = reportFileName('2026-10-08');
    await printWithTitle(docTitle, name, ['Vulnerability report', 'Network Topology Mapper']).done;
    expect(events).toEqual([
      'title: ntm-apa-mapper-vuln-report-2026-10-08',
      'print: ntm-apa-mapper-vuln-report-2026-10-08',
      'title: Vulnerability report / Network Topology Mapper',
    ]);
  });

  it('keeps the name until the dialog closes when print() returns early', () => {
    jest.spyOn(window, 'print').mockImplementation(() => events.push('print'));
    printWithTitle(docTitle, 'report', ['Page']);
    expect(document.title).toBe('report');
    window.dispatchEvent(new Event('afterprint'));
    expect(document.title).toBe('Page - Wazuh');
  });

  it('restores the title when printing fails or the page goes away', async () => {
    jest.spyOn(window, 'print').mockImplementation(() => {
      throw new Error('blocked');
    });
    await printWithTitle(docTitle, 'report', ['Page']).done;
    expect(document.title).toBe('Page - Wazuh');

    jest.spyOn(window, 'print').mockImplementation(() => {});
    const job = printWithTitle(docTitle, 'report', ['Page']);
    job.cancel();
    expect(document.title).toBe('Page - Wazuh');
  });
});
