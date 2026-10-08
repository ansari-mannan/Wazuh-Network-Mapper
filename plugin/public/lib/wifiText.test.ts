import { clientCountText, wifiClientText } from './wifiText';

describe('wifiClientText', () => {
  const names: Record<string, string> = { 'device:ip:172.20.99.21': 'CYFOR-AP1' };
  const nameOf = (id: string) => names[id] || id;

  it('names the SSID, the access point and the radio', () => {
    expect(
      wifiClientText({ ssid: 'BIG-CYFOR-5G', access_point: 'device:ip:172.20.99.21', radio: 'Do1' }, nameOf)
    ).toBe('BIG-CYFOR-5G on CYFOR-AP1 (Do1)');
  });

  it('copes with a missing SSID or radio', () => {
    expect(wifiClientText({ ssid: null, access_point: 'device:x', radio: null }, nameOf)).toBe(
      'on device:x'
    );
  });
});

describe('clientCountText', () => {
  it('counts clients', () => {
    expect(clientCountText(0)).toBe('no clients');
    expect(clientCountText(1)).toBe('1 client');
    expect(clientCountText(12)).toBe('12 clients');
  });
});
