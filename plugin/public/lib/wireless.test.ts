import { bandOf, isWireless, radioClients, wirelessText } from './wireless';
import { smallGraph } from './faceplate.fixtures';

describe('wireless links', () => {
  it('classifies Wi-Fi client links, not wired ones', () => {
    expect(isWireless({ type: 'endpoint_link', confidence: 'wifi', local_port: 'Dot11Radio0' })).toBe(true);
    expect(isWireless({ type: 'endpoint_link', local_port: 'Dot11Radio1' })).toBe(true);
    expect(isWireless({ type: 'endpoint_link', confidence: 'fdb', local_port: 'Fa0/3' })).toBe(false);
    expect(isWireless({ type: 'lldp', local_port: 'GigabitEthernet0' })).toBe(false);
  });

  it('names the band of the two standard radios only', () => {
    expect(bandOf('Dot11Radio0')).toBe('2.4 GHz');
    expect(bandOf('Dot11Radio1')).toBe('5 GHz');
    expect(bandOf('Dot11Radio2')).toBeNull();
    expect(bandOf(null)).toBeNull();
  });

  it('writes the tooltip', () => {
    expect(wirelessText('OFFICE', 'Dot11Radio0')).toBe('Wireless · OFFICE · 2.4 GHz (Dot11Radio0)');
    expect(wirelessText('LAB', 'Dot11Radio2')).toBe('Wireless · LAB · Dot11Radio2');
    expect(wirelessText(null, 'Dot11Radio1')).toBe('Wireless · 5 GHz (Dot11Radio1)');
  });

  it('counts clients per radio', () => {
    expect(radioClients('device:ap', smallGraph.edges)).toEqual(
      new Map([
        ['Dot11Radio0', 1],
        ['Dot11Radio1', 2],
      ])
    );
    expect(radioClients('device:sw24', smallGraph.edges).size).toBe(0);
  });
});
