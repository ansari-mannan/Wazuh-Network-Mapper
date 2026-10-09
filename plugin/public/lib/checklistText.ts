import { ConfigEvidence, ConfigFinding, ConfigReference, ConfigSummary, GraphNode, Metadata } from '../../common';

// Plain words for a device's configuration checks (backend/vulnmapper/checklist),
// for the detail flyout and the overview. No theme imports: unit tested.

export type ConfigSeverity = 'high' | 'medium' | 'low' | 'advisory';
export const CONFIG_SEVERITIES: ConfigSeverity[] = ['high', 'medium', 'low', 'advisory'];

/** "High", "Medium", "Low"; a check with no published severity is "Advisory". */
export function severityLabel(severity: string | null | undefined): string {
  if (!severity) return 'Advisory';
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

export function severityKey(severity: string | null | undefined): ConfigSeverity {
  return severity === 'high' || severity === 'medium' || severity === 'low' ? severity : 'advisory';
}

/** "FastEthernet1/0/3" -> "Fa1/0/3", as the map names ports; others unchanged. */
export function shortPort(name: string): string {
  const m = /^([A-Za-z]+Ethernet)\s*(\d.*)$/.exec(name);
  return m ? m[1].slice(0, 2) + m[2] : name;
}

const LIST_SHOWN = 3;

/** "Fa1/0/3", "Fa1/0/3 and Fa1/0/7", "Fa1/0/3, Fa1/0/7, Fa1/0/8 and 12 more". */
export function portList(ports: string[], total?: number): string {
  const all = total ?? ports.length;
  const names = ports.slice(0, LIST_SHOWN).map(shortPort);
  const more = all - names.length;
  if (more > 0) return `${names.join(', ')} and ${more} more`;
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

function count(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** What a failed check found, as short sentences. */
export function evidenceLines(id: string, e: ConfigEvidence | null | undefined): string[] {
  if (!e) return [];
  const out: string[] = [];
  if (e.ports && e.ports.length) {
    const total = e.total ?? e.ports.length;
    const names = e.ports.map((p) => (typeof p === 'string' ? p : `${shortPort(p.port)} (VLAN ${p.vlan})`));
    out.push(`${total === 1 ? 'Port' : `${total} ports`}: ${portList(names, total)}.`);
  }
  if (id === 'spare-ports-in-used-vlan' && e.enabled !== undefined) {
    const shut = e.shut_down ?? 0;
    out.push(
      `None has had a link since the device started; ${e.enabled} ${e.enabled === 1 ? 'is' : 'are'} enabled, ${shut} shut down.`
    );
    const recent = e.down_recently_not_counted ?? 0;
    if (recent > 0) {
      out.push(`${count(recent, 'port')} lost ${recent === 1 ? 'its' : 'their'} link later and ${recent === 1 ? 'is' : 'are'} not counted: it may be a computer that is switched off.`);
    }
  }
  if (id === 'access-ports-default-vlan' && e.with_link !== undefined) {
    out.push(
      e.with_link > 0
        ? `${count(e.with_link, 'has a device', 'have a device')} attached and ${e.with_link === 1 ? 'is' : 'are'} listed first.`
        : 'None of them has a device attached at the moment.'
    );
  }
  if (e.port !== undefined) {
    out.push(
      e.found_by
        ? `TCP port ${e.port} accepted a connection from the scanner.`
        : `The device lists TCP port ${e.port} as in use.`
    );
  }
  if (e.snmp_version) out.push(`The scan polled it with SNMP ${e.snmp_version}.`);
  if (e.communities && e.communities.length) {
    out.push(`It answers to “${e.communities.join('” and “')}”, found by ${e.found_by || 'the scan'}.`);
  }
  return out;
}

/** "DISA STIG V-220630, CAT II"; "NVD CVE-1999-0517, CVSS 2.0 7.5"; "related" when it is. */
export function referenceText(r: ConfigReference): string {
  let text: string;
  if (r.source === 'NVD') {
    text = `NVD ${r.rule_id}${r.cvss ? `, CVSS ${r.cvss.version} ${r.cvss.score}` : ''}`;
  } else {
    const kind = /\bSTIG\b/.test(r.document) ? 'STIG' : /\bSRG\b|Requirements Guide/.test(r.document) ? 'SRG' : r.document;
    text = `${r.source} ${kind} ${r.rule_id}${r.category ? `, ${r.category}` : ''}`;
  }
  return r.relation === 'related' ? `Related: ${text}` : text;
}

const RESULT_WORDS: Array<[keyof ConfigSummary['results'], string]> = [
  ['pass', 'passed'],
  ['unknown', 'unknown'],
  ['not_checked', 'not checked'],
  ['not_applicable', 'not applicable'],
];

/** "5 of 8 checks failed (3 medium, 2 advisory); 2 unknown, 1 not checked, 1 not applicable." */
export function summaryLine(s: ConfigSummary): string {
  const failed = s.results.fail || 0;
  const bySeverity = CONFIG_SEVERITIES.filter((k) => s.findings[k] > 0).map(
    (k) => `${s.findings[k]} ${k === 'advisory' ? 'advisory' : k}`
  );
  const head =
    failed === 0
      ? `None of ${count(s.checks, 'check')} failed`
      : `${failed} of ${count(s.checks, 'check')} failed (${bySeverity.join(', ')})`;
  const rest = RESULT_WORDS.filter(([k]) => (s.results[k] || 0) > 0).map(([k, w]) => `${s.results[k]} ${w}`);
  return rest.length ? `${head}; ${rest.join(', ')}.` : `${head}.`;
}

/** Why a device has no configuration checks; empty when it has them. */
export function noChecklistText(node: GraphNode, meta: Metadata | undefined): string {
  if (node.kind !== 'device' || node.config_checks) return '';
  if (node.pollable === false) {
    return 'It was only seen in a neighbour’s table, never polled, so its configuration could not be read.';
  }
  const checklist = meta?.checklist;
  if (!checklist) return 'This graph has no configuration checks; the next scan adds them.';
  if (checklist.source !== 'scan') {
    return `The configuration checks in this graph come from ${checklist.source}; this device was not among them.`;
  }
  return 'The configuration checks did not run for this device.';
}

/** Failed checks with a severity first, worst first; advisories last. */
export function sortFindings(findings: ConfigFinding[]): ConfigFinding[] {
  const rank = (f: ConfigFinding) => CONFIG_SEVERITIES.indexOf(severityKey(f.severity));
  return [...findings].sort((a, b) => rank(a) - rank(b));
}

/** Configuration findings over every checked device, for the overview. */
export function configFindingCounts(nodes: GraphNode[]) {
  const counts: Record<ConfigSeverity, number> = { high: 0, medium: 0, low: 0, advisory: 0 };
  let devices = 0;
  let withFindings = 0;
  for (const n of nodes) {
    if (n.kind !== 'device' || !n.config_summary) continue;
    devices += 1;
    const f = n.config_summary.findings;
    for (const k of CONFIG_SEVERITIES) counts[k] += f[k] || 0;
    if (CONFIG_SEVERITIES.some((k) => (f[k] || 0) > 0)) withFindings += 1;
  }
  return { counts, devices, withFindings, total: CONFIG_SEVERITIES.reduce((a, k) => a + counts[k], 0) };
}
