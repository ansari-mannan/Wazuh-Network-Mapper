import { layoutGraph, rowCapacity } from './layout';

// dagre calls structuredClone, which this jest sandbox does not expose
(globalThis as any).structuredClone ??= (v: unknown) => JSON.parse(JSON.stringify(v));

const device = (i: number) => ({ node_id: `device:${i}`, kind: 'device' as const, hostname: `sw${i}` });

describe('layoutGraph on a wide, barely linked graph', () => {
  const nodes = Array.from({ length: 247 }, (_, i) => device(i));
  const edges = [{ source: 'device:0', target: 'device:1', type: 'lldp' as const }];
  const { nodes: out } = layoutGraph({ nodes, edges } as any);
  const perRow = rowCapacity(nodes.length);

  it('folds a huge rank into rows no wider than the row capacity', () => {
    const rows = new Map<number, number>();
    for (const n of out) rows.set(n.position.y, (rows.get(n.position.y) || 0) + 1);
    expect(Math.max(...rows.values())).toBeLessThanOrEqual(perRow);
  });

  it('keeps the map roughly screen shaped, not a strip', () => {
    const xs = out.map((n) => n.position.x);
    const ys = out.map((n) => n.position.y);
    const w = Math.max(...xs) - Math.min(...xs);
    const h = Math.max(...ys) - Math.min(...ys);
    expect(w / h).toBeLessThan(6);
  });

  it('never stacks two nodes on the same spot', () => {
    expect(new Set(out.map((n) => `${n.position.x},${n.position.y}`)).size).toBe(out.length);
  });
});

describe('layoutGraph with subnet-inferred hosts and separate components', () => {
  const nodes = Array.from({ length: 247 }, (_, i) => ({
    ...device(i),
    ip: i < 120 ? `10.1.${i % 6}.${i + 1}` : i < 180 ? `10.9.${i % 40}.${i}` : undefined,
  }));
  const edges = [
    { source: 'device:0', target: 'device:1', type: 'lldp' as const },
    { source: 'device:2', target: 'device:3', type: 'lldp' as const },
    { source: 'device:200', target: 'device:201', type: 'lldp' as const },
  ];
  const { nodes: out } = layoutGraph({ nodes, edges } as any);

  it('stays compact and screen shaped', () => {
    const xs = out.map((n) => n.position.x);
    const ys = out.map((n) => n.position.y);
    const w = Math.max(...xs) - Math.min(...xs);
    const h = Math.max(...ys) - Math.min(...ys);
    expect(w / h).toBeLessThan(6);
    expect(w).toBeLessThan(rowCapacity(nodes.length) * 260);
  });

  it('never stacks two nodes on the same spot', () => {
    expect(new Set(out.map((n) => `${n.position.x},${n.position.y}`)).size).toBe(out.length);
  });
});
