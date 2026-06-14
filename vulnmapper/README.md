# vulnmapper

One package that unifies the Wazuh endpoint pipeline (NTM collector + APA CVE
scorer) and the SNMP/LLDP network-device crawler into a **single graph
document**:

```json
{ "nodes": [ ... ], "edges": [ ... ], "metadata": { ... } }
```

## Layout

```
vulnmapper/
  common/      schema.py (Node/Edge/CVE + node_id helpers), mac.py (the one MAC
               canonicalizer), config.py (env-var + TLS conventions)
  endpoints/   wazuh_client / indexer_client (fetch), normalize (pure),
               collect -> agents.json, score -> scored_agents.json
  network/     seed-based LLDP crawler; fdb.py (pure FDB parsing),
               fdb_collect.py (SNMP FDB collection incl. per-VLAN context)
  linking/     fdb_link.py — endpoint -> switch resolution (the core new logic)
  assemble/    merge.py — unify nodes/edges + stamp discovery_order / parent_id
  pipeline.py  top-level: collect -> score -> link -> assemble (-> stdout JSON)
```

## node_id (the join key)

Every node carries one stable id that edges reference — never hostname/IP:

* endpoints — `endpoint:<agent_id>` (the Wazuh agent id)
* devices   — `device:<chassis_id>` (the LLDP/SNMP chassis id)

## Run

```bash
# Full live run (creds from env): collect -> score -> crawl -> assemble.
WAZUH_PASS=... INDEXER_PASS=... \
  python -m vulnmapper --community cyfor123 > graph.json

# Rebuild the graph from cached stage outputs (no lab access):
python -m vulnmapper --scored scored_agents.json --network output.json > graph.json

# One-sided graphs:
python -m vulnmapper --no-endpoints --community cyfor123 > graph.json
python -m vulnmapper --no-network --scored scored_agents.json > graph.json
```

stdout is the unified JSON **only**; every log/progress/warning goes to stderr.

Individual stages are still runnable on their own (filenames preserved):

```bash
python -m vulnmapper.endpoints.collect    # -> agents.json
python -m vulnmapper.endpoints.score      # -> scored_agents.json
python -m vulnmapper.network --community cyfor123 > output.json
```

## Environment

| Var | Stage | Default |
|-----|-------|---------|
| `WAZUH_HOST/PORT/USER/PASS` | collect | localhost / 55000 / wazuh-wui / *(required)* |
| `INDEXER_HOST/PORT/USER/PASS` | score | localhost / 9200 / admin / *(required)* |
| `AGENTS_OUT` / `AGENTS_IN` / `SCORED_OUT` | collect/score | agents.json / agents.json / scored_agents.json |
| `SNMP_COMMUNITIES` / `SNMP_COMMUNITY` / `SNMP_V3_*` | crawl | — |
| `VULNMAPPER_VERIFY_TLS`, `WAZUH_CA_BUNDLE`, `INDEXER_CA_BUNDLE` | endpoints | off (lab self-signed certs) |

No credentials are hard-coded. `verify=False` is the explicit lab default; set
`VULNMAPPER_VERIFY_TLS=1` (or a `*_CA_BUNDLE`) to turn TLS verification on.

## Tests

Pure logic is unit-tested without a live network:

```bash
python -m unittest discover -s tests -v
```

Covers MAC canonicalization, the endpoint normalizers, FDB index decoding, the
linker's uplink-subtraction / tie-break disambiguation, and the assembler's
discovery stamping.

## Note on the old layout

`NTM/`, `APA/` and `discovery_module/` are the pre-unification scripts. They are
fully superseded by this package and kept only until a live run confirms parity;
delete them once verified.
