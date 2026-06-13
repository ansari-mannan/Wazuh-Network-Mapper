# Consolidation refactor — decisions log

Behaviour-preserving consolidation of `vulnmapper/` for clean UML. Prime
directive: **identical output / CLI / env / tests** before and after. Each step
is gated (compile + full suite + both `--help`) and committed separately.

Baseline: 89 suite tests + 1 golden = **90 green**, committed at the Phase-0 tag.

## Target layout (37 files → ~12; 17 classes → ~9 diagram classes)

| Target | Absorbs | Notes / contract handling |
|---|---|---|
| `vulnmapper/schema.py` | `common/{schema,mac,config}.py` | All shared types + MAC + env config. Re-path test/tool imports `common.mac`/`common.schema` → `schema`. Delete `common/`. |
| `vulnmapper/network/vendors/` (kept a package) | merge `cisco.py`+`fortinet.py`+registry into `__init__.py`; **keep `comware.py`** | `vendors.comware` is a frozen test import → keep it a real module. `cisco`/`fortinet` preserved as names (SimpleNamespace with `.identify`) so the registry shape and public names are unchanged. Model JSONs stay at `network/` (path constants already resolve there). |
| `vulnmapper/network/parse.py` | `lldp.py`+`fdb.py`+`fdb_collect.py`+`utils.py` | Pure parsing + async `collect_*` wrappers + string helpers. Tests re-path via alias: `from ..network import parse as fdb` / `as lldp` (call sites unchanged). |
| `vulnmapper/network/snmp.py` | `snmp_client.py` | The ONLY pysnmp importer. Re-path crawler + tools. |
| `vulnmapper/network/roles.py` | unchanged | Pure; heavily tested; its own clean concept. |
| `vulnmapper/network/crawl.py` | `crawler,runner,seed,sysinfo,output,models,config,cli` | Public `crawl_document(cfg)` + `parse_config(argv)` (+ `emit`/`write`). `network/__main__.py` re-pathed. Holds `Crawler,Config,Credential,Device,Link`. |
| `vulnmapper/network/__main__.py` | unchanged entry | imports from `crawl`. |
| `vulnmapper/endpoints/` (kept a package) | merge `wazuh_client,indexer_client,normalize,collect,score` into `__init__.py` as `WazuhSource` + pure fns | **Keep `collect.py`/`score.py` as thin `-m` shims** (frozen entry points). Re-path test `endpoints.normalize` → `endpoints`. |
| `vulnmapper/assemble.py` (module) | `assemble/merge.py`+`linking/fdb_link.py` | `GraphAssembler` + `MacTable` (`SwitchFdb`/`HostFact` internal). Public `assemble(endpoints, network_doc)`. Re-path test/tool `assemble.merge` + `linking.fdb_link` → `assemble`. Delete `assemble/` pkg + `linking/`. |
| `vulnmapper/pipeline.py` | thin `Pipeline` wrapper around existing `run()` | `run(argv)` unchanged; `__main__` unchanged. |

## Deviations from the spec's recommended target (and why)
1. **`vendors/` kept as a package, not flattened to `vendors.py`.** Flattening
   would break the frozen `vulnmapper.network.vendors.comware` test import for
   zero class-diagram benefit (vendors are functions, not classes). Merging
   `cisco`+`fortinet` into `__init__.py` still cuts the file count.
2. **Model JSONs not moved.** `fortinet_models.json`/`comware_models.json` stay
   at `network/`; the `os.path.dirname(os.path.dirname(__file__))` constants
   already resolve there from both the old and new module locations — moving
   them would be churn with breakage risk and no benefit.
3. **`endpoints/` kept a package** (not a module) because `python -m
   vulnmapper.endpoints.collect` / `...score` are frozen entry points and a
   module cannot host submodules. The merged code lives in `__init__.py`;
   `collect.py`/`score.py` are thin `main()` shims.

## Test/tool import re-paths (applied in lockstep with each step)
- `common.mac`/`common.schema` → `schema`  (test_mac, test_comware, tools/verify_comware)
- `network.fdb`/`network.lldp` → `network.parse` (alias) (test_fdb, test_roles, test_comware, test_topology_fixes, tools/verify_comware)
- `network.snmp_client` → `network.snmp`; `network.models` → `network.crawl` (tools/verify_comware)
- `endpoints.normalize` → `endpoints` (test_normalize)
- `assemble.merge` + `linking.fdb_link` → `assemble` (test_assemble, test_golden, test_topology_fixes, test_fdb_link, tools/_freeze_golden)

Kept unchanged: `network.roles`, `network.vendors.comware`.

## Result summary (Phase 3)

| Metric | Before | After |
|---|---|---|
| `vulnmapper/*.py` files | 37 | 16 |
| classes (total) | 17 | 18 |
| behaviour-bearing classes (diagram cast) | scattered | 9: Pipeline, WazuhSource, Crawler, SnmpClient, GraphAssembler (+ data holders Node/Edge/CVE/Device/Link/Config/Credential/MacTable) |

Gate results (all green): `compileall` ✓ · `pytest` 90 passed (89 + golden) ✓ ·
`vulnmapper --help` + `vulnmapper.network --help` flag lists unchanged ✓ ·
`-m endpoints.collect` / `-m endpoints.score` run (no ImportError) ✓ ·
GUI spawn `-m vulnmapper --community cyfor123 --no-endpoints --no-network` -> valid stdout-only JSON ✓ ·
single pysnmp importer (`network/snmp.py`) ✓ · golden assemble output byte-identical ✓.

Module map (final): schema.py · endpoints/{__init__(WazuhSource),collect,score} ·
network/{snmp,parse,roles,vendors/{__init__,comware},crawl,__main__} · assemble.py ·
pipeline.py · __main__.py.
