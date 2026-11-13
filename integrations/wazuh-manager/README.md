# Wazuh manager integration: scan events as alerts

The scanner's output (`graph.json`, `vulnerabilities.json`,
`attack_paths.json`) is a full-state snapshot rewritten on every scan, so
`wazuh-logcollector` has nothing to follow and a rule has no stable contract to
match. This directory turns one scan into an append-only event stream the
manager can collect, and a ruleset that alerts on it.

What you get in Wazuh: one alert per scan, plus one alert per change the scan
found (a device appeared or disappeared, a device's firmware moved, the
confirmed link set changed, a new CVE on a host or device, a new attack path to
an important asset). Everything the plugin shows on screen also reaches the
analyst's alert queue, so a new P0 finding does not wait for somebody to open
the map.

Files:

| file | where it goes |
|---|---|
| `vulnmapper-events` | `/usr/local/sbin/vulnmapper-events` (root, mode 755) |
| `111200-vulnmapper_rules.xml` | `/var/ossec/etc/rules/` on the manager (wazuh:wazuh, mode 660) |
| `test_vulnmapper_events.py` | tests, not deployed |

## 1. Emit the events

`vulnmapper-events` diffs what a scan just published against the previous
publication and appends one JSON object per line to `events.json`. Paths come
from the environment:

| variable | default | meaning |
|---|---|---|
| `VM_DATA` | `/var/lib/vulnmapper` | the scan output that was just published |
| `VM_PREV` | `$VM_DATA/last-good` | the previous publication |
| `VM_EVENTS` | `$VM_DATA/events.json` | the event log to append to |
| `VM_SCANNER` | this host's FQDN | the `scanner` field on every event |

The previous publication is the one thing the scanner does not keep on its own:
copy the three JSON files aside before a scan overwrites them, then run the
emitter after it. In a wrapper around the scan:

```sh
DATA=/var/lib/vulnmapper
mkdir -p "$DATA/last-good"
for f in graph.json vulnerabilities.json attack_paths.json; do
  [ -f "$DATA/$f" ] && cp -a "$DATA/$f" "$DATA/last-good/$f"
done

python -m vulnmapper -o "$DATA/graph.json" --vulns-out "$DATA/vulnerabilities.json" ...

/usr/local/sbin/vulnmapper-events || echo "event emit failed" >&2
```

Run the emitter on every terminal path of the wrapper, including the failures:
it reports the outcome as well as the changes. A wrapper that gates publication
can write `scan-status.json` next to the graph
(`{"result": "OK|DEGRADED|FAIL", "detail": "..."}`); the emitter picks it up and
skips the change events on anything but `OK` or `DEGRADED`, because on a failed
scan the data directory still holds the previous graph and a diff against it
would be noise. Without that file a readable graph counts as a successful scan.

Nothing is kept between runs, so each change is reported once.

Events emitted:

| event | when | `severity_class` |
|---|---|---|
| `scan_result` | always | `normal` / `high` / `critical` by result |
| `device_new`, `device_removed` | the device set changed | `normal` / `high` |
| `firmware_change` | a device kept its node id and changed firmware | `high` |
| `link_change` | the confirmed link set changed | `normal` |
| `ovss_tier_change` | the OVSS findings-by-tier counts changed | `normal` |
| `finding_new` | a (node, CVE, package) triple that was not there before | by tier and KEV |
| `attack_path_new` | a route identity that was not there before | by target importance |
| `device_truncated`, `finding_truncated`, `route_truncated` | a per-kind cap was hit | `high` |

Flood and rotation guards: 40 findings, 40 devices and 20 routes per scan, each
cap emitting one `*_truncated` event that carries the real total. At 5 MB the
file is rotated to `events.json.1` with `os.replace` rather than truncated in
place, because logcollector follows the inode and would silently stop reading a
file truncated under it.

## 2. Collect it

On the manager, in `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/vulnmapper/events.json</location>
</localfile>
```

logcollector runs as root and reads a mode-644 file fine, so the emitter does
not need to write inside `/var/ossec`. Then:

```
/var/ossec/bin/wazuh-logcollector -t && systemctl reload wazuh-manager
```

A ruleset reload is not enough for a new `localfile`: logcollector rereads
`ossec.conf` only on a manager reload. Confirm with
`(1950): Analyzing file: '/var/lib/vulnmapper/events.json'` in `ossec.log`.

## 3. The rules

Copy `111200-vulnmapper_rules.xml` to `/var/ossec/etc/rules/`, run
`/var/ossec/bin/wazuh-analysisd -t`, then reload the ruleset (on a cluster, on
every node: integrity sync copies the file but does not reload analysisd).

Parent `111200` is level 0 and matches `<decoded_as>json</decoded_as>` plus
`<field name="integration">^vulnmapper$</field>`; the children key on `event`
and, where siblings would otherwise collide, on `severity_class`.

| id | level | event |
|---|---|---|
| 111200 | 0 | parent, integration `vulnmapper` |
| 111201 | 3 | `scan_result` OK |
| 111202 | 7 | `scan_result` DEGRADED |
| 111203 | 10 | `scan_result` FAIL or UNKNOWN |
| 111204 | 5 | `device_new` |
| 111205 | 7 | `device_removed` |
| 111206 | 7 | `firmware_change` |
| 111207 | 3 | `link_change` |
| 111208 | 12 | `finding_new`, critical (P0 or KEV), MITRE T1190 |
| 111209 | 10 | `finding_new`, high (P1), MITRE T1190 |
| 111210 | 5 | `finding_new`, normal |
| 111211 | 12 | `attack_path_new` to a high-importance asset, MITRE T1046 T1210 |
| 111212 | 10 | `attack_path_new` to any other asset, MITRE T1046 T1210 |
| 111213 | 3 | `ovss_tier_change` |
| 111215 | 7 | any `*_truncated` |

111214 is deliberately unused: it is reserved for a site-specific event (a
staleness check on whatever feeds the scanner its topology) that does not
belong in this generic ruleset.

Rule ids 111200-111299 are in the user range (100000 and above) and were free
on the manager this was built against. Check yours before deploying
(`grep -rho 'rule id="[0-9]*"' /var/ossec/etc/rules /var/ossec/ruleset/rules |
sort -u`) and renumber the file if they clash; the filename sorts the file late
enough that nothing it depends on loads after it, and it uses no
`overwrite="yes"` and no cross-file `if_sid`.

Three constraints shaped both the emitter and the rules, worth knowing before
editing either:

- Wazuh fires only ONE sibling rule per `if_sid` parent, so sibling rules must
  be mutually exclusive. That is why the emitter computes `severity_class` and
  the rules match on (`event`, `severity_class`) instead of relying on rule
  order.
- Field names avoid the JSON decoder's reserved set: `device_name` and
  `device_ip`, never `hostname` or `srcip`.
- No rule sits below level 3, because `<alerts><log_alert_level>` on a manager
  gates which levels reach the indexer, and 3 is a common setting.

Steady-state volume is one level-3 `scan_result` per scan plus the change
events. If that baseline is unwanted, drop 111201 to level 0 (it then stays in
`alerts.log` but not in the indexer) or scan less often.

## Tests

```
cd integrations/wazuh-manager
python -m unittest test_vulnmapper_events
```

The tests run the emitter against the repository's synthetic sample scan in
`data/`, with a modified copy as the previous publication, and cover every
event kind, the status-file override, a cap and the rotation.
