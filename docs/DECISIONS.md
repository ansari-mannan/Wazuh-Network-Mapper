# Design decisions

Decisions on review items, agreed with the team before they were changed.

## Q3. Automatic rescan: off by default (was on)

`vulnmapper.liveness.autoRescan` now defaults to false. Liveness itself is
unchanged: with `vulnmapper.liveness.enabled` it still runs its quick up/down
checks every interval and the map shows them. What is now opt-in is the full
scan a liveness pass could start when it saw something appear that is not on
the map (a port coming up with nothing linked, a new Wi-Fi client, a Wazuh
agent missing from the graph). A full scan crawls every device, looks up
NVD and cve.org and may run nmap, which is a lot to start unasked; an owner
who wants the map to follow the network by itself sets `autoRescan: true`.

## D4. Liveness interval: default 60 s (was 10 s)

Each liveness pass starts a new Python process, which imports pysnmp,
networkx and requests; every 10 s that is a noticeable CPU load on the
dashboard server. `vulnmapper.liveness.intervalSeconds` now defaults to 60.
The minimum stays 10, so an owner who wants faster detection can still set
it. A long-lived liveness process was the other option; it was not taken.

## D3. TLS verification stays off by default, with a visible warning

The default is unchanged: Wazuh Manager API and Indexer calls skip
certificate verification unless `VULNMAPPER_VERIFY_TLS=1` or a
`*_CA_BUNDLE` is set, because the lab's certificates are self-signed. A live
scan now adds a `tls_unverified` warning to `metadata.warnings`, naming each
service it did not verify, so the gap is visible outside a lab instead of
silent. Since it is the lab default, the Overview shows it as a small info
note the user can dismiss (remembered in the browser, per kind of note), and
Scan settings lists it permanently under "Connection security".

## D6. CI runs the backend tests

`.github/workflows/backend-tests.yml` runs on every push and pull request:
Python 3.12, `backend/requirements.txt` plus pytest, then `pytest` and
`python -m unittest discover -s tests` (the two runners the project uses).
It needs no secret and the tests never reach the network. The plugin's Jest
suite needs an OpenSearch Dashboards checkout and is not run in CI.

## D7. The Wazuh Overview card comes from our plugin, not a patch to Wazuh's

Wazuh's Overview page builds its module cards from a list compiled into
Wazuh's own plugin. Changing that list would mean patching Wazuh's bundle,
which every Wazuh upgrade overwrites and which we would have to rebuild for
each version. Instead our plugin's browser side (`public/wazuhCard.ts`)
watches the page while Wazuh's `wz-home` app is open, finds the section by the
name in its header, copies one of Wazuh's cards there (so it looks the same),
puts our icon and text in it and appends it after Wazuh's cards. If Wazuh
re-renders the section the card is put back; if the section or a card to copy
is not there within 10 s it gives up with one console.debug line and the page
is left as Wazuh drew it. The cost: it depends on Wazuh 4.14's markup (an
OuiCard per section, the name in its beta badge); a Wazuh release that
changes it silently loses the card, which the menu entry (Security) and the
home-page card still cover. The section is a setting,
`vulnmapper.wazuhCard.section`.

## D8. File layout on the Wazuh server

The scanner and its venv go in `/opt/vulnmapper` (root-owned; the service
user only reads it), everything the scanner writes (graph, caches, history,
schedule) in `/var/lib/vulnmapper` (owned by `wazuh-dashboard`, 750), and the
credentials in `/etc/vulnmapper/vulnmapper.env` (root:wazuh-dashboard, 640).
The dashboard gets the credentials through a systemd drop-in
(`EnvironmentFile=`) rather than `opensearch_dashboards.yml`, which holds
only our non-secret settings in a marked block, so the yml can be shared or
backed up without leaking anything and the uninstall can remove exactly what
the install added. Nothing is under a home folder, because the dashboard runs
as a system user.

## D9. A typed SNMP community comes first, and a fallback is shown

The crawl always tried the community typed in the scan form before the
server's SNMP settings, but nothing said which one a device answered, so a
mistyped community silently worked through the environment's and looked as if
the environment file had priority. The order stays (typed, then the server's,
for the scan and the liveness passes; automatic and scheduled scans use the
server's only) and each polled device now records the source it answered as a
label, `entered` or `server`, in `metadata.snmp`. When a community was typed
and any device answered only the server's, an `snmp_fallback` warning names
those devices in the scan toast, on the Overview (not dismissible for that
scan) and on Scan settings. No extra SNMP request is sent: the next credential
is tried only on a device that did not answer the one before, as before.

## D10. The NVD API key can be saved from Scan settings

Setting `NVD_API_KEY` meant editing `/etc/vulnmapper/vulnmapper.env` and
restarting the dashboard. The key can now be saved on Scan settings: the
plugin writes it to `nvd-key` beside the graph (atomic, mode 600, owned by the
service user) and passes it as `NVD_API_KEY` in the environment of the
scanner and the rescore it spawns, never in argv. A saved key beats the
environment's; removing it brings the environment's back. The key never goes
back to the browser, into a log or an API response: the page shows only where
the key comes from, and "Test key" makes one NVD request and reports valid,
invalid or unreachable. The file lives with the data, so the installer keeps
it and `uninstall --purge` removes it.

## D11. Junos devices are decided from Juniper's own CVE records

NVD answered no Junos lookup: the CPE name had 14 components, which NVD
rejects with HTTP 404, and it kept the build number, for which NVD returns
fewer CVEs. Even the correct name misses many CVEs, because NVD's
applicability data for Junos lags Juniper's advisories and lists only some
releases. Juniper is the CNA for its products
and states the affected Junos releases in every CVE record (CVE JSON 5), so
those records decide a Junos device, with NVD's cpeName answer adding only the
CVEs Juniper did not assign. The records are taken from the CVE Services API
(cveawg.mitre.org). Choices made on the way:

- The index (ids Juniper assigned) is pulled from NVD with its own NVD client
  and a 60 s budget, so a slow pull never spends the device lookups' budget or
  marks NVD unreachable for them. The first full pull and the record fetch
  happen inside a scan; the refresh command with `--budget 600` fills an
  empty cache in one run.
- A device is decided only from a complete set of records. A partial set
  would give an `ok` that silently misses CVEs, so the device is `unavailable`
  until the gaps are filled.
- "Train not listed" is judged over the whole record, not per affected block:
  records often split one statement over several platform blocks, and a train
  fixed or stated unaffected in one of them is assessed.
- Records that use `changes` as a timeline over one train (status from the
  train's start, flipping at `lessThan` and at each change) are read as such.
- A model that cannot be placed among a record's platforms matches every
  platform block, and platform limits stated only in description text are not
  read. Both can over-report for a given model; neither can hide a CVE.
- Anything not parsed is listed in `cve_lookup.undecided`, never guessed.
  `cve_lookup` gained `reason` (why a lookup is not `ok`) and `undecided`, and
  the plugin says both in plain words.
- Every Junos device is compared with every record (about 1200), so the
  stage keeps the parsed version strings for the scan and assesses each
  release and model pair once. Without that, a scan with many Junos devices
  took over a minute of CPU; the decisions are the same either way.

## D12. Every identified family is named, even without an NVD product

A device whose software family and version are known was reported the same
way as one with nothing known, when NVD had no product name for that family.
The family table now covers more vendors, and a family without a product name
that can be trusted is still identified (`match: none`, status `unverified`,
reason `no_cpe_rule`). The plugin says the device is identified but its CVEs
are not looked up, instead of saying its software is unknown. Choices made on
the way:

- No CPE rule for Brocade Network OS, DCN switches, IBM Networking OS and the
  HP GbE2c blade switch. The CPE dictionary has no product that fits them
  (`brocade:fabric_os` is the Fibre Channel product, IBM has only single
  per-model firmware entries). A near name would report another product's
  CVEs.
- No CPE rule for ProCurve software before ArubaOS-Switch 16. The dictionary
  writes those releases with their train letters, and NVD compares versions
  as strings, so a release on one train matches ranges stated for another.
- ArubaOS-Switch 16.x is asked under two names, `hpe:arubaos-switch` and the
  per-model `arubanetworks:<line>_firmware`. Each lists CVEs the other does
  not, so the answers are merged. When the model names no product line (only
  a part number), the per-model half cannot be asked and the device is
  `unverified` (`model_not_mapped`) rather than reported with half its CVEs.
- The CPE dictionary check is set per family (`listed`): the exact release
  (the default), the product with any release (ArubaOS-Switch, whose
  dictionary lists only some releases while NVD still evaluates the version
  ranges), or none (FortiOS, for the same reason; this was a special case in
  the lookup before).
- Junos OS Evolved is its own family (`juniper_junos_evolved`, CPE
  `juniper:junos_os_evolved`), recognised by the `-EVO` suffix. It is decided
  from the Evolved blocks of Juniper's records (D11), never from the Junos OS
  blocks, and a release of one branch is never matched against the other.
  Records cached before the Evolved blocks were kept are fetched again, and
  Evolved devices stay `unavailable` until that is done.
