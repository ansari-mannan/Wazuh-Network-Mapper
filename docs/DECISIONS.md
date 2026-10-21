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

