# Wazuh Network Topology Mapper and Attack Path Analysis Plugin

This project maps a network and shows where its vulnerabilities sit. A Python
scanner discovers routers, switches and access points over SNMP (LLDP and CDP),
pulls endpoints and their CVEs from Wazuh, and joins both into one topology
graph. An OpenSearch Dashboards plugin for the Wazuh dashboard draws that graph,
so an analyst sees how vulnerable hosts connect to the rest of the network
instead of reading CVE lists per host in isolation.

## What it does

- **Topology map**: every device and host, each host placed on the switch port
  it sits on, with a detail panel per node.
- **Vulnerabilities**: CVEs for endpoints (from Wazuh) and for network devices
  (from NVD, matched by software version), each scored with OVSS: its CVSS
  score weighted by where the asset sits, what depends on it, and whether the
  CVE is exploited (CISA KEV, FIRST EPSS), then placed in a tier from P0 (act
  now) to P3. A vulnerability report ranked by OVSS exports to PDF.
- **Configuration checks**: switch settings checked against DISA STIG and SRG
  rules (telnet or HTTP management, SNMP without authentication, default
  communities, spare ports, the default VLAN, BPDU guard, port security).
- **Attack paths**: for each asset the owner marks as important, the most
  likely routes to it from a place assumed already compromised (NIST IR 7788).
- **Recommendations**: one prioritised, trackable action plan for the network.
- **Liveness** (optional): between scans, nodes that stop answering are greyed
  out, and a new device or agent can start a rescan. A host liveness marks
  inactive is not used as an attack-path starting point either.
- **Scheduled scans**: the server can scan on its own every 1, 3, 6 or 12
  hours or daily at a chosen hour, read-only and with every active check off.
- **Scan history**: the last 10 successful scans are kept, each with what
  changed since the one before (hosts and devices added, removed or gone
  offline, CVEs new and fixed, risk changes) and how long each stage took.
- **Hosts without an agent** are found in the switches' tables; optional
  checks can ask them over SNMP or service-scan them with nmap.

## Project structure

```
backend/   the Python scanner (vulnmapper), its tests and maintenance scripts
plugin/    the OpenSearch Dashboards plugin (Wazuh dashboard)
data/      a synthetic sample scan (graph, findings, attack paths), rebuilt by
           backend/scripts/make_sample_data.py from the saved test inputs
docs/      the code tour, and archived documents from earlier stages
scripts/   start the dashboard with the plugin, build and install the plugin
```

## Running it

Requirements: Python 3.10 or later; OpenSearch Dashboards 2.19.3 for
development (the Wazuh dashboard 4.14.8 is built on 2.19.6) and Node.js
18.19.0 for the plugin.

Scanner, from `backend/`:

```
python -m pip install -r requirements.txt
python -m unittest discover -s tests
python -m vulnmapper --community <community> -o ../data/graph.json
```

Credentials come from the environment only: copy `backend/.env.example` to
`~/.vulnmapper.env` and fill in the Wazuh, Indexer and SNMP settings.
`python -m vulnmapper --help` lists the options; `backend/README.md` describes
each stage.

Dashboard: `scripts/run.sh` starts the dashboard with the plugin (from a source
checkout of OpenSearch Dashboards, or a packaged one on a server) and loads
`~/.vulnmapper.env`. The plugin is then at http://localhost:5601/app/vulnmapper.
See `plugin/README.md` for the development setup, the plugin's settings and
building the zip.

The zip only installs into the exact dashboard version it was built for.
`scripts/send-plugin.sh` builds for 2.19.3 by default; for the Wazuh dashboard
4.14.8 build `vulnmapper-2.19.6.zip` with:

```
OSD_VERSION=2.19.6 ./scripts/send-plugin.sh
```

Scheduled scans and the scan history are on the plugin's Scan settings page.
A schedule is kept in `schedule.json` beside the graph and survives dashboard
restarts. Scheduled scans take the SNMP credential from the dashboard server's
environment (`VULNMAPPER_SNMP_COMMUNITY`, `SNMP_COMMUNITIES`, `SNMP_COMMUNITY`
or the `SNMP_V3_*` variables), never from the scan form, and fail with a message on that page if
none is set. Times are the server's local time. The history is kept in
`history/` beside the graph; like the graph, it holds MAC addresses and
serial numbers, so keep it out of version control (`.gitignore` covers
`data/history/` and `data/schedule.json`).

## Documentation

[docs/CODE_TOUR.md](docs/CODE_TOUR.md) maps each part of the system to its
files, follows the data through a scan and lists every class. Older documents
are in [docs/archive/](docs/README.md).

## Authors

- [Ahmad Naaem Saad](https://github.com/AhmadNaaem)
- [Abdul Mannan Ansari](https://github.com/ansari-mannan)
- [Muhammad Hasan](https://github.com/hasan8733)

## Acknowledgements

Developed at the CYFOR Cybersecurity and Networking Research Lab as a Final
Year Project (FYP Batch 2023) at UIT University, Karachi.

## License

MIT; see [LICENSE](LICENSE).
