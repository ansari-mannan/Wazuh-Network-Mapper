# Wazuh Network Topology Mapper and Attack Path Analysis Plugin

This project maps a network and shows where its vulnerabilities sit. A Python
scanner discovers routers and switches over SNMP/LLDP, pulls endpoints and
their CVEs from Wazuh, and joins both into a single topology graph. A web app
draws that graph so an analyst can see how vulnerable hosts connect to the rest
of the network, instead of reading CVE lists per host in isolation.

## Status

The project runs as an OpenSearch Dashboards plugin (`plugin/`, OpenSearch
Dashboards 2.19.3, Wazuh dashboard 4.14). On real scan data it shows the
overview, the topology map with a detail panel per node, and the scan settings.
Endpoints get CVEs and a base score from Wazuh; network devices get potential
CVEs and a base score from NVD, matched by software version. An optional
liveness check marks nodes that have left the network. Vulnerabilities, attack
paths and recommendations are not built yet and show "Coming soon".

## Project structure

```
backend/     Python scanner (vulnmapper), its tests and maintenance scripts
data/        graph.json, the scan output the web app reads
docs/        diagrams and archived project documents
plugin/      OpenSearch Dashboards plugin (Wazuh dashboard), see plugin/README.md
```

## Getting started

Prerequisites: Python 3.10 or later, Node.js 22.18 or later, and npm.

Backend tests:

```
cd backend
python -m pip install -r requirements.txt
python -m unittest discover -s tests
```

The dashboard plugin: see [plugin/README.md](plugin/README.md).

## Configuration

Copy `backend/.env.example` to `~/.vulnmapper.env` and fill in the Wazuh and
SNMP settings it lists.

## Documentation

See [docs/README.md](docs/README.md).

## License

MIT; see [LICENSE](LICENSE).
