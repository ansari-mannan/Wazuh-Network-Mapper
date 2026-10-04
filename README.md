# Wazuh Network Topology Mapper and Attack Path Analysis Plugin

This project maps a network and shows where its vulnerabilities sit. A Python
scanner discovers routers and switches over SNMP/LLDP, pulls endpoints and
their CVEs from Wazuh, and joins both into a single topology graph. A web app
draws that graph so an analyst can see how vulnerable hosts connect to the rest
of the network, instead of reading CVE lists per host in isolation.

## Status

Network discovery, the topology map and the per-device detail pages work on
real scan data. Attack path analysis, recommendations and the summary screens
currently show sample data and are in development. The project runs as a
standalone web app; packaging it as a Wazuh dashboard plugin is planned.

## Project structure

```
backend/     Python scanner (vulnmapper), its tests and maintenance scripts
frontend/    Next.js web app that displays the graph and starts scans
data/        graph.json, the scan output the web app reads
docs/        diagrams and archived project documents
```

## Getting started

Prerequisites: Python 3.10 or later, Node.js 22.18 or later, and npm.

Backend tests:

```
cd backend
python -m pip install -r requirements.txt
python -m unittest discover -s tests
```

Frontend:

```
cd frontend
npm install
npm run dev
```

The app is then available at http://localhost:3000. For a production build,
run `npm run build` and then `npm start`.

## Configuration

Copy `frontend/.env.example` to `frontend/.env.local` and fill in the Wazuh and
SNMP settings it lists.

## Documentation

See [docs/README.md](docs/README.md).

## License

MIT; see [LICENSE](LICENSE).
