"""Golden regression test: the outputs of a fixed run must not change.

Each scenario runs part of the scanner on fixed, offline inputs (the SNMP
fakes, the saved Wazuh endpoints, canned NVD and nmap replies) and compares
what it wrote with the frozen files in ``tests/golden/``, as parsed objects
and as text. Only the fields that change from run to run (timestamps and
durations) are normalised first.

A refactor must keep this green. If it fails, the change altered behaviour.
To refreeze after an intended change: ``python3 scripts/_freeze_golden.py``.
"""

import asyncio
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_GOLDEN = os.path.join(_HERE, "golden")
_FIXTURES = os.path.join(_HERE, "fixtures")
sys.path.insert(0, _HERE)  # the sibling test modules hold the fakes

from vulnmapper.assemble import assemble  # noqa: E402

FROZEN = "FROZEN"
# Wall-clock stamps, at the top of a document or in its metadata.
_STAMPS = ("scan_time", "network_scan_time", "source_scan", "computed_at",
           "started_at", "finished_at")


def normalise(doc: dict) -> dict:
    """Blank the fields that differ between two identical runs.

    A timing entry or stage duration that is null stays null: null means the
    stage did not run, and that is behaviour worth pinning.
    """
    meta = doc.get("metadata")
    for place in (doc, meta) if isinstance(meta, dict) else (doc,):
        for key in _STAMPS:
            if place.get(key) is not None:
                place[key] = FROZEN
    if not isinstance(meta, dict):
        return doc
    timing = meta.get("timing")
    if isinstance(timing, dict):
        for key, value in timing.items():
            if value is not None:
                timing[key] = FROZEN
    for stage in meta.get("stages") or []:
        if stage.get("seconds") is not None:
            stage["seconds"] = FROZEN
    return doc


def dump(doc: dict) -> str:
    return json.dumps(doc, indent=2) + "\n"


# --- scenarios ----------------------------------------------------------------

def _assemble_only():
    import test_assemble

    return {"parenting_ladder.expected.json":
            assemble(test_assemble.endpoints(), test_assemble.network_doc())}


def _run_pipeline(tmp, argv, **fakes):
    from vulnmapper.pipeline import Pipeline

    graph = os.path.join(tmp, "graph.json")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = Pipeline(**fakes).run(argv + ["-o", graph])
    if code != 0:
        raise AssertionError(f"pipeline exited {code}")
    out = {}
    for name in ("graph", "vulnerabilities", "attack_paths"):
        with open(os.path.join(tmp, f"{name}.json"), encoding="utf-8") as f:
            out[name] = json.load(f)
    return out


def _lab(tmp):
    """The lab crawl (checklist and default-community probe on), the saved
    Wazuh endpoints and every NVD stage, with two protected assets."""
    from test_cdp import L3_CID, lab
    from test_device_stage import lab_nvd
    from test_nvd import FakeClock
    from vulnmapper.network.crawl import Crawler, build_document

    async def crawl():
        crawler = Crawler(lab(), concurrency=4, max_nodes=50, queue_maxsize=50,
                          checklist=True, check_default_communities=True)
        await crawler.seed(["172.20.20.254"])
        return await crawler.run()

    # pinned in its JSON form, the form the pipeline reads (integer keys become strings)
    network = json.loads(json.dumps(build_document(*asyncio.run(crawl()))))
    network_path = os.path.join(tmp, "network.json")
    with open(network_path, "w", encoding="utf-8") as f:
        json.dump(network, f)
    targets = os.path.join(tmp, "targets.json")
    with open(targets, "w", encoding="utf-8") as f:
        json.dump({f"device:{L3_CID}": {"importance": "moderate"},
                   "endpoint:102": {"importance": "high"}}, f)

    clock = FakeClock()
    out = _run_pipeline(tmp, ["--scored", os.path.join(_FIXTURES, "offline_scored.json"),
                              "--network", network_path, "--targets", targets,
                              "--check-default-communities"],
                        nvd_transport=lab_nvd(clock), clock=clock,
                        resolver=lambda ip: None)
    return {"lab.network.json": network, **{f"lab.{k}.json": v for k, v in out.items()}}


def _unmanaged(tmp):
    """One switch with three agentless hosts: one silent, one that answers SNMP
    and one that forwards traffic (crawled as a device). nmap finds OpenSSH on
    the answering host and the reverse lookup names it."""
    from snmp_fakes import FakeSnmpClient, load_rows
    from test_cdp import L2_CID
    from test_device_stage import lab_nvd
    from test_nvd import FakeClock
    from test_service_scan import (IPP_PORT, NBSTAT, SSH_CPE, SSH_CVES, SSH_SERVICE_PORT,
                                   FakeRunner, host_xml, listed, nmaprun, port)

    silent, answers, forwards = (("00:50:56:bb:00:01", "10.0.0.60"),
                                 ("00:50:56:bb:00:02", "10.0.0.50"),
                                 (L2_CID, "172.20.10.100"))
    hosts = (silent, answers, forwards)
    switch = {"chassis_id": "00:11:22:33:44:01", "ip": "10.0.0.1", "hostname": "core",
              "status": "online", "pollable": True, "lldp_cap_enabled": "0x2800",
              "fdb": [{"mac": mac, "port": f"Fa0/{i + 2}", "vlan": 10}
                      for i, (mac, _ip) in enumerate(hosts)],
              "arp": {mac: ip for mac, ip in hosts}}
    network_path = os.path.join(tmp, "network.json")
    with open(network_path, "w", encoding="utf-8") as f:
        json.dump({"nodes": [switch], "edges": []}, f)
    targets = os.path.join(tmp, "targets.json")
    with open(targets, "w", encoding="utf-8") as f:
        json.dump({"device:00:11:22:33:44:01": {"importance": "high"}}, f)

    l2 = load_rows("cisco_l2_switch.snmp")
    system = [r for r in l2 if r[0].startswith(("1.3.6.1.2.1.1.", "1.3.6.1.2.1.47."))]
    clock = FakeClock()
    nvd = lab_nvd(clock)
    nvd.cves[SSH_CPE] = SSH_CVES
    nvd.dictionary[SSH_CPE] = listed(SSH_CPE)
    runner = FakeRunner(nmaprun(host_xml(answers[1], SSH_SERVICE_PORT + IPP_PORT, NBSTAT),
                                host_xml(silent[1], port(80, service='name="http"'))))
    out = _run_pipeline(tmp, ["--no-endpoints", "--network", network_path, "--targets", targets,
                              "--probe-unmanaged-snmp", "--nmap-unmanaged"],
                        nvd_transport=nvd, clock=clock,
                        resolver=lambda ip: "printer.lab" if ip == answers[1] else None,
                        snmp_client=FakeSnmpClient({answers[1]: system, forwards[1]: l2}),
                        nmap_runner=runner)
    return {f"unmanaged.{k}.json": v for k, v in out.items()}


def _liveness(_tmp):
    """Three liveness passes over each frozen graph above, each pass carrying
    the state of the one before. The lab graph exercises agents, SNMP, ping and
    the access point's client list; the unmanaged one a port going down and
    coming back up next to a port no edge uses."""
    from test_liveness import FakeProber
    from vulnmapper.liveness import liveness_pass

    agents = [{"id": "000", "status": "active", "lastKeepAlive": "9999-12-31T23:59:59Z"},
              {"id": "101", "status": "active", "lastKeepAlive": "2026-10-07T09:00:15Z"},
              {"id": "102", "status": "disconnected", "lastKeepAlive": "2026-10-07T08:00:00Z"},
              {"id": "103", "status": "active", "lastKeepAlive": "2026-10-07T08:00:00Z"},
              {"id": "105", "status": "active", "lastKeepAlive": "2026-10-07T09:00:15Z"}]
    lab = [FakeProber(snmp={"172.20.20.254": True, "172.20.10.100": True, "172.20.99.21": True},
                      icmp={"172.20.100.1": True, "10.10.0.14": True}, agents=agents,
                      wifi={"172.20.99.21": {"7abd0618062c", "e4a7a025ceac"}},
                      ports={"172.20.20.254": {"Fa1/0/6": "up"}}),
           FakeProber(snmp={"172.20.20.254": True}, icmp={}, agents=agents,
                      wifi={"172.20.99.21": {"7abd0618062c"}},
                      ports={"172.20.20.254": {"Fa1/0/6": "down"}}),
           FakeProber(snmp={"172.20.20.254": True, "172.20.99.21": True}, agents=agents,
                      wifi={"172.20.99.21": RuntimeError("walk failed")},
                      ports={"172.20.20.254": {"Fa1/0/6": "up"}})]
    unmanaged = [FakeProber(snmp={"10.0.0.1": True}, icmp={"10.0.0.60": True, "10.0.0.50": True},
                            ports={"10.0.0.1": {"Fa0/2": "up", "Fa0/3": "up", "Fa0/9": "down"}}),
                 FakeProber(snmp={"10.0.0.1": True}, icmp={"10.0.0.50": True},
                            ports={"10.0.0.1": {"Fa0/2": "down", "Fa0/3": "up", "Fa0/9": "down"}}),
                 FakeProber(snmp={"10.0.0.1": True}, icmp={"10.0.0.60": True},
                            ports={"10.0.0.1": {"Fa0/2": "up", "Fa0/3": "up", "Fa0/9": "up"}})]
    times = ("2026-10-07T09:00:20+00:00", "2026-10-07T09:00:40+00:00",
             "2026-10-07T09:01:00+00:00")
    out = {}
    for name, probers in (("lab", lab), ("unmanaged", unmanaged)):
        with open(os.path.join(_GOLDEN, f"{name}.graph.json"), encoding="utf-8") as f:
            graph = json.load(f)
        state, passes = {}, []
        for prober, now in zip(probers, times):
            state = asyncio.run(liveness_pass(graph, state, prober, 2, now=now))
            passes.append(state)
        out[f"{name}.liveness.json"] = {"passes": passes}
    return out


SCENARIOS = {"parenting_ladder": lambda _tmp: _assemble_only(),
             "lab": _lab,
             "unmanaged": _unmanaged,
             "liveness": _liveness}


def produce(name: str) -> dict:
    """``{golden file name: normalised document}`` for one scenario."""
    tmp = tempfile.mkdtemp()
    try:
        return {fname: normalise(doc) for fname, doc in SCENARIOS[name](tmp).items()}
    finally:
        shutil.rmtree(tmp)


class TestGolden(unittest.TestCase):
    def test_outputs_match_frozen_golden(self):
        for name in SCENARIOS:
            for fname, produced in produce(name).items():
                with self.subTest(scenario=name, file=fname):
                    path = os.path.join(_GOLDEN, fname)
                    self.assertTrue(os.path.exists(path),
                                    f"missing golden {path}; run scripts/_freeze_golden.py")
                    with open(path, encoding="utf-8") as f:
                        expected_text = f.read()
                    self.assertEqual(produced, json.loads(expected_text))
                    self.assertEqual(dump(produced), expected_text)


if __name__ == "__main__":
    unittest.main()
