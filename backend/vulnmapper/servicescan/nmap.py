"""Running nmap against a host list, and parsing its XML.

The only active part of the tool. One ``nmap -sV`` invocation (service/version
detection, nmap's default ports and timing) over a host-list file, with the
benign nbstat discovery script for a Windows host's NetBIOS name. No OS
detection, no vuln scripts, no aggressive options. The host list carries only
IP addresses; nmap's arguments carry no secret.

The XML parse and the service/product/version extraction follow
github.com/AhmadNaaem/hev-scan. ElementTree only; no dependency added.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional

log = logging.getLogger("vulnmapper.servicescan")

PER_HOST_TIMEOUT_S = 60.0
# Service names that, on their own, name the kind of appliance answering.
_SERVICE_HINTS = {
    "ipp": "printer", "printer": "printer", "jetdirect": "printer", "pdl-datastream": "printer",
    "rtsp": "camera", "onvif": "camera",
}
_NETBIOS_NAME = re.compile(r"NetBIOS name:\s*([^,\n]+)")


class NmapBudgetExceeded(Exception):
    """nmap did not finish inside the run's time budget."""


class NmapRunner:
    """Locates nmap and runs it; ``available`` is False when it is not installed."""

    def __init__(self, nmap: Optional[str] = None) -> None:
        self.path = nmap or shutil.which("nmap")

    @property
    def available(self) -> bool:
        return self.path is not None

    def scan(self, ips: list, budget_s: float,
             per_host_timeout_s: float = PER_HOST_TIMEOUT_S) -> str:
        """nmap's XML for ``ips``. Raises :class:`NmapBudgetExceeded` on timeout.

        The host list goes in a temp file (IPs only) that nmap reads and that is
        removed afterwards, so no address sits on the command line.
        """
        fd, listfile = tempfile.mkstemp(prefix="vulnmapper-nmap-", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write("\n".join(ips) + "\n")
            args = [self.path, "-sV", "--script", "nbstat",
                    "--host-timeout", f"{int(per_host_timeout_s)}s", "-oX", "-", "-iL", listfile]
            try:
                proc = subprocess.run(args, capture_output=True, text=True, timeout=budget_s)
            except subprocess.TimeoutExpired:
                raise NmapBudgetExceeded()
            if proc.returncode != 0:
                log.warning("nmap exited %d: %s", proc.returncode, (proc.stderr or "").strip()[:200])
            return proc.stdout or ""
        finally:
            try:
                os.unlink(listfile)
            except OSError:
                pass


def _service_fields(service: Optional[ET.Element]) -> dict:
    if service is None:
        return {"service": None, "product": None, "version": None, "cpes": []}
    return {
        "service": service.get("name") or None,
        "product": service.get("product") or None,
        "version": service.get("version") or None,
        "cpes": [c.text for c in service.findall("cpe") if c.text],
    }


def _device_hint(open_ports: list) -> Optional[str]:
    """A guess at the kind of appliance, from a hardware CPE or a telltale
    service; None when nothing suggests one. Always a guess, never a fact."""
    for p in open_ports:
        for cpe in p.get("cpes") or []:
            if cpe.startswith("cpe:/h:"):
                parts = cpe.split(":")                # cpe:/h:vendor:product[:...]
                if len(parts) >= 4 and parts[2]:
                    return " ".join(x for x in parts[2:4] if x).replace("_", " ")
    for p in open_ports:
        hint = _SERVICE_HINTS.get((p.get("service") or "").lower())
        if hint:
            return hint
    return None


def parse_nmap_xml(xml_text: str) -> dict:
    """``{ip: {open_ports, netbios, device_hint}}`` for every host that answered.

    ``open_ports`` is a list of ``{port, protocol, service, product, version}``
    (service fields None where nmap did not detect them). A host with no open
    port is still returned (empty ``open_ports``) when it answered the scan.
    """
    out: dict = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        log.warning("could not parse nmap XML output")
        return out
    for host in root.findall("host"):
        ip = next((a.get("addr") for a in host.findall("address")
                   if a.get("addrtype") == "ipv4"), None)
        if ip is None:
            continue
        open_ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            fields = _service_fields(port.find("service"))
            open_ports.append({"port": int(port.get("portid")),
                               "protocol": port.get("protocol"), **fields})
        netbios = None
        for script in host.findall("hostscript/script"):
            if script.get("id") == "nbstat":
                m = _NETBIOS_NAME.search(script.get("output") or "")
                name = (m.group(1).strip() if m else "")
                netbios = name if name and name != "<unknown>" else None
        out[ip] = {"open_ports": open_ports, "netbios": netbios,
                   "device_hint": _device_hint(open_ports)}
    return out
