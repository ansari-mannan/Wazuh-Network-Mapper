import { Network, Router, Shield, Monitor, Server, Box } from "lucide-react";

// role -> icon, in the clean/flat "network diagram" style (lucide, MIT licensed —
// deliberately NOT Cisco's proprietary Packet Tracer assets). Glyphs are chosen
// to be instantly recognizable: a switch reads as a network node, a router as a
// router, a firewall as a shield, a host as a monitor, a server as a server.
const ROLE_ICON = {
  "l3-switch": Network,
  "l2-switch": Network,
  switch: Network,
  router: Router,
  firewall: Shield,
  host: Monitor,
  station: Monitor,
  server: Server,
  scanner: Server,
};

export function iconForRole(role) {
  return ROLE_ICON[(role || "").toLowerCase()] || Box; // unknown -> generic box
}
