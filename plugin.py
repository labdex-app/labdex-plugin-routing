"""Routing discovery: BGP neighbours and routes from OPNsense (FRR) or Cisco IOS-XE (RESTCONF)."""
from __future__ import annotations

import ipaddress

from labdex.plugins.base import Plugin as Base
from labdex.plugins.base import PluginError

PROTO = {"connected": "connected", "direct": "connected", "local": "connected", "static": "static", "bgp": "bgp", "ospf": "ospf",
         "ospfv3": "ospf", "kernel": "kernel", "isis": "isis", "rip": "rip", "eigrp": "eigrp"}


def _proto(p: str) -> str:
    p = (p or "").split(":")[-1].lower()
    return PROTO.get(p, p or "?")


class Plugin(Base):
    def _http(self):
        s = self.settings
        if not s.get("url"):
            raise PluginError("set the URL first")
        headers = {"Accept": "application/yang-data+json"} if s.get("source") == "cisco_restconf" else {}
        return self.ctx.http(s["url"].rstrip("/") + "/", verify=bool(s.get("verify_tls", True)), timeout=20,
                             auth=(s.get("username", ""), s.get("password", "")), headers=headers)

    # ------------------------------------------------------------- sources
    def _frr(self, http):
        neigh = []
        summary = (http.get("api/quagga/diagnostics/bgpsummary").json() or {}).get("response") or {}
        for afi, block in summary.items():
            if not isinstance(block, dict):
                continue
            for peer, p in (block.get("peers") or {}).items():
                neigh.append({"peer": peer, "afi": afi, "remote_as": p.get("remoteAs"), "state": p.get("state") or p.get("bgpState") or "?",
                              "prefixes": p.get("pfxRcd", p.get("prefixReceivedCount")), "uptime": p.get("peerUptime", ""),
                              "description": p.get("desc", "") or p.get("description", "")})
        routes = []
        for fam in ("4", "6"):
            rows = (http.post(f"api/quagga/diagnostics/search_generalroute{fam}", json={"current": 1, "rowCount": -1}).json() or {}).get("rows") or []
            for r in rows:
                if r.get("selected") is False:
                    continue
                routes.append({"prefix": r.get("prefix", ""), "protocol": _proto(r.get("protocol", "")), "nexthop": r.get("ip") or "",
                               "interface": r.get("interfaceDescr") or r.get("interfaceName") or ""})
        return neigh, routes

    def _restconf(self, http):
        neigh = []
        try:
            d = http.get("restconf/data/Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors").json()
            for n in (d.get("Cisco-IOS-XE-bgp-oper:neighbors") or {}).get("neighbor") or []:
                state = ((n.get("connection") or {}).get("state") or "?").replace("fsm-", "")
                pfx = (((n.get("prefix-activity") or {}).get("received") or {}).get("current-prefixes"))
                neigh.append({"peer": n.get("neighbor-id", ""), "afi": n.get("afi-safi", ""), "remote_as": n.get("as"),
                              "state": "Established" if state.lower() == "established" else state, "prefixes": pfx,
                              "uptime": n.get("up-time", ""), "description": n.get("description", "")})
        except PluginError as exc:
            if "404" not in str(exc):
                raise
            self.log("no BGP on this router")
        routes = []
        for fam in ("ipv4", "ipv6"):
            data = None
            for path in (f"restconf/data/ietf-routing:routing-state/routing-instance=default/ribs/rib={fam}-default/routes",
                         f"restconf/data/ietf-routing:routing/ribs/rib={fam}-default/routes"):
                try:
                    data = http.get(path).json()
                    break
                except PluginError as exc:
                    if "404" not in str(exc):
                        raise
            for r in ((data or {}).get("ietf-routing:routes") or {}).get("route") or []:
                nh = r.get("next-hop") or {}
                routes.append({"prefix": r.get("destination-prefix", ""), "protocol": _proto(r.get("source-protocol", "")),
                               "nexthop": nh.get("next-hop-address") or nh.get("ietf-ipv4-unicast-routing:next-hop-address") or "",
                               "interface": nh.get("outgoing-interface", "")})
        return neigh, routes

    def _read(self):
        http = self._http()
        return self._restconf(http) if self.settings.get("source") == "cisco_restconf" else self._frr(http)

    def test(self):
        neigh, routes = self._read()
        return f"{len(routes)} routes, {len(neigh)} BGP neighbour(s)"

    # ------------------------------------------------------------- compare
    def compare(self, routes):
        from labdex.models import Network, NetworkPrefix, db
        inv = []
        for p in db.session.scalars(db.select(NetworkPrefix)):
            if p.prefix:
                try:
                    inv.append((ipaddress.ip_network(p.prefix, strict=False), p.network.name))
                except ValueError:
                    pass
        ignore = []
        for c in self.settings.get("ignore") or []:
            try:
                ignore.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
        unknown, covered = [], set()
        for r in routes:
            try:
                net = ipaddress.ip_network(r["prefix"], strict=False)
            except ValueError:
                continue
            if net.prefixlen == 0:
                continue
            if net.prefixlen == net.max_prefixlen and not self.settings.get("host_routes"):
                for n, name in inv:
                    if n.version == net.version and net.subnet_of(n):
                        covered.add(name)
                continue
            hit = [name for n, name in inv if n.version == net.version and (net.subnet_of(n) or n.subnet_of(net))]
            covered |= set(hit)
            if not hit and not any(net.version == i.version and net.subnet_of(i) for i in ignore):
                unknown.append(r | {"prefix": str(net)})
        no_route = sorted({name for _, name in inv} - covered)
        nets = {n.name: n for n in db.session.scalars(db.select(Network).where(Network.name.in_(no_route)))} if no_route else {}
        return unknown, [{"network": n, "prefixes": ", ".join(p.prefix for p in nets[n].prefixes if p.prefix)} for n in no_route if n in nets]

    def run_read(self, params):
        neigh, routes = self._read()
        unknown, no_route = self.compare(routes)
        old = {n["peer"]: n["state"] for n in (self.ctx.state.get("routing") or {}).get("neighbours", [])}
        match = self.ctx.match_host()
        for n in neigh:
            n["host"] = match(n["peer"]) or ""
            was = old.get(n["peer"])
            if was == "Established" and n["state"] != "Established":
                self.ctx.notify("neighbour_down", f"BGP neighbour {n['peer']} is {n['state']}",
                                f"{n.get('description') or n['host'] or n['peer']} (AS {n.get('remote_as')}) on {self.ctx.name}",
                                f"/integrations/{self.ctx.name}?tab=routes", {"peer": n["peer"], "state": n["state"]})
        for u in unknown:
            self.log(f"not in the inventory: {u['prefix']} ({u['protocol']} via {u['nexthop'] or u['interface'] or '?'})")
        self.ctx.set_state("routing", {"neighbours": neigh, "unknown": unknown, "no_route": no_route, "routes": len(routes)})
        return {"routes": len(routes), "neighbours": len(neigh), "established": sum(1 for n in neigh if n["state"] == "Established"),
                "unknown": len(unknown), "no_route": len(no_route)}

    # ---------------------------------------------------------------- views
    def page_routes(self, args):
        st = self.ctx.state.get("routing") or {}
        neigh = st.get("neighbours", [])
        return {"summary": [{"label": "routes", "value": st.get("routes", 0)},
                            {"label": "neighbours established", "value": f"{sum(1 for n in neigh if n['state'] == 'Established')}/{len(neigh)}",
                             "tone": "ok" if all(n["state"] == "Established" for n in neigh) else "err"},
                            {"label": "unknown prefixes", "value": len(st.get("unknown", [])), "tone": "warn" if st.get("unknown") else "ok"},
                            {"label": "networks without a route", "value": len(st.get("no_route", [])), "tone": "warn" if st.get("no_route") else "ok"}],
                "sections": [
                    {"title": "BGP neighbours", "type": "table",
                     "columns": [{"key": "peer", "label": "Peer"}, {"key": "host", "label": "Host"}, {"key": "remote_as", "label": "AS"},
                                 {"key": "state", "label": "State"}, {"key": "prefixes", "label": "Prefixes"}, {"key": "uptime", "label": "Up"},
                                 {"key": "description", "label": "Description"}],
                     "rows": [n | {"_tone": "" if n["state"] == "Established" else "err"} for n in neigh], "empty": "No BGP neighbours."},
                    {"title": "Routed, but not in the inventory", "type": "table",
                     "columns": [{"key": "prefix", "label": "Prefix"}, {"key": "protocol", "label": "From"}, {"key": "nexthop", "label": "Next hop"},
                                 {"key": "interface", "label": "Interface"}],
                     "rows": [u | {"_tone": "warn"} for u in st.get("unknown", [])], "empty": "Every routed prefix is an inventory network."},
                    {"title": "In the inventory, but no route", "type": "table",
                     "columns": [{"key": "network", "label": "Network"}, {"key": "prefixes", "label": "Prefixes"}],
                     "rows": st.get("no_route", []), "empty": "The router has a route for every inventory network."}],
                "note": "Read-only. Add prefixes that are fine without a network to the plugin's “Ignore prefixes”."}

    def widget_neighbours(self, host):
        st = self.ctx.state.get("routing")
        if not st:
            return {"kind": "list", "items": [], "sub": "run “Read routes and neighbours”"}
        items = [{"label": n.get("description") or n["peer"], "state": "up" if n["state"] == "Established" else "down",
                  "detail": f"AS {n.get('remote_as')} · {n.get('prefixes') if n.get('prefixes') is not None else '?'} prefixes",
                  "link": f"/integrations/{self.ctx.name}?tab=routes"} for n in st["neighbours"]]
        extra = len(st.get("unknown", []))
        return {"kind": "status", "items": items, "link": f"/integrations/{self.ctx.name}?tab=routes",
                "sub": f"{extra} routed prefix(es) not in the inventory" if extra else "routes match the inventory"}
