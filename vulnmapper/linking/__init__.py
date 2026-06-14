"""Endpoint -> switch edge resolution.

Endpoints don't speak LLDP, so the crawler gives them no adjacency edges. This
layer resolves each endpoint to the switch/port it hangs off, using the switch
MAC forwarding tables (FDB) the crawler now collects. The matching is trivial;
the disambiguation — an endpoint's MAC appears in *every* switch's FDB along its
L2 path — is the whole point, and is what :mod:`fdb_link` does.
"""
