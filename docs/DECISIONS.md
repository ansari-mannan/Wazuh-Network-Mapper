# Design decisions

Decisions on the review's Part D items, agreed with the team before they were
changed.

## D4. Liveness interval: default 60 s (was 10 s)

Each liveness pass starts a new Python process, which imports pysnmp,
networkx and requests; every 10 s that is a noticeable CPU load on the
dashboard server. `vulnmapper.liveness.intervalSeconds` now defaults to 60.
The minimum stays 10, so an owner who wants faster detection can still set
it. A long-lived liveness process was the other option; it was not taken.
