# Incident groups

The **Incidents** page groups related episodes and shows the reason, a timeline, declared dependencies, and recent investigation reports. Individual episodes retain their evidence. You can request or stop an AI investigation for a group from this page.

## Dependencies and correlation

In a server's overview, use **Server dependencies** to select up to 64 other servers. The relationship is directional. Correlation uses the connected component of the dependency graph. For static Ansible inventories of up to 500 hosts, Cyberbot also establishes links to an anchor host. A routine inventory refresh respects manually removed links. Manual address lists do not create automatic links.

Correlation runs locally and requires episodes on at least two distinct servers. The window is ten minutes from the first episode. Cyberbot uses these signals in order:

1. A shared component of declared dependencies.
2. For connection failures, the same explicitly configured ProxyJump.
3. The same check and server source.

The group expresses a relationship between observations. A shared cause still needs investigation. Resource, service, and availability episodes can be grouped. Security events, package CVEs, and custom checks retain their separate evaluation rules. Timestamps come from observations recorded by the desktop.

## Investigation and recovery

An eligible group receives one automatic job and one budget reservation. Waiting individual jobs can be merged. If an episode already triggered an investigation, the group reuses that run instead of starting a duplicate. For eligible fleet incidents, a two-minute grace period allows related observations to arrive before automatic investigation.

A group investigation can include up to 500 servers in the frozen scope, including relevant dependencies. Late additions and endpoint changes cannot expand the scope of an active run. MCP serves the group's own events and a bounded list of allowed servers, plus saved summaries and limited refreshes. Group limits include 24 MCP calls, four remote refreshes, and five minutes of investigation time.

A group recovers when all its episodes meet their own recovery rules. Missing coverage cannot confirm recovery. Closing an episode manually preserves its evidence and history. Automatic work and incident-group retention follow the [desktop storage and queue policies](architecture.md).
