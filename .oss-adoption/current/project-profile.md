# Koi adoption profile

**Who:** container/LAN developers and technically capable homelab operators,
especially mixed Windows/Linux environments.

**Task:** label a container, open its application from another computer, and keep
names and state correct through restart, recreation and removal.

**Why try it:** reduce repeated coordination between runtime inventory, mDNS,
local naming and reachability while keeping existing tools and bridge networking.

**Private-space identity and trust:** Certmesh provides locally governed member
enrollment, certificate renewal and signed membership/revocation information for
participating applications. It is an existing product pillar alongside discovery.
Applications integrate identity checks and define their own access rules.

**Next release extension:** exact service-name HTTPS, explicit client DNS/root setup,
renewal and recovery, with one fully verified proxy/resolver recipe.

**Boundaries:** no universal multicast adaptation, no implied trust on arbitrary
devices, no overlay network or enterprise identity promise. MCP and embedded APIs
are integration paths, not evidence of demand on their own.

**Adoption model:** useful independent installations, reusable integrations,
contributors and sustainable support. No commercial sales funnel is assumed.

[Decision](../../docs/adr/046-container-lan-adoption.md) ·
[Readiness](../../docs/launch/README.md) ·
[Cohort protocol](../../docs/launch/cohort.md)
