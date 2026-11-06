# Koi landing page

`index.html` is the static source for the Koi page. This checkout is not evidence
that its current content is deployed. Publishing remains a separate action.

The page introduces the container/LAN adoption task and directs visitors to a
named release artifact and matching documentation. It must not imply that the
development branch, npm packaging or an unverified scenario is publicly ready.

## Content contract

- Lead with one container application found and opened from a second machine.
- Describe lifecycle verification, existing-tool fit and the actual audience.
- Give Certmesh a visible **Private-space identity and trust** pillar: a hero
  pointer and a dedicated section linked to the [Certmesh guide](../docs/guides/certmesh.md).
  Explain the local CA, member enrollment/renewal, signed membership/revocation
  information for participating Koi-aware applications, and recovery options.
- Keep network isolation, application authorization and browser HTTPS as separate
  responsibilities. Certmesh visibility does not expand the initial preview gate
  or imply a completed exact service-name integration.
- Separate stable 0.9.0, prerelease 1.0.0-rc.2 and development 1.0.0-dev.0.
- Use [release readiness](../docs/launch/README.md) to determine supported claims.
- Treat trusted exact service-name HTTPS as a separate extension.
- Do not claim measured setup times or broad platform acceptance without evidence.

## Hosting

The owned page is https://sylin.org/koi/. If bootstrap scripts are served under
that path, serve bytes from an identified release tag or redirect to that exact
tagged file. Do not silently mix development instructions and stable binaries.

The page has no build or external runtime dependency. Before deployment, inspect
its narrow-screen layout, keyboard links and release links; update
the public support statement only after the named artifact's evidence is accepted.
