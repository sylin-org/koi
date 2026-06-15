# Trusted HTTPS across two machines in ~10 minutes

You have a service on host **B** — say a dashboard on `127.0.0.1:3000`. You want to open it from a laptop **C** as a real HTTPS URL with **no certificate warning**, and you don't want to buy a public domain, run a DNS challenge, or hand-copy PEM files around.

This is the end-to-end journey: stand up a private CA on host **A**, enroll host **B**, put a TLS endpoint in front of the service, and teach a non-member laptop **C** to trust the CA root. By the end you open `https://<name>` in a browser and it's green.

Three machines, one for each role:

| Role | Machine | What it does |
| ---- | ------- | ------------ |
| **A** | CA host | Runs the certmesh CA (the root of trust) |
| **B** | service host | Joins the mesh, runs the service + the TLS proxy |
| **C** | client | A plain laptop with **no Koi membership** — it just needs to trust the root |

> A and B can be the **same** machine if you only have two boxes — create the CA and run the service on one host, and treat the laptop as C. The steps don't change.

Every step below is a real Koi command; nothing here is invented. Each capability has a deeper guide linked inline if you want the full story — this page is just the shortest correct path through all of them.

> **Prerequisite — a running daemon on A and B.** Certmesh, DNS, and proxy are all daemon-mediated. On each of A and B, either install Koi as a service (`koi install`) or run `koi --daemon` in a terminal. The CLI talks to that daemon for you.

---

## Step 1 — On host A: create the CA

The CA is your network's root of trust. Creating it is a deliberate act, so it runs an interactive ceremony:

```
koi certmesh create
```

The ceremony asks you to pick a **posture** (one of three presets — **Just Me**, **My Team**, **My Organization** — or **Custom**), contribute keyboard entropy, set a passphrase, and scan a **TOTP** QR code into an authenticator app. For a homelab, take the **Just Me** preset — it auto-unlocks on boot and opens enrollment with no approval queue:

```
koi certmesh create --profile just-me
```

When it finishes, A has an ECDSA P-256 CA, has self-enrolled its own certificate, and has installed the CA root in its own system trust store. Confirm:

```
koi certmesh status
```

```
Certificate mesh: active
  CA locked:  false
  Enrollment: open (no approval)
  Members:    1
    host-a (primary) - active
```

Keep the **TOTP authenticator** handy — host B needs a live code to join. (Posture presets, unlock methods, and the envelope encryption that protects the CA key are covered in the [certmesh guide](../guides/certmesh.md).)

---

## Step 2 — On host B: join the mesh

From host B, a single command browses the LAN for the CA over mDNS and enrolls:

```
koi certmesh join
```

```
Searching for certmesh CA on the local network...
Found CA: host-a Certmesh CA at http://192.168.1.10:5641
Enter the TOTP code from your authenticator app:
123456
Enrolled as: host-b
Certificates written to: /var/lib/koi/certs/host-b
```

You type the **current TOTP code from A's authenticator** — that's the whole authorization handshake. No CSR, no key exchange, no approval queue (unless your posture requires approval, which **Just Me** does not).

If mDNS discovery can't find exactly one CA (different broadcast domains, multiple CAs), point at the endpoint directly:

```
koi certmesh join http://192.168.1.10:5641
```

B now holds a certmesh-issued member certificate at `certs/host-b/`. **Its SANs are `host-b` and `host-b.local`** — that detail matters in Step 3 and Step 5. (Full join flow, including the `503 CA locked` case and `koi certmesh unlock`, is in the [certmesh guide](../guides/certmesh.md).)

---

## Step 3 — On host B: put a TLS endpoint in front of the service

Two parts: give the service a name, then bind a TLS listener that terminates with the member cert.

First, make sure Koi's DNS resolver is running and register the name (run this on whichever host is your resolver — typically A, or wherever you point clients):

```
koi dns serve
koi dns add host-b 192.168.1.20      # B's LAN IP
```

`koi dns add` takes a **name and an IP** (positional). Now `host-b.lan` resolves to B. (Koi DNS owns the `.lan` zone by default; coexisting with an existing resolver is covered in the [DNS guide](../guides/dns.md) and [DNS coexistence guide](../guides/dns-coexistence.md).)

Then, on B, bind the proxy:

```
koi proxy add app --listen 9443 --backend 127.0.0.1:3000
```

`--backend` is a `host:port`; loopback backends need no extra flag (the proxy→backend hop is plaintext, so non-loopback backends require `--backend-remote`). Check what's serving:

```
koi proxy status
```

```
NAME  LISTEN  BACKEND          TLS       STATE
app   :9443   127.0.0.1:3000   certmesh  running
```

The `TLS: certmesh` column is the win — the proxy found `certs/host-b/fullchain.pem` and is terminating TLS with the **member certificate**, the one every mesh member already trusts. (How the proxy resolves its cert, and the `self-signed` fallback, are in the [proxy guide](../guides/proxy.md).)

> **The name has to match the cert.** A browser only stays green if the URL's hostname is a **SAN on the served certificate**. The member cert covers `host-b` and `host-b.local`. So in Step 5 the no-warning URL is **`https://host-b.local:9443`** (or `https://host-b:9443`), served by the member cert. If you want a *zone-named* vanity URL like `https://app.lan` with no warning, see [Want `app.lan` instead?](#want-applan-instead) below — that needs a cert that lists `app.lan`, which the member cert does not.

---

## Step 4 — On laptop C: trust the CA root

This is the crucial, often-skipped part. C is **not** a mesh member, so nothing has told its trust store about your CA. Members trust the root automatically; a non-member must be handed the root once.

**On host A**, export the certmesh root to a file:

```
koi trust export --ca > koi-root.pem
```

That prints the CA root certificate (PEM) to stdout. Copy `koi-root.pem` to laptop C by whatever you'd normally use (scp, a USB stick, a chat to yourself).

**On laptop C**, install it into the OS trust store:

```
koi trust install ./koi-root.pem
```

`install` validates that the file is a real X.509 **CA** certificate (a leaf/server cert is rejected with `not a CA certificate`), then adds it to the system store — browsers, `curl`, and language runtimes all pick it up. You can see and later undo what Koi installed:

```
koi trust list
koi trust remove koi-koi-root        # untrust later — every door has an exit
```

(`koi trust` and its interop with step-ca / mkcert / Caddy roots is in the [integrations guide](../guides/integrations.md#trust-root-distribution).)

> **`koi trust` needs Koi on C, but C never joins the mesh.** Installing the binary just to run one `trust install` is the easy path. If you can't put Koi on C at all, you can still trust `koi-root.pem` by hand through the OS's normal "add a trusted root" UI / `update-ca-certificates` flow — `koi trust` is the convenience, not a requirement.

---

## Step 5 — Confirm green

On laptop C, name resolution for `.local` is handled natively by the OS (Bonjour on macOS, the DNS Client on Windows, Avahi on Linux) over mDNS — so `host-b.local` already resolves without C using Koi's resolver at all.

Verify on the command line first — `curl` exits `0` and prints no TLS error:

```sh
curl -v https://host-b.local:9443/
#  * SSL certificate verify ok.
```

If `curl` is green, the browser will be too. Open it:

```
https://host-b.local:9443
```

No warning, a real padlock. The chain is: the proxy presented B's member cert → that cert chains to your CA root → C trusts that root (Step 4). End to end, trusted HTTPS between two machines with no public CA and no per-client PEM juggling.

If you instead pointed C at Koi's resolver for the `.lan` zone (see the [DNS coexistence guide](../guides/dns-coexistence.md)), `https://host-b:9443` works the same way — `host-b` is also a SAN on the member cert.

---

## What this required (the honest version)

- **C must trust the root.** There is no way around handing a non-member the CA root once (Step 4). That single trust step is what removes the warning — TLS validation is doing exactly its job.
- **The URL name must be on the cert.** The proxy serves B's **member certificate**, whose SANs are `host-b` and `host-b.local`. That's why the working URL is host-named. A different name needs a different cert — see below.
- **The proxy is a byte passthrough.** It terminates TLS and pipes bytes to the backend; it does no path routing or header rewriting. For that, run Caddy/Traefik and let them get certs from Koi over ACME (next section).

---

## Want `app.lan` instead?

To open a *vanity* zone name like `https://app.lan` (not the host's own name) with no warning, the served cert has to list `app.lan` as a SAN — and `koi certmesh join` does **not** add arbitrary SANs to the member cert. The clean way to get an `app.lan` cert is Koi's **ACME facade**, which issues for any name **inside your DNS zone** (`.lan` by default):

1. Point a standard ACME client (Caddy, Traefik, `lego`) at Koi's directory: `koi certmesh acme enable` prints the URL and the one-time root-trust recipe.
2. The client orders `app.lan`, solves the in-process `dns-01` challenge, and gets a leaf that chains to your CA.
3. Either let that reverse proxy serve `app.lan` directly, or drop the issued `fullchain.pem` + `key.pem` into `certs/app/` and run `koi proxy add app --listen 9443 --backend 127.0.0.1:3000` — the proxy serves the **per-entry** cert (it's checked ahead of the member cert) and `https://app.lan:9443` goes green.

The full ACME walk-through — scope, wildcards, and the bootstrap recipe — is in the [ACME guide](../guides/acme.md).

---

## Where to go next

- [certmesh guide](../guides/certmesh.md) — postures, unlock methods, renewal hooks, revocation, backup/restore.
- [proxy guide](../guides/proxy.md) — cert resolution order, remote backends, WebSockets/gRPC passthrough.
- [DNS guide](../guides/dns.md) — the three record sources, the `.lan` zone, port 53.
- [ACME guide](../guides/acme.md) — get certs for any in-zone name with the tools you already run.
- [integrations: trust](../guides/integrations.md#trust-root-distribution) — `koi trust` across step-ca / mkcert / Caddy.
- [security model](../reference/security-model.md) — the daemon access token (`x-koi-token`), bind addresses, what is and isn't protected.

> **A note on the API.** Everything above used the CLI, which reads the daemon's access token for you. If you script these steps over HTTP instead, mutating calls (`POST`/`PUT`/`DELETE` — e.g. `/v1/dns/add`, `/v1/proxy/add`, `/v1/certmesh/join`) need the token in an `x-koi-token` header. `koi token show` prints it; `koi token write <path>` writes a `0600` file for containers. See the [security model](../reference/security-model.md) for the details.
