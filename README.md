# certifex-minimus-rs

[![CI](https://github.com/codeandsolder/certifex-minimus-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/codeandsolder/certifex-minimus-rs/actions/workflows/ci.yml)

**Browser-trusted HTTPS and normal DNS names for Tailscale-only localhost services — without a central traffic proxy or private CA.**

Certifex Minimus turns services such as `127.0.0.1:3000` into ordinary URLs such as `https://grafana.example.com`. Public DNS points the name at the node's Tailscale CGNAT address, the node terminates a normal ACME certificate itself, and traffic stays end-to-end on the tailnet.

It is deliberately small: Rust, Cloudflare DNS, ACME DNS-01 / Let's Encrypt, and Tailscale are the whole idea. `certifex-senex` is the central registrar/control plane; `certifex-iuvenis` runs on each service node.

## How it works

```text
browser on tailnet
      |
      | https://grafana.example.com
      v
public DNS: grafana.example.com -> 100.64.12.34
      |
      | Tailscale route, no central traffic proxy
      v
certifex-iuvenis on 100.64.12.34:443
      |
      +--> Host: grafana.example.com -> http://127.0.0.1:3000
      +--> Host: victoria.example.com -> http://127.0.0.1:8428
```

The DNS records are public, ordinary unproxied `A` records, but the destination addresses are Tailscale CGNAT addresses (`100.64.0.0/10`). A machine without the tailnet route cannot reach the services. Certificates are normal publicly trusted multi-SAN ACME certificates, so browsers do not need a private CA installed.

### Why this exists

- **Normal custom-domain URLs:** use `https://grafana.example.com`, not a special proxy hostname or a locally trusted CA.
- **Nothing public except DNS:** DNS-01 proves control of the name; the service itself remains reachable only through Tailscale.
- **No central data-plane bottleneck:** the registrar handles DNS and certificates, then browsers connect directly to the target node.
- **Tiny node configuration:** map labels to localhost ports; certificate issuance, renewal, DNS reconciliation, and hot reload are automatic.

## What each side owns

### `certifex-iuvenis` — node/data plane

- generates and retains the node P-256 private key locally;
- derives service FQDNs and the registrar endpoint (`certifex.<domain>:7443`) from a tiny TOML config;
- sends only a signed CSR, node ID, service names, and observed Tailscale IPv4 to the registrar;
- rejects certificate rollback;
- verifies public trust, validity, every requested DNS name, the exact SAN set, and leaf SPKI equality with the local private key before installing a generation;
- terminates TLS directly on the node's Tailscale address;
- routes by the original HTTP authority/`Host` to configured localhost ports;
- supports HTTP/1.1 and HTTP/2 ingress, streaming bodies, and HTTP upgrade/WebSocket tunneling;
- hot-loads new certificate generations for future handshakes without dropping existing connections;
- notices node config changes while running;
- treats an empty service set as full deregistration, removing the local serving certificate and
  generation while retaining the node private key for future re-enrollment.

If persisted certificate state is corrupt or no longer matches the private key, the node stays alive with TLS disabled, reports no usable installed generation, and lets the registrar repair it instead of getting stuck in a restart loop.

### `certifex-senex` — registrar/control plane

- owns the Cloudflare DNS credential and the ACME account, not node private keys;
- publishes `certifex.<domain>` to its own Tailscale IPv4 when listening on the tailnet, so nodes never pin the registrar's address;
- reserves that hostname from node registrations;
- accepts only Tailscale IPv4 claims and rejects a remote registration whose TCP source address differs from the claimed address;
- only permits names below the configured base domain;
- keeps hostname ownership stable across restarts and rejects collisions between nodes;
- reconciles unproxied Cloudflare `A` records to the node Tailscale address and requires relinquished
  names to be removed before committing replacement node state;
- provisions all required ACME DNS-01 challenge records before validation, then removes challenge TXT records;
- stores the issued chain plus generation centrally so offline/rebuilt nodes can fetch it later;
- retains an inactive generation tombstone after full deregistration, preventing a crash between remote deregistration and local cleanup from turning the next enrollment into an apparent rollback;
- binds an active node ID to its CSR public key, so another tailnet peer cannot take over persisted hostname ownership by reusing the node ID;
- treats a changed CSR/SAN set under the same node key as requiring a new certificate;
- renews centrally while nodes may be offline;
- follows ACME Renewal Information (ARI), persisting a randomized point inside the CA's suggested renewal window; if ARI is unsupported it renews at two-thirds of certificate lifetime, and transient ARI failures retain the previous safe target while retrying ARI later.

## Node configuration

```toml
node_id = "laptop"
domain = "example.com"

[services]
grafana = 3000
victoria = 8428
```

This requests one certificate whose SAN set is exactly `grafana.example.com` and `victoria.example.com`, then routes those names to `127.0.0.1:3000` and `127.0.0.1:8428` respectively. The registrar endpoint is derived as `http://certifex.example.com:7443`.

Service names are relative DNS names below the configured base domain, so a node can publish `exits.waw` as `exits.waw.example.com`. The exact name `certifex` is reserved for the registrar. Wildcards are out of scope for v1.

### Path fan-out services

A node can also publish one hostname with file routes and typed local stream tunnels. Stream targets use HTTP/1.1 `CONNECT` and may terminate at either loopback TCP or a Unix stream socket.

```toml
[fanouts.workers]

[[fanouts.workers.files]]
path = "/inventory.json"
source = "/run/workers/inventory.json"

[[fanouts.workers.streams]]
path = "/control"
transport = "unix-stream"
socket = "/run/workers/control.sock"

[[fanouts.workers.stream_ranges]]
path_prefix = "/tcp/"
first = 1
last = 16
host = "127.0.0.1"
port_start = 9000
```

Exact stream targets support `tcp` and `unix-stream`; numeric stream ranges currently represent TCP port banks. IP targets must be loopback addresses and Unix socket paths must be absolute.

A request such as `CONNECT /tcp/7` maps to `127.0.0.1:9006`; after the `200 OK`, the connection is a raw bidirectional byte stream. `CONNECT /control` reaches the configured Unix stream socket. File routes take precedence over stream routes. Stream relays use 64 KiB buffers, selected from the proxy-only benchmark rather than Tokio's 8 KiB default.

## Registrar startup

ACME defaults to Let's Encrypt **staging** on purpose.

```sh
CLOUDFLARE_API_TOKEN=... \
  certifex-senex \
  --domain example.com \
  --listen 100.64.0.1:7443
```

For production, prefer a secret file or systemd credential rather than an environment variable. The registrar resolves the token in this order:

1. `--cloudflare-token-file PATH`;
2. `--cloudflare-token-json-file PATH` (reads its string `value` field);
3. systemd credential `${CREDENTIALS_DIRECTORY}/cloudflare-token`;
4. systemd credential `${CREDENTIALS_DIRECTORY}/cloudflare-token-json`;
5. the environment variable named by `--cloudflare-token-env` (default `CLOUDFLARE_API_TOKEN`).

After an end-to-end staging issuance succeeds, switch to production explicitly:

```text
https://acme-v02.api.letsencrypt.org/directory
```

The Cloudflare token only needs access to read the target zone and create/update/delete DNS records in that zone.

## Deployment

Ready-to-adapt systemd units and example configuration live under [`deploy/`](deploy/README.md).

The units use:

- `DynamicUser=yes`;
- private state directories;
- systemd credentials for the Cloudflare token;
- a strict filesystem/kernel sandbox;
- no capabilities for `senex`;
- only `CAP_NET_BIND_SERVICE` for `iuvenis` so it can bind 443 without running as root.

## Security boundary

The registrar API itself is intentionally minimal and currently relies on the tailnet as the authenticated network boundary plus source-address matching. It should be reachable only over Tailscale (and ideally constrained with Tailscale ACLs/firewall policy); do **not** expose the registrar port to the public Internet.

A peer that is already trusted onto the reachable tailnet can attempt first registration of an otherwise-unclaimed service name. Active node IDs are bound to the public key in their first validated CSR, while hostname ownership is persisted and collision-checked, so a different peer cannot take over an existing registration merely by reusing its node ID. Full deregistration releases that key binding but retains only the last certificate generation as an inactive tombstone; a later enrollment may therefore use a new key without resetting generation numbering. v1 does not yet have a second application-layer enrollment secret or Tailscale identity API check.

The node still treats the registrar as untrusted with respect to private-key possession: it accepts a returned certificate only when the chain is publicly valid, the SAN set is exactly what the node requested, and the leaf public key matches the private key that never left the node.

## Tested paths

The proxy path has been exercised on a real Tailscale node with:

- HTTP/2 client ingress translated to HTTP/1.1 localhost origin traffic;
- preservation of the external `Host`/authority, `X-Forwarded-{Host,Proto,For}`, and `X-Real-IP`;
- unknown-host isolation (`404`);
- RFC hop-by-hop header stripping;
- a real `101 Switching Protocols` upgraded byte stream tunneled in both directions;
- hot certificate state loading and recovery from an intentionally mismatched persisted key/certificate.

CI runs stable Rust checks/tests plus the repository's `rust-skills2` strict nightly policy.
