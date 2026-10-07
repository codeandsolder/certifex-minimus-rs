# certifex-minimus-rs

Tiny tailnet service naming and HTTPS ingress.

`certifex-senex` is the central registrar/control plane. `certifex-iuvenis` runs on each service node. The intended v1 model is deliberately small:

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

## What each side owns

### `certifex-iuvenis` — node/data plane

- generates and retains the node P-256 private key locally;
- derives service FQDNs from a tiny TOML config;
- sends only a signed CSR, node ID, service names, and observed Tailscale IPv4 to the registrar;
- rejects certificate rollback;
- verifies public trust, validity, every requested DNS name, the exact SAN set, and leaf SPKI equality with the local private key before installing a generation;
- terminates TLS directly on the node's Tailscale address;
- routes by the original HTTP authority/`Host` to configured localhost ports;
- supports HTTP/1.1 and HTTP/2 ingress, streaming bodies, and HTTP upgrade/WebSocket tunneling;
- hot-loads new certificate generations for future handshakes without dropping existing connections;
- notices node config changes while running.

If persisted certificate state is corrupt or no longer matches the private key, the node stays alive with TLS disabled, reports no usable installed generation, and lets the registrar repair it instead of getting stuck in a restart loop.

### `certifex-senex` — registrar/control plane

- owns the Cloudflare DNS credential and the ACME account, not node private keys;
- accepts only Tailscale IPv4 claims and rejects a remote registration whose TCP source address differs from the claimed address;
- only permits names below the configured base domain;
- keeps hostname ownership stable across restarts and rejects collisions between nodes;
- reconciles unproxied Cloudflare `A` records to the node Tailscale address and removes names a node relinquishes;
- completes ACME DNS-01 challenges in parallel, then removes challenge TXT records;
- stores the issued chain plus generation centrally so offline/rebuilt nodes can fetch it later;
- treats a changed CSR/key as requiring a new certificate even when the SAN set did not change;
- renews centrally while nodes may be offline;
- follows ACME Renewal Information (ARI), persisting a randomized point inside the CA's suggested renewal window; if ARI is unsupported it renews at two-thirds of certificate lifetime, and transient ARI failures retain the previous safe target while retrying ARI later.

## Node configuration

```toml
node_id = "laptop"
domain = "example.com"
registrar = "http://100.64.0.1:7443"

[services]
grafana = 3000
victoria = 8428
```

This requests one certificate whose SAN set is exactly `grafana.example.com` and `victoria.example.com`, then routes those names to `127.0.0.1:3000` and `127.0.0.1:8428` respectively.

Service labels are intentionally one DNS label deep. Wildcards and arbitrary nested names are out of scope for v1.

### Path fan-out services

A node can also publish one hostname that selects among multiple local TCP backends by URL path. This is useful for replica banks, test workers, sharded local services, or any other node-local set where creating one DNS name per backend would be needless.

```toml
[fanouts.workers]

[[fanouts.workers.files]]
path = "/inventory.json"
source = "/run/workers/inventory.json"

[[fanouts.workers.tcp_ranges]]
path_prefix = "/"
first = 1
last = 16
port_start = 9000
```

The example requests `workers.example.com`; `port_start` is the backend port selected by `first`. `GET /inventory.json` and `HEAD /inventory.json` serve the current file directly with `Cache-Control: no-store`. An HTTP/1.1 `CONNECT /7` opens `127.0.0.1:9006`; after the `200 OK` response the connection is a raw bidirectional TCP tunnel. File routes take precedence over TCP ranges. Backends remain loopback-only by design.

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
2. systemd credential `${CREDENTIALS_DIRECTORY}/cloudflare-token`;
3. the environment variable named by `--cloudflare-token-env` (default `CLOUDFLARE_API_TOKEN`).

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

A peer that is already trusted onto the reachable tailnet can attempt first registration of an otherwise-unclaimed service name. Existing ownership cannot be silently stolen because names are persisted and collision-checked, but v1 does not yet have a second application-layer enrollment secret or Tailscale identity API check.

The node still treats the registrar as untrusted with respect to private-key possession: it accepts a returned certificate only when the chain is publicly valid, the SAN set is exactly what the node requested, and the leaf public key matches the private key that never left the node.

## Tested paths

The proxy path has been exercised on a real Tailscale node with:

- HTTP/2 client ingress translated to HTTP/1.1 localhost origin traffic;
- preservation of the external `Host`/authority and `X-Forwarded-{Host,Proto,For}`;
- unknown-host isolation (`404`);
- RFC hop-by-hop header stripping;
- a real `101 Switching Protocols` upgraded byte stream tunneled in both directions;
- hot certificate state loading and recovery from an intentionally mismatched persisted key/certificate.

CI runs stable Rust checks/tests plus the repository's `rust-skills2` strict nightly policy.
