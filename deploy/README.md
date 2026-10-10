# Deployment

Build the two release binaries and install them as `/usr/local/bin/certifex-iuvenis` and `/usr/local/bin/certifex-senex`.

## Registrar (`senex`)

1. Copy `senex.env.example` to `/etc/certifex-minimus/senex.env` and set the real base domain plus the registrar's Tailscale listen address. On startup, Senex publishes `certifex.<domain>` to that address.
2. Put a Cloudflare API token with DNS edit/read access for that zone in `/etc/certifex-minimus/cloudflare-token`, owned by root and mode `0600`.
3. Install `systemd/certifex-senex.service`, reload systemd, and start it.
4. Leave the ACME directory on Let's Encrypt staging until a node completes an end-to-end issuance and installation.
5. Change `CERTIFEX_ACME_DIRECTORY` to `https://acme-v02.api.letsencrypt.org/directory` and restart only after staging is clean.

The unit passes the token through systemd's credential mechanism. `certifex-senex` also supports `--cloudflare-token-file` and, for development, the `CLOUDFLARE_API_TOKEN` environment variable.

## Node (`iuvenis`)

1. Copy `node.toml.example` to `/etc/certifex-minimus/node.toml`, use the same base `domain` as Senex, and list each relative service name with its localhost port. Relative names may contain dots (for example `exits.waw`).
2. Install `systemd/certifex-iuvenis.service`, reload systemd, and start it.
3. The agent creates its P-256 private key under `/var/lib/certifex-minimus`, registers its CSR and Tailscale IPv4 address, validates returned certificates, and binds HTTPS on the node's Tailscale address.

Configuration changes are noticed without restarting the process. Certificate generations are hot-loaded for new TLS handshakes; existing connections continue normally.
