# certifex-minimus-rs

Tiny tailnet service naming and HTTPS ingress.

- `certifex-senex`: registrar/control plane. Reconciles public DNS and ACME certificate issuance.
- `certifex-iuvenis`: node agent/data plane. Owns the local private key, requests certificates for its service names, validates and installs them, and terminates/proxies HTTPS on the node.

The intended v1 model is deliberately small: public DNS points each service name directly at the Tailscale `100.64.0.0/10` address of the node that hosts it; certificates are ordinary multi-SAN Let's Encrypt certificates; traffic never hairpins through a central proxy.
