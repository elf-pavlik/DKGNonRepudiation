# did-hosting

Dev-only, reproducible host for the `did:web` DIDs used by the demo.

Every agent (issuer, user, two apps, TTP, CSS) identifies itself with a `did:web`.
For `did:web` to resolve, the DID document must be fetchable over HTTPS at the
URL derived from the DID (`did:web:host:path` -> `https://host/path/did.json`).
This folder generates those documents and a small HTTPS server that the
`did-host` container runs on the `solid-demo-net` network.

## How it fits together

- `seeds.json` — the committed dev secrets (one 32-char Ed25519 seed per agent).
  This is the source of truth.
- `generate.js` — derives the Ed25519 public key/fingerprint from each seed and
  writes:
  - `dids/<host>/<path>/did.json` for every agent
  - `generated.json` (derived DIDs, fingerprints, public keys, `did:key`s)
  - `../demo-ttp/config/did.json` (kept in sync)
- `contexts/` — JSON-LD contexts that are referenced by `@context` under the
  aliased hostnames (`NonRepudiationContext.jsonld`, `presexchange.jsonld`).
- `server.js` — HTTPS static server; maps `Host` + path to a file under `dids/`.
- `certs/` — dev CA + server certificate (self-signed) covering every alias.
- `gen-certs.sh` — regenerates `certs/`.

`docker-compose.yml` runs `server.js` in the `did-host` container and gives it
network aliases for every `did:web` hostname:

```
secureissuer.solidcommunity.net
bboi.solidcommunity.net
privateclinic.solidcommunity.net
publichospital.solidcommunity.net
raw.githubusercontent.com
```

Because those are aliases on the shared network, every other container resolves
them to `did-host`, so standard `did:web` resolution "just works" locally. The
Node services set `NODE_TLS_REJECT_UNAUTHORIZED=0` to trust the dev certificate.

## DIDs and secrets

| Agent | DID | Public key |
| --- | --- | --- |
| secure-issuer | `did:web:secureissuer.solidcommunity.net:public` | see `generated.json` |
| demo-user | `did:web:bboi.solidcommunity.net:public` | see `generated.json` |
| demo-app-1 (Private Clinic) | `did:web:privateclinic.solidcommunity.net:public` | see `generated.json` |
| demo-app-2 (Public Hospital) | `did:web:publichospital.solidcommunity.net:public` | see `generated.json` |
| demo-ttp | `did:web:raw.githubusercontent.com:biagioboi:DKGNonRepudiation:main:demo-ttp:config` | see `generated.json` |
| solid-css | `did:web:raw.githubusercontent.com:biagioboi:CommunitySolidServer:main` | `css-did.json` (from the CSS fork) |

The `solid-css` DID/seed are hardcoded in the CSS fork; `css-did.json` mirrors
its committed `did.json`.

## Regenerating

```bash
# 1. (optional) edit seeds.json
# 2. regenerate DID documents + generated.json, syncing demo-ttp/config/did.json
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/..":/repo -w /repo/did-hosting \
  node:22-bookworm node generate.js
# 3. regenerate the dev certificate
docker run --rm -v "$PWD":/h -w /h node:22-bookworm bash gen-certs.sh
```

If you change a seed you must also update the matching env values in
`docker-compose.yml` (wallet `seed_private_key`, and the fingerprint/public key
env vars for the issuer/TTP/apps), because some of that material is hardcoded in
the agent sources. `generated.json` has the values to copy.

## Warning

These keys/certificates are for a local development demo only. They are
committed on purpose so the demo is reproducible; never reuse them anywhere
real.
