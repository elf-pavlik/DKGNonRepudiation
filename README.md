# Interoperable non-repudiation protocol powered by DKGs

Research project by Biagio Boi and Ross Horne, carried out at the University of Strathclyde. It implements VERA, a non-repudiable read extension for Solid. VERA.pdf describes the protocol.

The repo has one folder per agent: demo-app, demo-issuer, demo-ttp, demo-user. The lib folder holds the pinned libraries.

## Run

```bash
docker network create solid-demo-net
git clone https://github.com/biagioboi/CommunitySolidServer ../biagioboi-CommunitySolidServer
docker compose up -d --build
```

docker-compose.yml builds the modified Community Solid Server from the sibling checkout and starts the whole network. It holds generated dev secrets and is committed so the demo reproduces. docker-compose-template.yml is the original template.

## Services

| Container | Host URL | Purpose |
| --- | --- | --- |
| did-host | internal only | serves the did:web documents over HTTPS |
| solid-css | http://localhost:3002 | modified Community Solid Server, pod and resource owner |
| secure-issuer | http://localhost:8083 | issues the base identity credential |
| demo-user | http://localhost:3007 | patient wallet |
| demo-ttp | http://localhost:8084 | trusted third party |
| demo-app-1 | http://localhost:8081 | Private Clinic, non-repudiable read |
| demo-app-2 | http://localhost:8082 | Public Hospital, plain read and write |
| tempo | http://localhost:3200 | trace store and MCP server |

## DIDs

The DIDs match the paper. did-hosting/generated.json holds the keys derived from the seeds.

| Agent | DID |
| --- | --- |
| secure-issuer | did:web:secureissuer.solidcommunity.net:public |
| demo-user | did:web:bboi.solidcommunity.net:public |
| demo-app-1 | did:web:privateclinic.solidcommunity.net:public |
| demo-app-2 | did:web:publichospital.solidcommunity.net:public |
| demo-ttp | did:web:raw.githubusercontent.com:biagioboi:DKGNonRepudiation:main:demo-ttp:config |
| solid-css | did:web:raw.githubusercontent.com:biagioboi:CommunitySolidServer:main |

did-host runs an HTTPS server and holds network aliases for each DID hostname. The other containers resolve those hostnames to did-host and set NODE_TLS_REJECT_UNAUTHORIZED=0 to accept the dev certificate. did-hosting/README.md explains how to regenerate the seeds, documents and certificate.

## Demo flow

1. Issue a credential. Open http://localhost:8083, copy the invitation URL and paste it into the wallet at http://localhost:3007, then accept the credential offer.
2. Connect an app to the wallet. Open http://localhost:8081 or http://localhost:8082, click "Log In with SSI" and paste the app invitation into the wallet.
3. Request a resource. The field defaults to http://localhost:3002/my-pod/test-folder/dual-mode-resource.txt. Click "Request Access".
4. Approve the proof request in the wallet.
5. Read the result. demo-app-1 receives an encrypted resource, signs a receipt and gets the key back. It then offers two release paths (the two branches of `sequence.mmd`): **Release via Solid server** sends the receipt to the CSS (5a) and **Release via TTP** sends it to the TTP escrow (5b). demo-app-2 receives the plaintext directly.

The app's "NRO Graph Audit" panel reads /.internal/nro-audit/query. The CSS keeps its own audit records at http://localhost:3002/.internal/jws-audit/query.

The resource /my-pod/test-folder/dual-mode-resource.txt grants non-repudiable read to privateclinic and read plus write to publichospital. nr-resource.txt grants non-repudiable read to privateclinic. The other test-folder resources grant plain read to publichospital.

## Driving with chrome-devtools MCP

The chrome-devtools MCP server is configured in ~/.pi/agent/mcp.json and connects to a local Chrome. `take_snapshot` returns the page as text, so an agent can read and drive the UI without images. The steps below replay `sequence.mmd` end to end; they were verified against a `docker compose up -d --build` from a clean state.

### Prerequisites

- **Chrome for the MCP server.** On Linux `chrome-devtools-mcp` only looks for `/opt/google/chrome/chrome`. On NixOS the easiest fix is a symlink to Nix's Chromium, or pass it explicitly in `~/.pi/agent/mcp.json`:

  ```json
  {
    "mcpServers": {
      "chrome-devtools": {
        "command": "npx",
        "args": ["-y", "chrome-devtools-mcp@latest",
                 "--executablePath", "/etc/profiles/per-user/$USER/bin/chromium",
                 "--isolated"]
      }
    }
  }
  ```

  Run `/reload` after changing `mcp.json`. `--isolated` gives each session its own temporary profile so parallel sessions do not fight over the Chrome user-data dir.
- **JSON-LD contexts on did-host.** The wrapped-VPR/VP signing dereferences `https://bboi.solidcommunity.net/public/schemas/2024/{presexchange,wrappedvp,wrappedvpr,protocol}.jsonld`. If any of these is missing from `did-hosting/dids/...` the wallet never receives the proof request and the app logs `jsonld.InvalidUrl: Dereferencing a URL did not result in a valid JSON-LD object`. `did-hosting/generate.js` copies them from `did-hosting/contexts/`; check with:

  ```bash
  docker exec demo-app-1 sh -c 'for u in presexchange wrappedvp wrappedvpr protocol; do \
    curl -sk -o /dev/null -w "$u %{http_code}\n" \
    "https://bboi.solidcommunity.net/public/schemas/2024/$u.jsonld"; done'
  ```

### Tabs

Use two pages: **page 1** for the issuer/apps and **page 2** for the wallet (`http://localhost:3007`). Snapshot element `uid`s change on every re-render, so select elements by text or `data-*` attribute in `evaluate_script` instead of by uid. One quirk: the wallet buttons (and sometimes the app buttons) refuse the MCP `click` with *"element did not become interactive"*; dispatch the click from `evaluate_script` instead. `wait_for` accepts a list of texts and resolves when any appears.

### 1. Issue the credential (README step 1)

1. page 1 -> `http://localhost:8083`; read the invitation URL from the page:

   ```js
   () => document.body.innerText.match(/https?:\/\/secure-issuer:3011\?oob=[A-Za-z0-9_\-]+/)[0]
   ```

2. page 2 -> `http://localhost:3007`; fill `#invitationUrl` with that URL and click the `Connect` button, then `wait_for(["1 pending"])`.
3. Click `button[data-action="accept-credential"]` and `wait_for(["Credential received and stored"])`.

### 2. Private Clinic - non-repudiable read (sequence 2, 3b, 4, 5a/5b)

1. page 1 -> `http://localhost:8081`. Click the `Request Access` button. This issues the `GET` that returns `401` and parses the CSS proof request; `wait_for(["Wallet invitation ready"])`.
2. Click `Log In with SSI` and read its invitation:

   ```js
   () => [...document.querySelectorAll('button')]
     .find(b => b.textContent.trim() === 'Log In with SSI').dataset.invitationUrl
   ```

3. Paste that into the wallet (`#invitationUrl` + `Connect`), then `wait_for(["Share Credential"])` and click `button[data-action="accept-proof"]`.
4. Back on page 1 the resource arrives encrypted with the `NonRepudiableOrigin` NRO. Choose a release path:
   - **`Release via Solid server`** (5a): the app sends the signed receipt (NRR) to the CSS, which stores it at `/.internal/jws-audit/query` and returns the key.
   - **`Release via TTP`** (5b): the app sends the receipt to `demo-ttp/checkResource`, which verifies it and releases the key; the CSS audit does **not** grow.
5. `wait_for(["ACCESS GRANTED"])`. The decrypted body is the first `<pre>` on the page.

### 3. Public Hospital - plain read (sequence 3a)

1. page 1 -> `http://localhost:8082`; repeat steps 1-3 above with the same wallet. Here the CSS grants plain `acl:Read`, so after the wallet shares the proof the `200` response is served directly: `wait_for(["ACCESS GRANTED"])` and no NRO graph is saved.

### Verify the evidence

The app-side non-repudiation evidence (one `NonRepudiableOrigin` per NRRead):

```bash
curl -s 'http://localhost:8081/.internal/nro-audit/query?resource=http%3A%2F%2Flocalhost%3A3002%2Fmy-pod%2Ftest-folder%2Fdual-mode-resource.txt'
```

The CSS-side receipt (`NonRepudiationDestination`) is only present when 5a was used:

```bash
curl -s http://localhost:3002/.internal/jws-audit/query
```

In the NRRead exchange the `signedHash` in the CSS `NonRepudiableOrigin` NRO and in the app's `NonRepudiationDestination` NRR must match.

## Observability

Every demo party exports OpenTelemetry traces to Tempo. The compose file turns this on without application code changes.

- `tempo` stores the traces. The OTLP receivers are on 4317 (gRPC) and 4318 (HTTP). The query API and the MCP server are on 3200.
- `otel-node-modules` installs `@opentelemetry/auto-instrumentations-node` into the `otel-node` volume once, then exits.
- Each party mounts that volume at `/otel` and starts with `NODE_OPTIONS=--require /otel/register.js`, so the SDK loads at startup.
- The `x-otel` anchor in docker-compose.yml holds the shared settings. `OTEL_EXPORTER_OTLP_ENDPOINT` points at `http://tempo:4318`.

Reporting services: secure-issuer, demo-user, demo-ttp, demo-app-1, demo-app-2, solid-css. did-host is not instrumented.

The Tempo MCP server is enabled in `tempo/tempo.yaml` and listens at `http://localhost:3200/api/mcp`. It is registered as `tempo` in `~/.pi/agent/mcp.json`, so an agent session can query traces with TraceQL. Run `/reload` after changing the server list.

Query without an agent:

```bash
curl -s 'http://localhost:3200/api/search?q=%7B%7D&limit=20'
```

If the `otel-node` volume is missing, `docker compose up -d otel-node-modules` reinstalls it. To instrument a new service, add `<<: *otel`, `OTEL_SERVICE_NAME`, the `otel-node:/otel:ro` mount, and a dependency on `otel-node-modules` with `condition: service_completed_successfully`.

## Notice

The .tgz files in lib were built from the source in the same folder.

## TODO

Create a DID document to upload during the build phase, so a pod can host it.
