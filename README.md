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

## JSON-LD contexts

The Credo fork signs/verifies everything as JSON-LD, which needs context documents. There are three tiers:

**1. Bundled in the agent (never fetched).** The fork ships 17 contexts in its `defaultDocumentLoader` (`DEFAULT_CONTEXTS`), including `https://www.w3.org/2018/credentials/v1`, the `w3id.org/security/*` suite contexts, the DID contexts, `presentation-exchange/submission/v1`, `schema.org` and `odrl.jsonld`. These work fully offline.

**2. Fetched over HTTP from did-host (functionally local).** These are the protocol's own contexts, served by `did-host` from `did-hosting/contexts/` (copied into `did-hosting/dids/...` by `generate.js`):

| Context URL | Hosted at (did-host) | Used by |
| --- | --- | --- |
| `bboi.solidcommunity.net/public/schemas/2024/presexchange.jsonld` | `bboi.solidcommunity.net/public/schemas/2024/` | `presentationExchange` VPRs |
| `bboi.solidcommunity.net/public/schemas/2024/wrappedvp.jsonld` | same | wrapped VP/VPR signing |
| `bboi.solidcommunity.net/public/schemas/2024/wrappedvpr.jsonld` | same | `W3cPresentationRequestWrapper` |
| `bboi.solidcommunity.net/public/schemas/2024/protocol.jsonld` | same | `DifPresentationExchangeService` (acp terms) |
| `privateclinic.solidcommunity.net/public/NonRepudiationContext.jsonld` | `privateclinic.solidcommunity.net/public/` | NRO/NRR credential signing |

Missing any of these blocks the flow with `jsonld.InvalidUrl` (see the did-host check under "Driving with chrome-devtools MCP").

**3. Fetched from the real internet (no local copy anywhere).** Only one:

- **`https://www.w3.org/2018/credentials/examples/v1`** — required by the `ExampleDegreeCredential` and used during VP verification. It is **not** bundled and **not** on did-host, so every verification fetches it from w3.org, and uncached, repeatedly (Tempo traces show it fetched 3x per check, e.g. 890/656/209 ms). A 401/VP round-trip therefore depends on public internet access.

To make the demo fully offline, mirror `credentials/examples/v1` on did-host (alias the hostname or override the loader) or add it to the Credo fork's `DEFAULT_CONTEXTS`. These fetches are visible in Tempo as client spans with `url.full` set, or with the `curl` loop under "Driving with chrome-devtools MCP" (also add `w3.org/2018/credentials/examples/v1` to check).

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

Wallet-form quirk: the MCP `fill`/`click` on the *"Paste Invitation URL"* form can silently no-op (both calls report success, but `#invitationUrl` ends up empty and no `POST /api/invitations` is sent). Submit it in one `evaluate_script` instead:

```js
() => { const i = document.querySelector('#invitationUrl');
  i.value = '<invitation URL>'; // embed with JSON.stringify(url), not via `args`
  i.dispatchEvent(new Event('input', { bubbles: true }));
  i.dispatchEvent(new Event('change', { bubbles: true }));
  i.closest('form').requestSubmit(); }
```

Gotchas:
- The app's *Log In with SSI* click triggers a wallet-extension popup attempt (`window.open('chrome-extension://…/popup.html?invitationUrl=…')`); skip the click and read `data-invitation-url` from the button instead. With `--isolated` the attempt is inert (no extension in the temp profile), but skipping keeps the page list clean.
- `evaluate_script` `args` are **element UIDs**, not free-form values — pass values by string-interpolating them into the `function` body (e.g. `` `i.value = ${JSON.stringify(url)}` ``).
- Headings like *"Credential Offer"* / *"Proof Request"* are always present in the snapshot; wait for state counters such as `"1 pending"` or activity text (`"Credential received and stored"`, `"Share Credential"`) instead.

### 1. Issue the credential (README step 1)

1. page 1 -> `http://localhost:8083`; read the invitation URL from the page:

   ```js
   () => document.body.innerText.match(/https?:\/\/secure-issuer:3011\?oob=[A-Za-z0-9_\-]+/)[0]
   ```

2. page 2 -> `http://localhost:3007`; submit the invitation via the `evaluate_script` wallet-form snippet under *Tabs*, then `wait_for(["1 pending"])`.
3. Click `button[data-action="accept-credential"]` and `wait_for(["Credential received and stored"])`.

### 2. Private Clinic - non-repudiable read (sequence 2, 3b, 4, 5a/5b)

1. page 1 -> `http://localhost:8081`. Click the `Request Access` button. This issues the `GET` that returns `401` and parses the CSS proof request; `wait_for(["Wallet invitation ready"])`.
2. Read its invitation **without clicking `Log In with SSI`** (the click only triggers the wallet-extension popup attempt — the URL is already on the button):

   ```js
   () => [...document.querySelectorAll('button')]
     .find(b => b.textContent.trim() === 'Log In with SSI').dataset.invitationUrl
   ```

3. Paste that into the wallet with the same `evaluate_script` submit as step 1, then `wait_for(["1 pending"])`, `wait_for(["Share Credential"])` and click `button[data-action="accept-proof"]`.
4. Back on page 1 the resource arrives encrypted with the `NonRepudiableOrigin` NRO. Choose a release path:
   - **`Release via Solid server`** (5a): the app sends the signed receipt (NRR) to the CSS, which stores it at `/.internal/jws-audit/query` and returns the key.
   - **`Release via TTP`** (5b): the app sends the receipt to `demo-ttp/checkResource`, which verifies it and releases the key; the CSS audit does **not** grow.
5. `wait_for(["Protected resource unlocked"])` (the heading shown once the release completes; the old `"ACCESS GRANTED"` text is gone from recent UI). The decrypted body is the first `<pre>` on the page.

### 3. Public Hospital - plain read (sequence 3a)

1. page 1 -> `http://localhost:8082`; repeat steps 1-3 above with the same wallet. Here the CSS grants plain `acl:Read`, so after the wallet shares the proof the `200` response is served directly: `wait_for(["Protected resource unlocked"])` and no NRO graph is saved.

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
- Each party mounts that volume at `/otel`, mounts `otel/register.js` at `/otel/register.js`, and starts with `NODE_OPTIONS=--require /otel/register.js`, so the SDK loads at startup.
- The volume is read-write, not read-only. `register.js` is a nested bind mount inside the volume, and runc cannot create that mountpoint on a read-only filesystem.
- The `x-otel` anchor in docker-compose.yml holds the shared settings. `OTEL_EXPORTER_OTLP_ENDPOINT` points at `http://tempo:4318`.

Reporting services: secure-issuer, demo-user, demo-ttp, demo-app-1, demo-app-2, solid-css. did-host is not instrumented.

`otel/register.js` mirrors `@opentelemetry/auto-instrumentations-node/register` and adds four layers on top:

1. HTTP headers, under `http.request.header.*` and `http.response.header.*`. Request headers: `agent`, `client`, `issuer`, `didvc`, `vp`, `signedresource`, `x-forwarded-host`, `x-forwarded-proto`. Response headers: `www-authenticate`, `encryptedresource`, `keyfordecrypt`. In `@opentelemetry/instrumentation-http` 0.223 the option nests under `server` and `client`; the flat `{ requestHeaders, responseHeaders }` shape of older versions is ignored.
2. HTTP bodies, under `http.request.body` and `http.response.body`. The register buffers both on the server and attaches them to the span that is active when the response ends, which is usually the Express `request handler - <route>` span.
3. DIDComm, by patching `EnvelopeService.packMessage` and `unpackMessage` on load. The spans are `didcomm.pack` and `didcomm.unpack`, with `didcomm.payload`, `didcomm.type`, `didcomm.direction`, `didcomm.recipients` and `didcomm.encrypted`. The extractor serializes the `AgentMessage`/`PlaintextMessage`, so `didcomm.type` is the `@type` of the actual message.
4. Internal operations, by patching modules on load through `Module._load`. The spans are `vc.wrapPresentation`, `vc.wrapPresentationRequest`, `vc.signWrappedPresentation`, `vc.signWrappedPresentationRequest`, `vc.verifyWrappedPresentation`, `vc.verifyPresentation`, `vc.createPresentation`, `vc.verifyCredential` and `vc.issue` (W3c credential services and `@digitalcredentials/vc`), plus `css.VpChecker.verifyNew`, `css.attachNonRepudiationMaterial`, `css.generateHashCredentials`, `css.verifySignedResource` and `css.storeVerifiedJws` (CSS internals). `vc.createPresentation` and `vc.createPresentationRequest` are declared in the register but the demo sequence does not produce them (not observed in `issue-credential` / `present-proof` runs). Their payloads sit under `vera.*` (observed keys: `credential`, `credentials`, `holderDid`, `messageHash`, `nro`, `nrr`, `presentation`, `record`, `requesterDid`, `signed`, `signedCredential`, `verified`, `vp`, `vpr`, `wrapper`).

Three things to keep in mind:

- Payloads are large. `vp`, `signedresource`, `encryptedresource` and `didcomm.payload` are base64 or JSON and often run to several KB. `VERA_PAYLOAD_MAX_LENGTH` (default 16384) truncates every header, body and payload. Lower it if Tempo storage or MCP output grows too much.
- DIDComm and internal spans appear only when those operations run. A plain `curl` does not open a wallet connection, so `didcomm.*`, `vc.*` and `css.*` stay absent until the demo flow runs.
- Two ordering constraints matter if you edit the register. `http` and `https` must be required after `sdk.start()`, otherwise the http instrumentation cannot patch them and there are no server spans or bodies. Credo must be patched on load, not required eagerly, because it needs a reflect-metadata polyfill that the application loads.

What the spans look like in practice (observed from live runs):

- Every party also emits non-HTTP child spans such as `dns.lookup`, `tcp.connect` and `tls.connect` (the latter with TLS certificate attributes), and the Express apps add `middleware - *` and `request handler - <route>` internal spans.
- Server spans expose the URL via `url.path` (e.g. demo-user `/api/state`, solid-css `/my-pod/test-folder/dual-mode-resource.txt`) and Express routes via `http.route`; `url.full` is populated only on client (outbound) spans, so filter server spans by `url.path`/`http.route`.
- Resource attributes are set to `service.namespace=vera` and `deployment.environment=dkg-demo` (from `otel/register.js`).
- The CSS to TTP reserve-channel handshake appears as `POST http://demo-ttp:3070/` client spans that can end with status 500 or a timeout on the TTP agent endpoint. Treat their presence as normal during the first NRRead.

The Tempo MCP server is enabled in `tempo/tempo.yaml` and listens at `http://localhost:3200/api/mcp`. It is registered as `tempo` in `~/.pi/agent/mcp.json`, so an agent session can query traces with TraceQL. Run `/reload` after changing the server list. When using the MCP's `get_attribute_values`, dotted attribute names need the `span.` prefix (e.g. `span.http.request.header.agent`); the bare `http.request.header.agent` form is rejected. Payload-heavy attrs (`http.request.body`, `http.response.body`, `didcomm.payload`) already make `traceql_search` return ~80 KB responses, so scope queries (limit + window) when probing them.

Query without an agent:

```bash
curl -s 'http://localhost:3200/api/search?q=%7B%7D&limit=20'
```

If the `otel-node` volume is missing, `docker compose up -d otel-node-modules` reinstalls it. To instrument a new service, add `<<: *otel`, `OTEL_SERVICE_NAME`, the `otel-node:/otel` mount, the `./otel/register.js:/otel/register.js` mount, and a dependency on `otel-node-modules` with `condition: service_completed_successfully`.

## Notice

The .tgz files in lib were built from the source in the same folder.

## TODO

Create a DID document to upload during the build phase, so a pod can host it.
