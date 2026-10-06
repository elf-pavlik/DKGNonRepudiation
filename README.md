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
5. Read the result. demo-app-1 receives an encrypted resource, signs a receipt and gets the key back. demo-app-2 receives the plaintext directly.

The app's "NRO Graph Audit" panel reads /.internal/nro-audit/query. The CSS keeps its own audit records at http://localhost:3002/.internal/jws-audit/query.

The resource /my-pod/test-folder/dual-mode-resource.txt grants non-repudiable read to privateclinic and read plus write to publichospital. nr-resource.txt grants non-repudiable read to privateclinic. The other test-folder resources grant plain read to publichospital.

## Driving with chrome-devtools MCP

The chrome-devtools MCP server is configured in ~/.pi/agent/mcp.json and connects to a local Chrome. take_snapshot returns the page as text, so an agent can read and drive the UI without images. Start from the service URLs above and use the flow in the previous section.

## Notice

The .tgz files in lib were built from the source in the same folder.

## TODO

Create a DID document to upload during the build phase, so a pod can host it.
