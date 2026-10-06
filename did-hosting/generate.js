#!/usr/bin/env node
/**
 * Reproducible DID/secret generator for the DKG non-repudiation demo.
 *
 * Source of truth: did-hosting/seeds.json (committed). Running this script
 * regenerates every did:web DID document under did-hosting/dids/ and writes
 * did-hosting/generated.json with the derived key material that the
 * docker-compose.yml / agent sources consume.
 *
 * Each agent uses a did:web whose DID document is served over HTTPS by the
 * `did-host` container on the solid-demo-net network. The hostnames below are
 * network aliases of that container, so every other container resolves them.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const DIDS_DIR = path.join(ROOT, 'dids');
const seeds = JSON.parse(fs.readFileSync(path.join(ROOT, 'seeds.json'), 'utf8'));

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(buf) {
  let num = BigInt('0x' + buf.toString('hex'));
  let out = '';
  while (num > 0n) { const r = num % 58n; num = num / 58n; out = B58[Number(r)] + out; }
  for (const b of buf) { if (b === 0) out = '1' + out; else break; }
  return out;
}

function derive(seedString) {
  const seed = Buffer.from(seedString, 'utf8');
  if (seed.length !== 32) throw new Error(`seed must be 32 bytes, got ${seed.length}`);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const keyObj = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = crypto.createPublicKey(keyObj).export({ format: 'der', type: 'spki' });
  const rawPub = spki.subarray(spki.length - 32);
  return {
    publicKeyBase58: base58(rawPub),
    fingerprint: 'z' + base58(Buffer.concat([Buffer.from([0xed, 0x01]), rawPub])),
  };
}

// did:web -> URL path under the host
function didWebPath(did) {
  const parts = did.slice('did:web:'.length).split(':');
  const host = decodeURIComponent(parts[0]);
  const rest = parts.slice(1).map(decodeURIComponent);
  const dir = rest.length ? path.join(host, ...rest) : path.join(host, '.well-known');
  return { host, file: path.join(dir, 'did.json') };
}

const agents = {
  issuer: {
    did: 'did:web:secureissuer.solidcommunity.net:public',
    endpoint: 'http://secure-issuer:3011',
    seed: seeds.issuer.seed,
  },
  user: {
    did: 'did:web:bboi.solidcommunity.net:public',
    endpoint: 'http://demo-user:3006',
    seed: seeds.user.seed,
  },
  app1: {
    did: 'did:web:privateclinic.solidcommunity.net:public',
    endpoint: 'http://demo-app-1:3010',
    seed: seeds.app1.seed,
  },
  app2: {
    did: 'did:web:publichospital.solidcommunity.net:public',
    endpoint: 'http://demo-app-2:3010',
    seed: seeds.app2.seed,
  },
  ttp: {
    did: 'did:web:raw.githubusercontent.com:biagioboi:DKGNonRepudiation:main:demo-ttp:config',
    endpoint: 'http://demo-ttp:3070',
    seed: seeds.ttp.seed,
  },
};

function buildDidDocument(did, fingerprint, publicKeyBase58, endpoint) {
  const vmId = `${did}#${fingerprint}`;
  return {
    '@context': [
      'https://w3id.org/did/v1',
      'https://w3id.org/security/suites/ed25519-2018/v1',
    ],
    id: did,
    verificationMethod: [
      { id: vmId, type: 'Ed25519VerificationKey2018', controller: did, publicKeyBase58 },
    ],
    service: [
      {
        id: '#inline-0',
        serviceEndpoint: endpoint,
        type: 'did-communication',
        priority: 0,
        recipientKeys: [vmId],
        routingKeys: [],
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
}

const output = {};
for (const [name, agent] of Object.entries(agents)) {
  const { publicKeyBase58, fingerprint } = derive(agent.seed);
  const doc = buildDidDocument(agent.did, fingerprint, publicKeyBase58, agent.endpoint);
  const { host, file } = didWebPath(agent.did);
  const target = path.join(DIDS_DIR, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify(doc, null, 2) + '\n');
  output[name] = {
    did: agent.did,
    endpoint: agent.endpoint,
    fingerprint,
    publicKeyBase58,
    didKey: `did:key:${fingerprint}`,
    hostedAt: `https://${host}/${path.relative(host, file).split(path.sep).join('/')}`,
  };
}

// CSS keeps its own wallet seed/DID (hardcoded in the fork); host its committed doc.
const cssDid = 'did:web:raw.githubusercontent.com:biagioboi:CommunitySolidServer:main';
const cssDoc = JSON.parse(fs.readFileSync(path.join(ROOT, 'css-did.json'), 'utf8'));
{
  const { file } = didWebPath(cssDid);
  const target = path.join(DIDS_DIR, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, JSON.stringify(cssDoc, null, 2) + '\n');
  output.css = { did: cssDid, endpoint: cssDoc.service?.[0]?.serviceEndpoint };
}

// Contexts referenced by @context but not aliased elsewhere: serve them locally.
const contextCopies = [
  ['NonRepudiationContext.jsonld', 'privateclinic.solidcommunity.net/public/NonRepudiationContext.jsonld'],
  ['presexchange.jsonld', 'bboi.solidcommunity.net/public/schemas/2024/presexchange.jsonld'],
];
for (const [src, dest] of contextCopies) {
  const target = path.join(DIDS_DIR, dest);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'contexts', src), target);
}

fs.writeFileSync(path.join(ROOT, 'generated.json'), JSON.stringify(output, null, 2) + '\n');

// Keep the committed TTP DID document in sync with the generated key material.
const ttpDocSource = path.join(DIDS_DIR, didWebPath(agents.ttp.did).file);
fs.copyFileSync(ttpDocSource, path.join(ROOT, '..', 'demo-ttp', 'config', 'did.json'));

console.log(JSON.stringify(output, null, 2));
