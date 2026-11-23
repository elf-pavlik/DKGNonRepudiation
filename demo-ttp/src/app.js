const {
    ConnectionsModule,
    DidsModule,
    V2ProofProtocol,
    V2CredentialProtocol,
    ProofsModule,
    AutoAcceptProof,
    AutoAcceptCredential,
    CredentialsModule,
    WsOutboundTransport,
    Agent,
    HttpOutboundTransport,
    KeyType, ConnectionEventTypes, DidExchangeState, TypedArrayEncoder, ProofEventTypes, ProofState, DidDocument,
    DifPresentationExchangeProofFormatService, JsonLdCredentialFormatService, JwaSignatureAlgorithm, DidDocumentBuilder,
    getEd25519VerificationKey2018, W3cCredentialsModule, CredentialEventTypes, SignatureSuiteRegistry,
    getEd25519VerificationKey2020, W3cJsonLdVerifiableCredential, CredentialState, W3cJsonLdVerifiablePresentation,
    JsonTransformer, W3cCredentialService, WebDidResolver, DidDocumentService, ConnectionService, DidCommV1Service,
    ConsoleLogger, LogLevel, RoutingService, HandshakeProtocol, MediationRecipientService, MediatorPickupStrategy,
    MediationRecipientModule, MediatorService, MediatorModule, OutOfBandEventTypes, PeerDidNumAlgo, ClaimFormat,
    CREDENTIALS_CONTEXT_V1_URL, WRAPPER_VP_CONTEXT_URL, W3cPresentationRequest, AgentMessage, Key, BasicMessage,
    DidKey, WalletKeyExistsError, getKeyFromVerificationMethod
} = require('@credo-ts/core')
const {
    AnonCredsCredentialFormatService,
    AnonCredsModule,
    AnonCredsProofFormatService,
    LegacyIndyCredentialFormatService,
    LegacyIndyProofFormatService,
    V1CredentialProtocol,
    V1ProofProtocol, DataIntegrityCredentialFormatService,
} = require('@credo-ts/anoncreds')
const QRCode = require('qrcode')
const {agentDependencies, HttpInboundTransport} = require('@credo-ts/node')
const {IndyVdrIndyDidResolver, IndyVdrAnonCredsRegistry, IndyVdrModule} = require('@credo-ts/indy-vdr')
const {indyVdr} = require('@hyperledger/indy-vdr-nodejs')
const {ariesAskar} = require('@hyperledger/aries-askar-nodejs')
const {AskarModule} = require('@credo-ts/askar')
const {anoncreds} = require('@hyperledger/anoncreds-nodejs')
const {AnonCredsRsModule} = require('@credo-ts/anoncreds')
const sys_config = require('config');
var bodyParser = require('body-parser');
const express = require('express');
const fs = require('fs');
const path = require('path');
const {randomUUID} = require("crypto");
const {defaultDocumentLoader} = require('@credo-ts/core/build/modules/vc/data-integrity/libraries/documentLoader');
const {NrrGraphService} = require('./audit/NrrGraphService');
const {
    TAG_KEX_CSS,
    TAG_KEX_TTP,
    TAG_TTP_RECEIPT,
    toBase64Url,
    fromBase64Url,
    seal,
    hashKey,
    computeCommitment,
    splitKid,
    unwrapKey,
    generateEphemeralKeyPair,
    keyExchangePayload,
    deriveTtpKey,
} = require('./vera-crypto');

const NON_REPUDIATION_CONTEXT_URL = 'https://privateclinic.solidcommunity.net/public/NonRepudiationContext.jsonld';
const NON_REPUDIATION_CONTEXT_PATH = [
    path.join(__dirname, '..', 'NonRepudiationContext.jsonld'),
    path.join(__dirname, '..', '..', 'NonRepudiationContext.jsonld'),
].find((candidatePath) => fs.existsSync(candidatePath));

if (!NON_REPUDIATION_CONTEXT_PATH) {
    throw new Error('NonRepudiationContext.jsonld not found for demo-ttp.');
}

const NON_REPUDIATION_CONTEXT = JSON.parse(
    fs.readFileSync(NON_REPUDIATION_CONTEXT_PATH, 'utf8')
);
const nrrGraphService = new NrrGraphService({
    rootFilePath: path.join(__dirname, '..'),
});
// K_ttp shared with each CSS, keyed by key id. Persisted so that wrapped keys Y issued before a
// restart can still be opened.
const TTP_KEYS_PATH = path.join(__dirname, '..', '.internal', 'kttp', 'keys.json');
// The TTP reaches the CSS via the docker network, not via the browser-facing origin in URI.
const CSS_INTERNAL_BASE = process.env.CSS_INTERNAL_BASE || 'http://solid-css:3002';

const prompt = require('prompt-sync')();
const TTP_DID = process.env.TTP_DID || 'did:web:raw.githubusercontent.com:biagioboi:DKGNonRepudiation:main:demo-ttp:config';
const APP_DID = process.env.APP_DID || 'did:web:privateclinic.solidcommunity.net:public';
const APP_DID_KEY = process.env.APP_DID_KEY || 'did:key:z6Mkg4kRxcfvWfqTV86RdBKHjTks5thJe7R4xsGTs5zASrB7';
const APP_VERIFICATION_METHOD_ID = `${APP_DID}#${APP_DID_KEY.slice('did:key:'.length)}`;

const getGenesisTransaction = async (url) => {
    const response = await fetch(url)
    return await response.text()
}

let agent;
let startPromise;

function buildAppDidDocument() {
    return {
        '@context': [
            'https://www.w3.org/ns/did/v1',
            'https://w3id.org/security/suites/ed25519-2018/v1',
        ],
        id: APP_DID,
        verificationMethod: [
            {
                id: APP_VERIFICATION_METHOD_ID,
                type: 'Ed25519VerificationKey2018',
                controller: APP_DID,
                publicKeyBase58: DidKey.fromDid(APP_DID_KEY).key.publicKeyBase58,
            },
        ],
        authentication: [APP_VERIFICATION_METHOD_ID],
        assertionMethod: [APP_VERIFICATION_METHOD_ID],
    }
}

async function buildTtpDidDocument(agent, did) {
    let ed25519Key

    try {
        ed25519Key = await agent.wallet.createKey({
            keyType: KeyType.Ed25519,
            privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
        })
    } catch (error) {
        if (!(error instanceof WalletKeyExistsError)) {
            throw error
        }

        const [existingDid] = await agent.dids.getCreatedDids({method: 'web', did})
        const existingVerificationMethod = existingDid?.didDocument?.verificationMethod?.find(
            (verificationMethod) => verificationMethod.type === 'Ed25519VerificationKey2018' && verificationMethod.publicKeyBase58
        )

        if (!existingVerificationMethod?.publicKeyBase58) {
            throw error
        }

        ed25519Key = Key.fromPublicKeyBase58(existingVerificationMethod.publicKeyBase58, KeyType.Ed25519)
    }

    const verificationMethod = getEd25519VerificationKey2018({
        key: ed25519Key,
        id: `${did}#${ed25519Key.fingerprint}`,
        controller: did,
    })

    const didDocument = new DidDocumentBuilder(did)
        .addService(new DidCommV1Service({
            id: '#inline-0',
            serviceEndpoint: sys_config.get('wallet.endpoint'),
            type: 'did-communication',
            recipientKeys: [verificationMethod.id],
            routingKeys: [],
        }))
        .addVerificationMethod(verificationMethod)
        .addAuthentication(verificationMethod.id)
        .addAssertionMethod(verificationMethod.id)
        .build()

    return {
        didDocument,
        verificationMethodId: verificationMethod.id,
    }
}

const initializeIssuerAgent = async (ledgerUrl, endPoint) => {

    const genesisTransactionsBCovrinTestNet = await getGenesisTransaction(ledgerUrl)

    const config = {
        label: sys_config.get('wallet.id'),
        walletConfig: {
            id: sys_config.get('wallet.id'),
            key: sys_config.get('wallet.key'),
        },
        endpoints: [endPoint],
        autoUpdateStorageOnStartup: true,
        logger: new ConsoleLogger(LogLevel.debug)
    }

    // A new instance of an agent is created here
    agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet),
    })

    // Register a simple `WebSocket` outbound transport - not needed
    //agent.registerOutboundTransport(new WsOutboundTransport())

    // Register a simple `Http` outbound transport
    agent.registerOutboundTransport(new HttpOutboundTransport())

    // Register a simple `Http` inbound transport
    agent.registerInboundTransport(new HttpInboundTransport({port: 3070}))

    // Initialize the agent
    await agent.initialize()


    const { didDocument } = await buildTtpDidDocument(agent, TTP_DID)

    console.log(JSON.stringify(didDocument))

    await agent.dids.import({
        did: TTP_DID,
        didDocument,
        overwrite: true,
    })

    const [createdDid] = await agent.dids.getCreatedDids({method: 'web', did: TTP_DID});
    if (createdDid?.did) {
        console.log("This is the TTP Wallet, it has this DID: " + createdDid.did);
    }


    return agent
}

async function startEverything() {
    agent = await initializeIssuerAgent(sys_config.get('wallet.ledger_url'), sys_config.get('wallet.endpoint'));
}

function ensureStarted() {
    if (!startPromise) {
        startPromise = startEverything();
    }

    return startPromise;
}

const app = express();
const PORT = 8082;
ensureStarted().then(result => {
    /* Empty */
}).catch((error) => {
    console.error('Failed to initialize demo-ttp agent', error);
})
const cors = require('cors');

app.use(cors());
app.use(express.static('public'))

app.use(express.json());
app.use(bodyParser.urlencoded({extended: false}));
app.get('/', (req, res) => {
    res.status(200);
    res.send("TTP Running.")
});

// Setup phase (m10/m11 in the ProVerif model): authenticated ephemeral Diffie-Hellman with a CSS,
// each half signed with the party's did:web key, yielding the long-term K_ttp shared with that CSS.
app.post('/keyExchange', async (req, res) => {
    try {
        await ensureStarted();
        const {did, publicKey, signature} = req.body ?? {};
        if (typeof did !== 'string' || typeof publicKey !== 'string' || typeof signature !== 'string') {
            res.status(400).json({error: 'Expected did, publicKey and signature.'});
            return;
        }

        const signedByCss = await verifyDidSignature(did, keyExchangePayload(TAG_KEX_CSS, did, publicKey), fromBase64Url(signature));
        if (!signedByCss) {
            throw new Error(`The key exchange request is not signed by ${did}.`);
        }

        const ephemeral = generateEphemeralKeyPair();
        const ttpSignature = await signWithDidKey(keyExchangePayload(TAG_KEX_TTP, TTP_DID, ephemeral.publicKey, publicKey));
        const {kid, key} = deriveTtpKey(ephemeral.privateKey, publicKey, publicKey, ephemeral.publicKey);
        await saveTtpKey({kid, key, cssDid: did});
        console.log(`K_ttp ${kid} established with ${did}`);

        res.status(200).json({did: TTP_DID, publicKey: ephemeral.publicKey, signature: toBase64Url(ttpSignature), kid});
    } catch (error) {
        console.error('TTP key exchange error', error);
        res.status(400).json({error: error.message ?? 'Unable to complete the key exchange.'});
    }
});

// TTP Resolution (paper Section 3.3, m15/m16): the app submits DID_U, URI, n_c, H(E), Y, h, h_K, the NRO
// and the NRR - but not E, which never leaves the app. The TTP opens Y with K_ttp, checks it against the
// submission, recomputes C, verifies both signatures on C, then releases K_R and forwards the NRR to the CSS.
app.post('/checkResource', async (req, res) => {
    try {
        await ensureStarted();
        const {didU, uri, nc, hE, Y, h, hK, nro, nrr} = req.body ?? {};
        for (const [name, value] of Object.entries({didU, uri, nc, hE, Y, h, hK})) {
            if (typeof value !== 'string') {
                throw new Error(`Missing ${name} in the request body.`);
            }
        }

        const {kid} = splitKid(Y);
        const ttpKey = await loadTtpKey(kid);
        if (!ttpKey) {
            throw new Error(`Unknown K_ttp key id ${kid}.`);
        }

        // The requesting app is the one that signed the NRR (and, once the channel uses mutual TLS,
        // the one presenting the client certificate).
        const appSignature = await verifyCommitmentCredential(nrr);
        const wrapped = unwrapKey(ttpKey.key, Y);
        if (wrapped.didA !== appSignature.issuer || wrapped.nc !== nc || wrapped.hE !== hE) {
            throw new Error('Y is not bound to the requesting app, the submitted nonce and the submitted H(E).');
        }
        if (hashKey(wrapped.kR) !== hK) {
            throw new Error('The key wrapped in Y does not match h_K.');
        }

        const commitment = computeCommitment({didV: ttpKey.cssDid, didA: wrapped.didA, didU, uri, nc, hE, Y, h, hK});
        const cssSignature = await verifyCommitmentCredential(nro);
        if (cssSignature.issuer !== ttpKey.cssDid || cssSignature.commitment !== commitment) {
            throw new Error('The NRO is not a signature of the CSS on C.');
        }
        if (appSignature.commitment !== commitment) {
            throw new Error('The NRR is not a signature of the app on C.');
        }

        const nrrRecord = await nrrGraphService.storeReceivedNrr({
            messageHash: commitment,
            receivedAt: new Date().toISOString(),
            signedResource: nrr,
        });

        // Releasing K_R never waits for the CSS: it may be offline, or a party to the dispute.
        forwardNrrToCss(ttpKey, nrr, uri).catch((error) => {
            console.error(`Could not forward the NRR for commitment ${commitment} to the CSS`, error);
        });

        res.status(200).json({
            keyForDecrypt: toBase64Url(wrapped.kR),
            commitment,
            nrrRecordId: nrrRecord.id,
        });
    } catch (error) {
        console.error('TTP resolution error', error);
        res.status(400).json({
            error: error.message ?? 'Unable to resolve the non-repudiable release.',
        });
    }
});

app.listen(PORT, (error) => {
        if (!error)
            console.log("Server is Successfully Running, and App is listening on port " + PORT)
        else
            console.log("Error occurred, server can't start", error);
    }
);


function getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet) {
    const legacyIndyCredentialFormatService = new LegacyIndyCredentialFormatService()
    const legacyIndyProofFormatService = new LegacyIndyProofFormatService()
    const customDocumentLoader = (agentContext) => {
        const fallbackLoader = defaultDocumentLoader(agentContext)
        const appDidDocument = buildAppDidDocument()
        const appVerificationMethod = appDidDocument.verificationMethod[0]

        return async (url) => {
            if (url === NON_REPUDIATION_CONTEXT_URL) {
                return {
                    contextUrl: null,
                    documentUrl: url,
                    document: NON_REPUDIATION_CONTEXT,
                }
            }

            if (url === APP_DID) {
                return {
                    contextUrl: null,
                    documentUrl: url,
                    document: appDidDocument,
                }
            }

            if (url === APP_VERIFICATION_METHOD_ID) {
                return {
                    contextUrl: null,
                    documentUrl: url,
                    document: {
                        '@context': 'https://w3id.org/security/suites/ed25519-2018/v1',
                        ...appVerificationMethod,
                    },
                }
            }

            return fallbackLoader(url)
        }
    }
    /* Il problema della */
    return {
        connections: new ConnectionsModule({
            autoAcceptConnections: true,
            peerNumAlgoForDidRotation: PeerDidNumAlgo.GenesisDoc,
            peerNumAlgoForDidExchangeRequests: PeerDidNumAlgo.GenesisDoc
        }),
        credentials: new CredentialsModule({
            autoAcceptCredentials: AutoAcceptCredential.Never,
            credentialProtocols: [
                new V1CredentialProtocol({
                    indyCredentialFormat: legacyIndyCredentialFormatService,
                }),
                new V2CredentialProtocol({
                    credentialFormats: [legacyIndyCredentialFormatService, new AnonCredsCredentialFormatService(), new DataIntegrityCredentialFormatService(), new JsonLdCredentialFormatService()],
                }),
            ],
        }),
        proofs: new ProofsModule({
            autoAcceptProofs: AutoAcceptProof.ContentApproved,
            proofProtocols: [
                new V1ProofProtocol({
                    indyProofFormat: legacyIndyProofFormatService,
                }),
                new V2ProofProtocol({
                    proofFormats: [legacyIndyProofFormatService, new AnonCredsProofFormatService(), new DifPresentationExchangeProofFormatService()],
                }),
            ],
        }),
        anoncreds: new AnonCredsModule({
            registries: [new IndyVdrAnonCredsRegistry()],
        }),
        indyVdr: new IndyVdrModule({
            indyVdr,
            networks: [{
                // Need unique network id as we will have multiple agent processes in the agent
                id: randomUUID(),
                genesisTransactions: genesisTransactionsBCovrinTestNet,
                indyNamespace: 'bcovrin:test',
                isProduction: false,
                connectOnStartup: true,
            }],
        }),
        dids: new DidsModule({
            resolvers: [new IndyVdrIndyDidResolver(), new WebDidResolver()],
        }),
        askar: new AskarModule({
            ariesAskar,
        }),
        w3cCredentials: new W3cCredentialsModule({
            documentLoader: customDocumentLoader,
        }),
    }
}

async function readTtpKeys() {
    try {
        return JSON.parse(await fs.promises.readFile(TTP_KEYS_PATH, 'utf8'));
    } catch (error) {
        if (error.code === 'ENOENT') {
            return {};
        }
        throw error;
    }
}

async function saveTtpKey({kid, key, cssDid}) {
    const keys = await readTtpKeys();
    keys[kid] = {key: toBase64Url(key), cssDid, createdAt: new Date().toISOString()};
    await fs.promises.mkdir(path.dirname(TTP_KEYS_PATH), {recursive: true});
    await fs.promises.writeFile(TTP_KEYS_PATH, JSON.stringify(keys, null, 2), {encoding: 'utf8', mode: 0o600});
}

async function loadTtpKey(kid) {
    const entry = (await readTtpKeys())[kid];
    return entry ? {kid, key: fromBase64Url(entry.key), cssDid: entry.cssDid} : undefined;
}

// m17: the NRR travels to the CSS sealed under K_ttp, so the CSS knows it comes from this TTP.
async function forwardNrrToCss({kid, key}, nrr, uri) {
    const receipt = `${kid}.${seal(key, Buffer.from(JSON.stringify({nrr, uri}), 'utf8'), TAG_TTP_RECEIPT)}`;
    const originalUrl = new URL(uri);
    const internalUrl = new URL(uri);
    const internalBase = new URL(CSS_INTERNAL_BASE);
    internalUrl.protocol = internalBase.protocol;
    internalUrl.host = internalBase.host;

    // Same X-Forwarded-* convention the app uses, so the CSS resolves the original resource identifier.
    const response = await fetch(internalUrl.toString(), {
        headers: {
            ttpreceipt: receipt,
            'x-forwarded-host': originalUrl.host,
            'x-forwarded-proto': originalUrl.protocol.replace(':', ''),
        },
    });
    if (!response.ok) {
        throw new Error(`The CSS rejected the forwarded NRR with ${response.status}: ${await response.text()}`);
    }
}

async function signWithDidKey(data) {
    const [createdDid] = await agent.dids.getCreatedDids({method: 'web', did: TTP_DID});
    const verificationMethod = createdDid?.didDocument?.verificationMethod?.[0];
    if (!verificationMethod) {
        throw new Error(`No verification method found for ${TTP_DID}.`);
    }
    return agent.context.wallet.sign({data, key: getKeyFromVerificationMethod(verificationMethod)});
}

async function verifyDidSignature(did, data, signature) {
    const didDocument = await agent.dids.resolveDidDocument(did);
    const verificationMethod = didDocument.verificationMethod?.[0];
    if (!verificationMethod) {
        throw new Error(`No verification method found for ${did}.`);
    }
    return agent.context.wallet.verify({data, key: getKeyFromVerificationMethod(verificationMethod), signature});
}

// Verifies an NRO/NRR credential and extracts the commitment C it signs (credentialSubject.signedHash).
async function verifyCommitmentCredential(signed) {
    const credentialJson = parseJsonIfNeeded(signed);
    if (!credentialJson || typeof credentialJson !== 'object' || Array.isArray(credentialJson)) {
        throw new Error('Expected a verifiable credential.');
    }

    const credential = JsonTransformer.fromJSON(credentialJson, W3cJsonLdVerifiableCredential);
    const result = await agent.w3cCredentials.verifyCredential({credential});
    if (!result.isValid) {
        throw new Error(result.error?.message ?? 'The credential could not be verified.');
    }

    const issuer = typeof credentialJson.issuer === 'string' ? credentialJson.issuer : credentialJson.issuer?.id;
    const proof = Array.isArray(credentialJson.proof) ? credentialJson.proof[0] : credentialJson.proof;
    const subject = Array.isArray(credentialJson.credentialSubject)
        ? credentialJson.credentialSubject[0]
        : credentialJson.credentialSubject;
    const commitment = subject?.signedHash;
    if (typeof issuer !== 'string' || typeof proof?.verificationMethod !== 'string' || typeof commitment !== 'string') {
        throw new Error('The credential does not carry an issuer, a proof and a signed commitment.');
    }
    if (proof.verificationMethod.split('#')[0] !== issuer) {
        throw new Error('The credential is not signed with a key of its issuer.');
    }

    return {issuer, commitment};
}

function parseJsonIfNeeded(value) {
    if (typeof value !== 'string') {
        return value;
    }

    try {
        return JSON.parse(value);
    } catch {
        return value;
    }
}
