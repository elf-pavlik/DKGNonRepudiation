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
    DidKey, JwsService, getJwkFromKey, isDid, WalletKeyExistsError
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
const {createHash, randomUUID} = require("crypto");
const {EnvelopeService} = require("@credo-ts/core/build/agent/EnvelopeService");
const {defaultDocumentLoader} = require('@credo-ts/core/build/modules/vc/data-integrity/libraries/documentLoader');
const {NrrGraphService} = require('./audit/NrrGraphService');

const NON_REPUDIATION_CONTEXT_URL = 'https://secureapp.solidcommunity.net/public/NonRepudiationContext.jsonld';
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

const prompt = require('prompt-sync')();
const TTP_DID = 'did:web:raw.githubusercontent.com:biagioboi:DKGNonRepudiation:main:demo-ttp:config';
const APP_DID = 'did:web:privateclinic.solidcommunity.net:public';
const APP_DID_KEY = 'did:key:z6Mkg4kRxcfvWfqTV86RdBKHjTks5thJe7R4xsGTs5zASrB7';
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

app.get('/generateInvitation', async (req, res) => {
    try {
        await ensureStarted();

        res.status(200);
        const outOfBandRecord = await agent.oob.createInvitation({
            autoAcceptConnection: true,
            handshake: true,
            invitationDid: TTP_DID,
        })

        agent.events.on(ConnectionEventTypes.ConnectionStateChanged, async ({payload}) => {
            console.log(JSON.stringify(payload));
            if (payload.connectionRecord.state === DidExchangeState.Completed) {
                console.log(JSON.stringify(payload));
            }
        });
        console.log("I'm generating a new invitation");
        const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({domain: sys_config.get('wallet.endpoint')})
        res.json({url: invitationUrl, connectionId: outOfBandRecord.id})
    } catch (error) {
        console.error('demo-ttp generateInvitation error', error);
        res.status(503).json({
            error: error.message ?? 'demo-ttp is not ready yet.',
        })
    }
});

async function handleDisputeFromCss(req, res) {
    const signedResource = extractSignedResourceFromRequestBody(req.body);
    if (signedResource === undefined) {
        res.status(400).json({error: 'Missing app NRR in the request body.'})
        return;
    }

    try {
        await ensureStarted();
        const encryptedMessage = extractEncryptedMessageFromRequestBody(req.body);
        const expectedHashFromRequest = typeof req.body.expectedHash === 'string'
            ? req.body.expectedHash
            : typeof req.body.messageHash === 'string'
                ? req.body.messageHash
                : undefined;
        const expectedHash = encryptedMessage
            ? await extractReferenceHashFromEncryptedMessage(encryptedMessage)
            : expectedHashFromRequest;
        const appSignatureInfo = await verifyAndExtractAppSignedResource(signedResource, expectedHash);
        const matchedTraceRecords = await nrrGraphService.findReceivedNrr({
            messageHash: appSignatureInfo.signedHash,
            signedResource,
        });

        res.status(200).json({
            genuine: true,
            messageHash: appSignatureInfo.signedHash,
            signerKid: appSignatureInfo.signerKid,
            matchedTraceCount: matchedTraceRecords.length,
            matchedTraceIds: matchedTraceRecords.map((record) => record.id),
        })
    } catch (error) {
        console.error('TTP dispute validation error', error);
        res.status(400).json({
            error: error.message ?? 'Unable to validate the app NRR.',
        })
    }
}

app.post('/checkResource', async (req, res) => {
    const encryptedMessage = extractEncryptedMessageFromRequestBody(req.body);
    const signedResource = extractSignedResourceFromRequestBody(req.body);
    if (encryptedMessage === undefined && signedResource === undefined) {
        res.status(400).json({error: 'Unable to process the request.'})
        return;
    }

    try {
        await ensureStarted();
        let verification;
        let symKeyForDecrypt;
        let appSignatureInfo;

        if (encryptedMessage !== undefined) {
            if (typeof encryptedMessage !== 'object' || typeof encryptedMessage.protected !== 'string') {
                throw new Error('The encrypted resource is not a valid JWE message.');
            }

            const env_service = new EnvelopeService(new ConsoleLogger());
            const dec_message = await env_service.unpackMessageWithReturn(agent.context, encryptedMessage);
            verification = await verifyRecoveryMaterial(
                encryptedMessage,
                dec_message.plaintextMessage,
                signedResource
            );
            symKeyForDecrypt = dec_message.payloadKey;
        } else {
            appSignatureInfo = await verifyAndExtractAppSignedResource(signedResource);
            verification = {
                mode: 'nrr-only',
                messageHash: appSignatureInfo.signedHash,
                signerKid: appSignatureInfo.signerKid,
                cssSignatureVerified: false,
                hashCredentialVerified: false,
                appSignatureVerified: true,
            };
        }

        let nrrRecord;
        if (signedResource !== undefined) {
            if (!appSignatureInfo) {
                appSignatureInfo = await verifyAndExtractAppSignedResource(signedResource, verification.messageHash);
            }

            nrrRecord = await nrrGraphService.storeReceivedNrr({
                encryptedResource: encryptedMessage,
                messageHash: appSignatureInfo.signedHash,
                receivedAt: new Date().toISOString(),
                signedResource,
            });
        }

        /* The TTP can now release the symmetric key after validating the non-repudiation material. */
        res.status(200).json({
            symKeyForDecrypt,
            verification,
            nrrRecordId: nrrRecord?.id,
        })
    } catch (error) {
        console.error('TTP validation error', error);
        res.status(400).json({
            error: error.message ?? 'Unable to validate the encrypted resource.',
        })
    }
})

app.post('/disputeFromCSS', handleDisputeFromCss)
app.post('/disputefromCSS', handleDisputeFromCss)

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

async function verifyRecoveryMaterial(encryptedMessage, plaintextMessage, signedResource) {
    // Hash the raw content string, not the whole decrypted DIDComm envelope: the CSS computes
    // the reference hash the same way (see AgentInitializer.buildNonRepudiableRelease), since
    // re-serializing the envelope object independently on each side isn't guaranteed to produce
    // byte-identical JSON. `plaintextMessage` may come back as the raw JSON string of the
    // envelope rather than an already-parsed object, depending on the EnvelopeService version.
    const parsedPlaintext = typeof plaintextMessage === 'string' ? JSON.parse(plaintextMessage) : plaintextMessage;
    const content = typeof parsedPlaintext === 'string' ? parsedPlaintext : parsedPlaintext?.content;
    if (typeof content !== 'string') {
        throw new Error('Could not extract the message content from the decrypted envelope.');
    }
    const computedHash = createHash('sha256').update(content).digest('hex');
    const referenceHash = await extractReferenceHashFromEncryptedMessage(encryptedMessage);

    if (!referenceHash) {
        return {
            mode: 'legacy',
            computedHash,
            cssSignatureVerified: false,
            hashCredentialVerified: false,
            appSignatureVerified: false,
        }
    }

    if (computedHash !== referenceHash) {
        throw new Error('The decrypted message hash does not match the non-repudiation material.');
    }

    let hashCredentialVerified = false;
    if (encryptedMessage.hashCredential !== undefined) {
        hashCredentialVerified = await verifyHashCredential(encryptedMessage.hashCredential);
    }

    let appSignatureVerified = false;
    let appSignerKid;
    if (signedResource !== undefined) {
        const appSignatureInfo = await verifyAndExtractAppSignedResource(signedResource, referenceHash);
        appSignatureVerified = true;
        appSignerKid = appSignatureInfo.signerKid;
    }

    return {
        mode: 'non-repudiation',
        computedHash,
        messageHash: referenceHash,
        cssSignatureVerified: encryptedMessage.signatureFromCSS !== undefined,
        hashCredentialVerified,
        appSignatureVerified,
        appSignerKid,
    }
}

async function extractReferenceHashFromEncryptedMessage(encryptedMessage) {
    if (!encryptedMessage || typeof encryptedMessage !== 'object') {
        return undefined;
    }

    const statedHash = typeof encryptedMessage.hash === 'string' ? encryptedMessage.hash : undefined;
    const credentialHash = extractSignedHashFromHashCredential(encryptedMessage.hashCredential);
    const cssSignatureHash = await verifyCssSignatureAndExtractHash(encryptedMessage.signatureFromCSS);
    const referenceHash = statedHash ?? credentialHash ?? cssSignatureHash;

    if (!referenceHash) {
        return undefined;
    }

    if (statedHash !== undefined && statedHash !== referenceHash) {
        throw new Error('The encrypted message hash does not match the non-repudiation material.');
    }

    if (credentialHash !== undefined && credentialHash !== referenceHash) {
        throw new Error('The non-repudiation credential does not match the encrypted message hash.');
    }

    if (cssSignatureHash !== undefined && cssSignatureHash !== referenceHash) {
        throw new Error('The CSS signature does not match the encrypted message hash.');
    }

    return referenceHash;
}

async function verifyCssSignatureAndExtractHash(signatureFromCSS) {
    if (signatureFromCSS === undefined || signatureFromCSS === null) {
        return undefined;
    }

    const jws = normalizeJws(signatureFromCSS, 'signatureFromCSS');
    const jwsService = new JwsService();
    const {isValid} = await jwsService.verifyJws(agent.context, {
        jws,
        jwkResolver: ({jws: {header}}) => {
            if (typeof header.kid !== 'string' || !isDid(header.kid, 'key')) {
                throw new Error('CSS JWS header kid must be a did:key DID.');
            }
            const didKey = DidKey.fromDid(header.kid);
            return getJwkFromKey(didKey.key);
        },
    });

    if (!isValid) {
        throw new Error('The CSS signature over the encrypted message hash is invalid.');
    }

    return TypedArrayEncoder.toUtf8String(TypedArrayEncoder.fromBase64(jws.payload));
}

async function verifyHashCredential(hashCredential) {
    const credentialJson = typeof hashCredential === 'string' ? JSON.parse(hashCredential) : hashCredential;
    const credential = JsonTransformer.fromJSON(credentialJson, W3cJsonLdVerifiableCredential);
    const result = await agent.w3cCredentials.verifyCredential({credential});

    if (!result.isValid) {
        const verificationError = result.error?.message ?? 'The non-repudiation credential could not be verified.';
        throw new Error(verificationError);
    }

    return true;
}

async function verifyAppSignedResource(signedResource, expectedHash) {
    await verifyAndExtractAppSignedResource(signedResource, expectedHash);
    return true;
}

async function verifyAndExtractAppSignedResource(signedResource, expectedHash) {
    const parsedSignedResource = parseJsonIfNeeded(signedResource);
    if (looksLikeCredential(parsedSignedResource)) {
        const credential = JsonTransformer.fromJSON(parsedSignedResource, W3cJsonLdVerifiableCredential);
        const result = await agent.w3cCredentials.verifyCredential({credential});

        if (!result.isValid) {
            const verificationError = result.error?.message ?? 'The signedResource credential is invalid.';
            throw new Error(verificationError);
        }

        const signedHash = extractSignedHashFromCredential(parsedSignedResource);
        if (!signedHash) {
            throw new Error('Could not extract a signed hash from the signedResource credential.');
        }

        if (expectedHash !== undefined && signedHash !== expectedHash) {
            throw new Error('The signedResource credential does not match the expected message hash.');
        }

        return {
            credential: parsedSignedResource,
            signedHash,
            signerKid: extractVerificationMethodFromProof(parsedSignedResource.proof),
        };
    }

    const jws = normalizeJws(signedResource, 'signedResource');
    const jwsService = new JwsService();
    const {isValid} = await jwsService.verifyJws(agent.context, {
        jws,
        jwkResolver: ({jws: {header}}) => {
            if (typeof header.kid !== 'string' || !isDid(header.kid, 'key')) {
                throw new Error('signedResource JWS header kid must be a did:key DID.');
            }
            const didKey = DidKey.fromDid(header.kid);
            return getJwkFromKey(didKey.key);
        },
    });

    if (!isValid) {
        throw new Error('The signedResource JWS is invalid.');
    }

    const signedPayload = TypedArrayEncoder.toUtf8String(TypedArrayEncoder.fromBase64(jws.payload));
    const signedHash = extractSignedHashFromSignedPayload(signedPayload);
    if (expectedHash !== undefined && signedHash !== expectedHash) {
        throw new Error('The signedResource payload does not match the expected message hash.');
    }

    return {
        jws,
        signedHash,
        signerKid: typeof jws.header?.kid === 'string' ? jws.header.kid : undefined,
    };
}

function normalizeJws(jws, fieldName) {
    const parsedJws = parseJsonIfNeeded(jws);
    if (!parsedJws || typeof parsedJws !== 'object' || typeof parsedJws.payload !== 'string') {
        throw new Error(`The ${fieldName} field must contain a JWS payload.`);
    }

    return {
        ...parsedJws,
        payload: parsedJws.payload,
    };
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

function extractEncryptedMessageFromRequestBody(body) {
    const parsedBody = parseJsonIfNeeded(body);
    const explicitEncryptedMessage = parseJsonIfNeeded(parsedBody?.encryptedMessage ?? parsedBody?.encryptedResource);
    if (explicitEncryptedMessage !== undefined) {
        return explicitEncryptedMessage;
    }

    if (parsedBody && typeof parsedBody === 'object' && typeof parsedBody.protected === 'string') {
        return parsedBody;
    }

    return undefined;
}

function extractSignedResourceFromRequestBody(body) {
    const parsedBody = parseJsonIfNeeded(body);
    return parseJsonIfNeeded(parsedBody?.signedResource ?? parsedBody?.nrr);
}

function extractSignedHashFromSignedPayload(signedPayload) {
    if (/^[a-f0-9]{64}$/iu.test(signedPayload)) {
        return signedPayload;
    }

    let parsedPayload;
    try {
        parsedPayload = JSON.parse(signedPayload);
    } catch {
        throw new Error('Could not parse signedResource payload.');
    }

    if (typeof parsedPayload === 'string' && /^[a-f0-9]{64}$/iu.test(parsedPayload)) {
        return parsedPayload;
    }

    if (parsedPayload && typeof parsedPayload === 'object') {
        if (typeof parsedPayload.hash === 'string') {
            if (typeof parsedPayload.signatureFromCSS?.payload === 'string') {
                const cssSignedHash = TypedArrayEncoder.toUtf8String(
                    TypedArrayEncoder.fromBase64(parsedPayload.signatureFromCSS.payload),
                );

                if (cssSignedHash !== parsedPayload.hash) {
                    throw new Error('The signed resource hash does not match the CSS signature payload.');
                }
            }

            const credentialHash = extractSignedHashFromHashCredential(parsedPayload.hashCredential);
            if (credentialHash !== undefined && credentialHash !== parsedPayload.hash) {
                throw new Error('The signed resource hash does not match the non-repudiation credential.');
            }

            return parsedPayload.hash;
        }

        const credentialHash = extractSignedHashFromHashCredential(parsedPayload.hashCredential);
        if (credentialHash !== undefined) {
            return credentialHash;
        }

        if (typeof parsedPayload.signatureFromCSS?.payload === 'string') {
            return TypedArrayEncoder.toUtf8String(
                TypedArrayEncoder.fromBase64(parsedPayload.signatureFromCSS.payload),
            );
        }
    }

    throw new Error('Could not extract a hash from signedResource payload.');
}

function extractSignedHashFromHashCredential(hashCredential) {
    if (hashCredential === undefined || hashCredential === null) {
        return undefined;
    }

    let parsedCredential = hashCredential;
    if (typeof parsedCredential === 'string') {
        try {
            parsedCredential = JSON.parse(parsedCredential);
        } catch {
            return undefined;
        }
    }

    if (parsedCredential && typeof parsedCredential === 'object') {
        const signedHashFromSubject = extractSignedHashFromCredentialSubject(parsedCredential);
        if (typeof signedHashFromSubject === 'string') {
            return signedHashFromSubject;
        }

        const signedHash = parsedCredential.signedHash;
        if (typeof signedHash === 'string') {
            return signedHash;
        }
    }

    return undefined;
}

function extractSignedHashFromCredential(credential) {
    const signedHashFromSubject = extractSignedHashFromCredentialSubject(credential);
    if (typeof signedHashFromSubject === 'string') {
        return signedHashFromSubject;
    }

    if (credential && typeof credential === 'object' && typeof credential.signedHash === 'string') {
        return credential.signedHash;
    }

    return undefined;
}

function extractSignedHashFromCredentialSubject(credential) {
    const credentialSubject = credential?.credentialSubject;

    if (credentialSubject && !Array.isArray(credentialSubject) && typeof credentialSubject === 'object') {
        return typeof credentialSubject.signedHash === 'string' ? credentialSubject.signedHash : undefined;
    }

    if (Array.isArray(credentialSubject)) {
        const subjectWithHash = credentialSubject.find((subject) => typeof subject?.signedHash === 'string');
        if (subjectWithHash) {
            return subjectWithHash.signedHash;
        }
    }

    return undefined;
}

function extractVerificationMethodFromProof(proof) {
    const resolvedProof = Array.isArray(proof) ? proof[0] : proof;
    return typeof resolvedProof?.verificationMethod === 'string' ? resolvedProof.verificationMethod : undefined;
}

function looksLikeCredential(value) {
    if (!value || typeof value !== 'object') {
        return false;
    }

    const types = Array.isArray(value.type) ? value.type : [];
    return types.includes('VerifiableCredential');
}
