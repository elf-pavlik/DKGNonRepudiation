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
    TransportService, JwsService, Ed25519Jwk, DidExchangeProtocol, Attachment, JsonEncoder, DidKey, getJwkFromKey,
    BasicMessageEventTypes, BaseLogger, isDid, getKeyFromVerificationMethod
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
const {agentDependencies, HttpInboundTransport} = require('@credo-ts/node')
const {IndyVdrIndyDidResolver, IndyVdrAnonCredsRegistry, IndyVdrModule} = require('@credo-ts/indy-vdr')
const {indyVdr} = require('@hyperledger/indy-vdr-nodejs')
const {ariesAskar} = require('@hyperledger/aries-askar-nodejs')
const {AskarModule} = require('@credo-ts/askar')
const {anoncreds} = require('@hyperledger/anoncreds-nodejs')
const {AnonCredsRsModule} = require('@credo-ts/anoncreds')
const sys_config = require('config');

// This app's own identity (client DID) - override per replica via env so multiple demo-app
// instances (e.g. demo-app-1 / demo-app-2) can each present a different client DID and get
// matched against different ACP policies on the same resource. The wallet key itself already
// comes from NODE_CONFIG's wallet.seed_private_key per replica; this just makes the DID label
// that goes with it configurable too.
// NOTE: the verification-method key fragment (the `#z6Mk...` suffix used where this app signs
// wrapped presentations) is NOT derived from this env var - it still needs to match whatever key
// was actually generated from this replica's wallet seed. Update APP_DID_VERIFICATION_FRAGMENT
// too when giving a replica a real new DID/key pair.
const APP_DID = process.env.APP_DID || 'did:web:privateclinic.solidcommunity.net:public';
const APP_DID_VERIFICATION_FRAGMENT = process.env.APP_DID_VERIFICATION_FRAGMENT || 'z6Mkg4kRxcfvWfqTV86RdBKHjTks5thJe7R4xsGTs5zASrB7';
const APP_VERIFICATION_METHOD = `${APP_DID}#${APP_DID_VERIFICATION_FRAGMENT}`;
// The holder (user) and issuer DIDs this app expects to deal with - also configurable per
// replica, exposed to the browser via GET /api/identity instead of being hardcoded in main.js.
const HOLDER_DID = process.env.APP_HOLDER_DID || 'did:web:bboi.solidcommunity.net:public';
const ISSUER_DID = process.env.APP_ISSUER_DID || 'did:web:secureissuer.solidcommunity.net:public';

// Purely cosmetic per-replica branding (org name shown in the UI, accent colors), so different
// demo-app instances can visibly represent different organizations (e.g. a private vs a public
// hospital) even though they run the same code.
const ORG_NAME = process.env.APP_ORG_NAME || 'Private Clinic';
const ORG_EYEBROW = process.env.APP_ORG_EYEBROW || 'Private Clinic Gateway';
const THEME_PRIMARY = process.env.APP_THEME_PRIMARY || '#0a7c86';
const THEME_PRIMARY_STRONG = process.env.APP_THEME_PRIMARY_STRONG || '#075f68';

const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');

const express = require('express');
var bodyParser = require('body-parser');
const {NroGraphService} = require('./audit/NroGraphService');
const {defaultDocumentLoader} = require('@credo-ts/core/build/modules/vc/data-integrity/libraries/documentLoader');
const {createWalletKeyPairClass} = require('@credo-ts/core/build/crypto/WalletKeyPair');
const vc = require('@digitalcredentials/vc');

const getGenesisTransaction = async (url) => {
    const response = await fetch(url)
    return await response.text()
}

function normalizeHostInvitationUrl(invitationUrl) {
    console.log("Normalizing invitation URL A: " + invitationUrl)
    const dockerHostGateway = process.env.DOCKER_HOST_GATEWAY || 'host.docker.internal'
    try {
        const parsedUrl = new URL(invitationUrl)
        if (['localhost', '127.0.0.1', '0.0.0.0'].includes(parsedUrl.hostname)) {
            parsedUrl.hostname = dockerHostGateway
            return parsedUrl.toString()
        }
    } catch (error) {
        console.warn(`Unable to normalize invitation URL: ${error.message}`)
    }
    return invitationUrl
}

function decodeBase64UrlUtf8(value) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
    return Buffer.from(normalized + padding, 'base64').toString('utf8');
}

function deserializeProofRequest(serializedProofRequest) {
    if (!serializedProofRequest) {
        return undefined;
    }

    if (typeof serializedProofRequest !== 'string') {
        return serializedProofRequest;
    }

    try {
        return JSON.parse(serializedProofRequest);
    } catch (error) {
        try {
            return JSON.parse(decodeBase64UrlUtf8(serializedProofRequest));
        } catch (decodeError) {
            throw new Error('Unable to deserialize the proof request from the DIDComm header.');
        }
    }
}

function populateRequestBodyFromProofRequest(requestBody) {
    const proofRequest = deserializeProofRequest(requestBody.vpr ?? requestBody.proofRequest);
    if (!proofRequest) {
        return undefined;
    }

    const requestAcp = proofRequest.presentation_definition?.requestACP ?? {};
    requestBody.vpr = JSON.stringify(proofRequest);
    requestBody.challenge ??= proofRequest.options?.challenge;
    requestBody.domain ??= proofRequest.options?.domain;
    requestBody.target ??= requestAcp.target;
    requestBody.owner ??= requestAcp.owner;
    requestBody.issuer ??= requestAcp.issuer;
    requestBody.creator ??= requestAcp.creator;
    requestBody.client ??= requestAcp.client;
    requestBody.agent ??= requestAcp.agent;
    requestBody.resource ??= requestAcp.target;

    if (requestBody.input_descriptors === undefined && proofRequest.presentation_definition?.input_descriptors) {
        requestBody.input_descriptors = JSON.stringify(proofRequest.presentation_definition.input_descriptors);
    }

    return proofRequest;
}

function runAsyncTask(label, task) {
    setImmediate(() => {
        void Promise.resolve()
            .then(task)
            .catch((error) => {
                console.error(`[${label}] ${error.stack || error.message}`)
            })
    })
}

const initializeIssuerAgent = async (ledgerUrl, endPoint) => {

    const genesisTransactionsBCovrinTestNet = await getGenesisTransaction(ledgerUrl)

    const config = {
        // Human-facing name shown to the wallet during the DID Exchange invitation - kept
        // separate from wallet.id (internal Askar storage identifier, must stay stable).
        label: ORG_NAME,
        walletConfig: {
            id: sys_config.get('wallet.id'),
            key: sys_config.get('wallet.key'),
        },
        endpoints: [endPoint],
        logger: new ConsoleLogger(LogLevel.debug),
        autoUpdateStorageOnStartup: true
    }

    // A new instance of an agent is created here
    const agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet)
    })

    // Register a simple `WebSocket` outbound transport - not needed
    agent.registerOutboundTransport(new WsOutboundTransport())

    // Register a simple `Http` outbound transport
    agent.registerOutboundTransport(new HttpOutboundTransport())


    const serverApp = express()
    serverApp.use(express.json({limit: '50mb'}));
    serverApp.use(express.json({limit: '50mb'}));
    serverApp.use(bodyParser.json({limit: '50mb'}));
    serverApp.use(bodyParser.urlencoded({limit: '50mb',extended: true, parameterLimit: 50000}));

    // Register a simple `Http` inbound transport
    agent.registerInboundTransport(new HttpInboundTransport({app: serverApp, port: 3010}))


    // Initialize the agent

    await agent.initialize()

    const did = APP_DID
    try {
        console.log("Trying to create the DID for the wallet: " + did)
        // Try to create the key for the wallet, if it already exists then jump these instructions
        const ed25519Key = await agent.wallet.createKey({
            keyType: KeyType.Ed25519,
            privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
        })

        const builder = new DidDocumentBuilder(did)
        const ed25519VerificationMethod2018 = getEd25519VerificationKey2018({
            key: ed25519Key,
            id: `${did}#${ed25519Key.fingerprint}`,
            controller: did,
        })

        builder.addService(new DidCommV1Service({
            "id": "#inline-0",
            "serviceEndpoint": sys_config.get('wallet.endpoint'),
            "type": "did-communication",
            "recipientKeys": [`${did}#${ed25519Key.fingerprint}`],
            "routingKeys": [`${did}#${ed25519Key.fingerprint}`]
        }));


        builder.addVerificationMethod(ed25519VerificationMethod2018)
        builder.addAuthentication(ed25519VerificationMethod2018.id)
        builder.addAssertionMethod(ed25519VerificationMethod2018.id)
        console.log(JSON.stringify(builder.build()));

        // result = await agent.dids.create({
        //     method: 'web',
        //     didDocument: builder.build(),
        //     options: {
        //         keyType: KeyType.Ed25519,
        //         privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
        //     }
        // })

        let didResp = await agent.dids.resolve(did);
        result = await agent.dids.import({
            did,
            didDocument: didResp.didDocument,
            overwrite: true,
            options: {
                keyType: KeyType.Ed25519,
                privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
            }
        })
        console.log("DID created for the wallet: " + JSON.stringify(result));
    } catch (e) {
        console.log("this is the error: " + e.message);
        let didResp = await agent.dids.resolve(did);
        let u = await agent.dids.resolveDidDocument(did)

        await agent.dids.import({
            did,
            didDocument: didResp.didDocument,
            overwrite: true,
            options: {
                keyType: KeyType.Ed25519,
                privateKey: TypedArrayEncoder.fromString(sys_config.get('wallet.seed_private_key'))
            }
        })
        let created_dids = await agent.dids.getCreatedDids({method: 'web'});
        console.log(created_dids[0].didDocument);
        console.log("This is the App Wallet, it has this DID: " + created_dids[0].did);

    }


    return agent
}

let agent

const NON_REPUDIATION_CONTEXT_URL = 'https://privateclinic.solidcommunity.net/public/NonRepudiationContext.jsonld';
const NON_REPUDIATION_CONTEXT_PATH = [
    path.join(__dirname, '..', 'NonRepudiationContext.jsonld'),
    path.join(__dirname, '..', '..', 'NonRepudiationContext.jsonld'),
].find((candidatePath) => fs.existsSync(candidatePath));

if (!NON_REPUDIATION_CONTEXT_PATH) {
    throw new Error('NonRepudiationContext.jsonld not found for demo-app.');
}

const NON_REPUDIATION_CONTEXT = JSON.parse(
    fs.readFileSync(NON_REPUDIATION_CONTEXT_PATH, 'utf8')
);
const APP_NRR_CREDENTIAL_TYPE = 'NonRepudiationDestination';
const TTP_CHECK_RESOURCE_URL = `${process.env.TTP_API_BASE || 'http://demo-ttp:8082'}/checkResource`;
// The browser reaches the CSS via its published host/port (e.g. http://localhost:3002), but
// this backend runs inside its own container and must reach the CSS via the docker network
// instead - same pattern as TTP_API_BASE above.
const CSS_INTERNAL_BASE = process.env.CSS_INTERNAL_BASE || 'http://solid-css:3002';

// Rewrites a browser-facing CSS resource URL to the internal (docker network) origin,
// keeping path/query intact, for server-to-server calls from this backend.
function toInternalCssUrl(url) {
    try {
        const target = new URL(url);
        const internalBase = new URL(CSS_INTERNAL_BASE);
        target.protocol = internalBase.protocol;
        target.host = internalBase.host;
        return target.toString();
    } catch {
        return url;
    }
}

const nroGraphService = new NroGraphService({
    rootFilePath: path.join(__dirname, '..'),
});
const {
    fromBase64Url,
    hashCiphertext,
    hashKey,
    computeCommitment,
    decryptResource,
} = require('./vera-crypto');

async function startEverything() {
    agent = await initializeIssuerAgent(sys_config.get('wallet.ledger_url'), sys_config.get('wallet.endpoint'));
    //await activateListener(agent, false, true)
}

const {randomUUID} = require("crypto");
const domain = require("domain");
const {W3cIssuerOptions} = require("@credo-ts/core/build/modules/vc/models/credential/W3cIssuer");
const {SingleOrArray} = require("@credo-ts/core/build/utils");
const {JsonObject} = require("@credo-ts/core/build/types");
const vc_1 = require("@credo-ts/core/build/modules/vc");
const {W3cJsonLdCredentialService} = require("@credo-ts/core/build/modules/vc/data-integrity/W3cJsonLdCredentialService");

const app = express();
const PORT = 8080;
startEverything().then(result => {
    /* Empty */
})
app.use(express.static('public'))
const OutOfBandEvents_1 = require("@credo-ts/core/build/modules/oob/domain/OutOfBandEvents");
const {EnvelopeService} = require("@credo-ts/core/build/agent/EnvelopeService");
const crypto = require("crypto");
app.use(express.json({limit: '50mb'}));
app.use(express.json({limit: '50mb'}));
app.use(bodyParser.json({limit: '50mb'}));
app.use(bodyParser.urlencoded({limit: '50mb',extended: true, parameterLimit: 50000}));

// Lets the browser pick up this replica's identity (agent/issuer/client DIDs) instead of
// hardcoding them in main.js - each demo-app replica can be configured with its own via
// APP_HOLDER_DID / APP_ISSUER_DID / APP_DID.
app.get('/api/identity', (req, res) => {
    res.json({
        agent: HOLDER_DID,
        issuer: ISSUER_DID,
        client: APP_DID,
        orgName: ORG_NAME,
        orgEyebrow: ORG_EYEBROW,
        themePrimary: THEME_PRIMARY,
        themePrimaryStrong: THEME_PRIMARY_STRONG,
    });
});

app.get('/.internal/nro-audit/query', async (req, res) => {
    try {
        const requestedResource = typeof req.query.resource === 'string' ? req.query.resource : undefined;
        const requesterDid = typeof req.query.requesterDid === 'string' ? req.query.requesterDid : undefined;
        const messageHash = typeof req.query.messageHash === 'string' ? req.query.messageHash : undefined;
        const issuerDid = typeof req.query.issuerDid === 'string' ? req.query.issuerDid : undefined;
        const records = await nroGraphService.findVerifiedNro({
            requestedResource,
            requesterDid,
            messageHash,
            issuerDid,
        });

        res.status(200).json({
            count: records.length,
            records,
        });
    } catch (error) {
        res.status(500).json({
            error: error.message ?? 'Unable to query the NRO audit graph.',
        });
    }
});

app.get('/', (req, res) => {
    res.status(200);
    //let url = `/index.html?user=${user}&application=${application}&vcissuer=${vcissuer}&nonce=${encodeURIComponent(nonce)}&domain=${domain}&redirect_uri=${redirect_uri}&code=${encodeURIComponent(code)}`;
    let url = 'index.html'
    res.redirect(url);
});

// The requester's long-form did:web (`didlong`) is verified cryptographically during DID
// Exchange (see DidExchangeProtocol.processRequest in the credo-ts fork) and stashed in
// connection metadata - this reads it back out. Falls back to the connection's peer DID
// (theirDid) if the wallet didn't present one (e.g. an older/unmodified DIDComm client).
function extractTheirPublicDid(connectionRecord) {
    const metadata = connectionRecord?.metadata?.get?.('_internal/theirPublicDid');
    return metadata?.did ?? connectionRecord?.theirDid;
}

// Waits for the wallet to complete the DID Exchange for the given OOB invitation and reports
// back the DID it authenticated with. Used by the frontend to learn *who* is connecting before
// ever asking the CSS for a resource, instead of assuming a single hardcoded patient DID.
app.get('/connectionIdentity', async (req, res) => {
    const oobId = req.query.connectionId;
    if (!oobId) {
        res.status(400).json({error: 'Missing connectionId.'});
        return;
    }

    const respondIfCompleted = (connectionRecord) => {
        if (res.headersSent || !connectionRecord || connectionRecord.state !== DidExchangeState.Completed) {
            return false;
        }
        const did = extractTheirPublicDid(connectionRecord);
        if (!did) {
            res.status(422).json({error: 'The wallet did not present an authenticated DID during connection.'});
        } else {
            res.json({did});
        }
        return true;
    };

    const handleConnectionStateChanged = ({payload}) => {
        runAsyncTask('demo-app connection identity listener', async () => {
            if (payload.connectionRecord.outOfBandId !== oobId) return;
            if (respondIfCompleted(payload.connectionRecord)) {
                agent.events.off(ConnectionEventTypes.ConnectionStateChanged, handleConnectionStateChanged);
            }
        });
    };
    agent.events.on(ConnectionEventTypes.ConnectionStateChanged, handleConnectionStateChanged);
    res.on('close', () => agent.events.off(ConnectionEventTypes.ConnectionStateChanged, handleConnectionStateChanged));

    // The connection may already be Completed by the time this is polled/awaited.
    const existing = (await agent.connections.findAllByOutOfBandId(oobId))
        .find((connection) => connection.state === DidExchangeState.Completed);
    if (respondIfCompleted(existing)) {
        agent.events.off(ConnectionEventTypes.ConnectionStateChanged, handleConnectionStateChanged);
    }
});

app.get('/generateInvitation', async (req, res) => {
    res.status(200);

    const outOfBandRecord = await agent.oob.createInvitation({
        autoAcceptConnection: true,
        handshake: true,
        invitationDid: APP_DID,
    })

    const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({domain: sys_config.get('wallet.endpoint')})
    let qrcode_png
    await QRCode.toDataURL(invitationUrl, {version: 22}).then(qrcode_generated => {
        qrcode_png = qrcode_generated
    })
    res.json({url: invitationUrl, connectionId: outOfBandRecord.id, qrcode: qrcode_png})
});

app.post('/generateInvitation', async (req, res) => {
    res.status(200);
    console.log(req.body);
    const cssInvitationURL = req.body.cssInvitationUrl;

    const handleProofStateChanged = ({payload}) => {
        runAsyncTask('demo-app generate invitation proof listener', async () => {
            if (payload.proofRecord.state !== ProofState.RequestReceived) return

            agent.events.off(ProofEventTypes.ProofStateChanged, handleProofStateChanged)

            const outOfBandRecord = await agent.oob.createInvitation({
                autoAcceptConnection: true,
                handshake: true,
                invitationDid: APP_DID,
            })
            const vpr = await agent.proofs.getFormatData(payload.proofRecord.id)
            const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({domain: sys_config.get('wallet.endpoint')})
            let qrcode_png
            await QRCode.toDataURL(invitationUrl, {version: 22}).then(qrcode_generated => {
                qrcode_png = qrcode_generated
            })
            if (!res.headersSent) {
                res.json({
                    cssInvitationConnection: payload.proofRecord.connectionId,
                    url: invitationUrl,
                    connectionId: outOfBandRecord.id,
                    qrcode: qrcode_png,
                    payload: vpr.request.presentationExchange
                })
            }
        })
    }

    agent.events.on(ProofEventTypes.ProofStateChanged, handleProofStateChanged)
    res.on('close', () => {
        agent.events.off(ProofEventTypes.ProofStateChanged, handleProofStateChanged)
    })

    try {
        resp = await agent.oob.receiveInvitationFromUrl(cssInvitationURL);
    } catch (error) {
        agent.events.off(ProofEventTypes.ProofStateChanged, handleProofStateChanged)
        throw error
    }

});

async function ourListener(payload, requestBody, onFlowReady, onProofReady) {
    if (payload.connectionRecord.state === DidExchangeState.Completed) {
        if (payload.connectionRecord.outOfBandId !== requestBody.connectionId) return

        onFlowReady()
        const proofConnectionId = payload.connectionRecord.id

        //console.log(await agent.connections.rotate({connectionId: payload.connectionRecord.id}));
        /* Start by sending a proof request, if we want to assess the identity */
        /* todo: get my_did from created did */
        let my_did = "did:key:z6Mkg4kRxcfvWfqTV86RdBKHjTks5thJe7R4xsGTs5zASrB7";
        /* TODO: Insert a field in the VPR that identify the application, by modifying PEX library */

        /* MAYBE_TODO: By now we have a list of authorized did from the holder, but in the future implementation we may have a protocol for exchanging app DID and add new dids to the list */

        /* Check if the request contains a proof field, if yes we have to create a wrapper rather than the simple request */

        /* We have to improve here, it is possible that we only sign the request, as well as only the ACP Context, as well as wrap it*/
        const handleProofStateChanged = ({payload: proofPayload}) => {
            runAsyncTask('demo-app proof completion listener', async () => {
                if (proofPayload.proofRecord.connectionId !== proofConnectionId) return
                if (proofPayload.proofRecord.state !== ProofState.Done) return
                if (proofPayload.proofRecord.isVerified !== true) return

                /* We are sure that the presentation has been signed and contains the same challenge and we can now produce a new VP containing our singature or maybe not*/
                let entire_vp = await agent.proofs.getFormatData(proofPayload.proofRecord.id)

                const presentationParsed = JsonTransformer.fromJSON(entire_vp.presentation.presentationExchange, W3cJsonLdVerifiablePresentation);
                let wrapPresentation = true;
                let presentationToSend = presentationParsed
                if (wrapPresentation) {
                    let wrappedVP = await agent.w3cCredentials.createPresentationWrapper({
                        id: "https://example.com/wrappedVP/321122",
                        vp: presentationParsed
                    })
                    presentationToSend = await agent.w3cCredentials.signWrappedPresentation({
                        presentation: wrappedVP,
                        format: ClaimFormat.LdpVp,
                        verificationMethod: APP_VERIFICATION_METHOD,
                        challenge: presentationParsed.proof.challenge,
                        domain: presentationParsed.proof.domain,
                        proofType: "Ed25519Signature2018",
                    })
                }

                agent.events.off(ProofEventTypes.ProofStateChanged, handleProofStateChanged)

                await onProofReady?.(presentationToSend)
            })
        }

        agent.events.on(ProofEventTypes.ProofStateChanged, handleProofStateChanged)

        try {
        if (requestBody.vpr === undefined) {
            const proof_request = await agent.proofs.requestProof({
                protocolVersion: 'v2',
                connectionId: proofConnectionId,
                proofFormats: {
                    presentationExchange: {
                        type: ["VerifiablePresentationRequest"],
                        '@context': ["https://bboi.solidcommunity.net/public/schemas/2024/presexchange.jsonld"],
                        presentationDefinition: {
                            "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                            "input_descriptors": JSON.parse(requestBody.input_descriptors),
                            "format": { // Which format we want for the signature? Currently, we are using ldp_vp
                                "ldp_vc": {
                                    "proof_type": [
                                        "JsonWebSignature2020",
                                        "Ed25519Signature2018",
                                    ]
                                },
                                "ldp_vp": {
                                    "proof_type": ["Ed25519Signature2018"]
                                },
                            },
                            "requestACP": {
                                "type": ["ACPContext"],
                                "target": requestBody.target,
                                "agent": requestBody.agent,
                                "creator": requestBody.creator,
                                "owner": requestBody.owner,
                                "client": requestBody.client,
                                "issuer": requestBody.issuer
                            }
                        },
                        options: {
                            challenge: requestBody.challenge,
                            domain: requestBody.domain,
                        },
                        signPresentationRequest: true,
                    }

                }
            });
        } else {
            let vpr_obj = JSON.parse(requestBody.vpr)
            let wrapperVPR = new W3cPresentationRequest(vpr_obj)
            let wrapped_VPR = await agent.w3cCredentials.createPresentationRequestWrapper({
                id: "https://example.com/wrappedVPR/321122",
                vpr: wrapperVPR,
                termsAndCondition: wrapperVPR.presentation_definition.requestACP,
            })
            let wrappedVPRSigned = await agent.w3cCredentials.signWrappedPresentationRequest(
                {
                    wrappedVPR: wrapped_VPR,
                    proofType: 'Ed25519Signature2018',
                    verificationMethod: APP_VERIFICATION_METHOD,
                }
            )
            /* Send it to the user */
            await agent.proofs.requestWrappedProof({
                protocolVersion: 'v2',
                connectionId: proofConnectionId,
                requestWrapper: wrappedVPRSigned,
                proofFormats: {
                    presentationExchange: {
                        // Empty, it is just for interop and to say that we want DifExchange
                    }
                }
            })

        }
        } catch (error) {
            agent.events.off(ProofEventTypes.ProofStateChanged, handleProofStateChanged)
            throw error
        }

    }
}

app.post('/requestUserCredential', async (req, res) => {
    res.status(200);
    const requestBody = {...req.body}
    try {
        populateRequestBodyFromProofRequest(requestBody)
    } catch (error) {
        return res.status(400).json({
            error: error.message ?? 'Unable to deserialize the proof request.',
        })
    }
    let flowFinished = false


    /* Is the domain what we want for the request (VPR)? */
    /* To attach the listner only to the current connection, checks on outOfBandId field  */
    /*agent.events.on(OutOfBandEventTypes.HandshakeReused, async ({payload}) => {
            await agent.connections.rotate({connectionId: payload.connectionRecord.id})
    });*/

    const removeFlowListeners = () => {
        agent.events.off(ConnectionEventTypes.ConnectionStateChanged, handleConnectionStateChanged)
    }

    // Guards against handling the same connection twice - it may already be Completed by the
    // time this endpoint runs (the frontend now establishes the wallet connection up front, via
    // /generateInvitation + /connectionIdentity, before ever asking the CSS for a proof request),
    // in which case the ConnectionStateChanged listener below would never fire on its own.
    let connectionHandled = false
    const handleConnectionReady = (connectionRecord) => {
        if (connectionHandled) return
        if (connectionRecord.outOfBandId !== requestBody.connectionId) return
        if (connectionRecord.state !== DidExchangeState.Completed) return
        connectionHandled = true

        runAsyncTask('demo-app request user credential connection listener', async () => {
            await ourListener({connectionRecord}, requestBody, () => {
                if (flowFinished) return
                flowFinished = true
                agent.events.off(ConnectionEventTypes.ConnectionStateChanged, handleConnectionStateChanged)
            }, async (proof) => {
                if (res.headersSent) return
                res.json(proof)
                removeFlowListeners()
            })
        })
    }

    const handleConnectionStateChanged = ({payload}) => handleConnectionReady(payload.connectionRecord)

    agent.events.on(ConnectionEventTypes.ConnectionStateChanged, handleConnectionStateChanged)
    res.on('close', removeFlowListeners)

    if (requestBody.connectionId) {
        const existingConnection = (await agent.connections.findAllByOutOfBandId(requestBody.connectionId))
            .find((connection) => connection.state === DidExchangeState.Completed)
        if (existingConnection) {
            handleConnectionReady(existingConnection)
        }
    }
})

// Completes the non-repudiable release (paper Section 3.3): the browser already holds the
// `encryptedresource` header (E, Y, h, h_K, NRO) from a `vp`-authenticated GET, plus the VPR it answered.
// The app recomputes C, checks the NRO, signs the NRR on C and obtains K_R from the CSS (`signedresource`
// header) or, when `useTtp` is set or the CSS fails to release a key matching h_K, from the TTP.
// It then decrypts E and checks it against h.
app.post('/completeNonRepudiableRelease', async (req, res) => {
    try {
        const {url, agent: didU, encryptedResource, vpr, useTtp} = req.body;
        const release = parseJsonIfNeeded(encryptedResource);
        const proofRequest = vpr ? deserializeProofRequest(vpr) : undefined;
        if (!url || !didU || !release || !proofRequest) {
            return res.status(400).json({error: 'Missing url, agent, vpr or encryptedResource.'});
        }

        const requestAcp = proofRequest.presentation_definition?.requestACP ?? {};
        if (requestAcp.target !== url) {
            throw new Error('The VPR does not refer to the requested resource.');
        }
        const context = {
            didV: requestAcp.owner,
            didA: APP_DID,
            didU,
            uri: url,
            nc: proofRequest.options?.challenge,
        };
        const {commitment, hE} = await verifyReleaseAndComputeCommitment(agent, release, context);
        await nroGraphService.storeVerifiedNro({
            nro: release.nro,
            requestedResource: url,
            requesterDid: APP_DID,
            messageHash: commitment,
            issuerDid: context.didV,
            verifiedAt: new Date().toISOString(),
        });
        const nrr = await createNrrCredential(agent, context.didV, commitment);

        let kR;
        let releasedBy = 'ttp';
        if (!useTtp) {
            try {
                kR = await requestKeyFromCss(url, nrr);
                if (hashKey(kR) !== release.hK) {
                    throw new Error('The key released by the CSS does not match h_K.');
                }
                releasedBy = 'css';
            } catch (error) {
                console.warn(`[demo-app completeNonRepudiableRelease] CSS release failed, turning to the TTP: ${error.message}`);
                kR = undefined;
            }
        }
        if (kR === undefined) {
            kR = await requestKeyFromTtp({...context, hE, release, nrr});
            if (hashKey(kR) !== release.hK) {
                throw new Error('The key released by the TTP does not match h_K.');
            }
        }

        // A key matching h_K that does not open E into a plaintext matching h is an inconsistent
        // release by the CSS: the stored NRO is the evidence of it.
        const {resource} = decryptResource(release.E, kR, release.h);
        res.json({content: resource, releasedBy, commitment});
    } catch (error) {
        console.error(`[demo-app completeNonRepudiableRelease] ${error.stack || error.message}`);
        res.status(400).json({error: error.message ?? 'Unable to complete the non-repudiable release.'});
    }
})

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
    const customDocumentLoader = (agentContext) => createDemoAppDocumentLoader(agentContext)
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

// Recomputes C from the received E, Y, h, h_K and from the identities and nonce of the VPR, and checks
// that the NRO is a signature of the CSS on that value.
async function verifyReleaseAndComputeCommitment(agent, release, context) {
    for (const [name, value] of Object.entries({...context, E: release?.E, Y: release?.Y, h: release?.h, hK: release?.hK})) {
        if (typeof value !== 'string') {
            throw new Error(`Missing ${name} for the non-repudiable release.`);
        }
    }

    const hE = hashCiphertext(release.E);
    const commitment = computeCommitment({...context, hE, Y: release.Y, h: release.h, hK: release.hK});
    const nro = await verifyCommitmentCredential(agent, release.nro);
    if (nro.issuer !== context.didV || nro.commitment !== commitment) {
        throw new Error('The NRO is not a signature of the CSS on C.');
    }

    return {commitment, hE};
}

async function requestKeyFromCss(url, nrr) {
    // Connect via the docker network, but tell the CSS the original Host/protocol via
    // X-Forwarded-*: the CSS resolves resource identifiers against the Host header (or
    // its Forwarded/X-Forwarded-Host override) - a raw `host` header can't be spoofed
    // through fetch() (forbidden by the Fetch spec even server-side), so use the
    // reverse-proxy convention CSS already supports instead (OriginalUrlExtractor).
    const originalUrl = new URL(url);
    const releaseResponse = await fetch(toInternalCssUrl(url), {
        headers: {
            signedresource: JSON.stringify(nrr),
            'x-forwarded-host': originalUrl.host,
            'x-forwarded-proto': originalUrl.protocol.replace(':', ''),
        },
    });
    if (!releaseResponse.ok) {
        throw new Error(await releaseResponse.text());
    }

    const keyForDecrypt = releaseResponse.headers.get('keyfordecrypt');
    if (!keyForDecrypt) {
        throw new Error('The CSS did not release a key.');
    }
    return fromBase64Url(keyForDecrypt);
}

// TTP Resolution (m15): everything the TTP needs to recompute C, but not the ciphertext E.
async function requestKeyFromTtp({didU, uri, nc, hE, release, nrr, ttpCheckResourceUrl = TTP_CHECK_RESOURCE_URL}) {
    const response = await fetch(ttpCheckResourceUrl, {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            didU,
            uri,
            nc,
            hE,
            Y: release.Y,
            h: release.h,
            hK: release.hK,
            nro: release.nro,
            nrr,
        }),
    });

    let responseJson = {};
    try {
        responseJson = await response.json();
    } catch {
        responseJson = {};
    }

    if (!response.ok) {
        throw new Error(responseJson.error || `TTP checkResource failed with status ${response.status}.`);
    }
    if (typeof responseJson.keyForDecrypt !== 'string') {
        throw new Error('The TTP did not release a key.');
    }

    return fromBase64Url(responseJson.keyForDecrypt);
}

function createDemoAppDocumentLoader(agentContext, currentDidDocument) {
    const fallbackLoader = defaultDocumentLoader(agentContext)

    return async (url) => {
        if (url === NON_REPUDIATION_CONTEXT_URL) {
            return {
                contextUrl: null,
                documentUrl: url,
                document: NON_REPUDIATION_CONTEXT,
            }
        }

        if (currentDidDocument) {
            const currentVerificationMethod = Array.isArray(currentDidDocument.verificationMethod)
                ? currentDidDocument.verificationMethod[0]
                : undefined

            if (url === currentDidDocument.id) {
                return {
                    contextUrl: null,
                    documentUrl: url,
                    document: currentDidDocument,
                }
            }

            if (currentVerificationMethod && url === currentVerificationMethod.id) {
                return {
                    contextUrl: null,
                    documentUrl: url,
                    document: {
                        '@context': 'https://w3id.org/security/suites/ed25519-2018/v1',
                        ...currentVerificationMethod,
                    },
                }
            }
        }

        return fallbackLoader(url)
    }
}

// NRR = sig(C, sk_A), issued as a credential whose subject is the CSS the resource comes from.
async function createNrrCredential(agent, didV, commitment) {
    const [appDidRecord] = await agent.dids.getCreatedDids({method: 'web', did: APP_DID})
    const currentDid = appDidRecord ?? (await agent.dids.getCreatedDids({method: 'web'}))[0]

    if (!currentDid?.didDocument) {
        throw new Error('Could not load the app DID document to issue the NRR credential.')
    }

    const verificationMethodId = currentDid.didDocument.verificationMethod?.[0]?.id
    if (typeof verificationMethodId !== 'string') {
        throw new Error('Could not determine the app verification method for the NRR credential.')
    }

    const suite = await createAppSignatureSuite(agent, currentDid.didDocument, verificationMethodId)
    const credential = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            NON_REPUDIATION_CONTEXT_URL,
        ],
        id: `urn:uuid:${crypto.randomUUID()}`,
        type: ['VerifiableCredential', APP_NRR_CREDENTIAL_TYPE],
        issuer: currentDid.didDocument.id,
        issuanceDate: toCompactW3cDate(new Date()),
        credentialSubject: {
            id: didV,
            signedHash: commitment,
        },
    }

    return await vc.issue({
        credential,
        suite,
        documentLoader: createDemoAppDocumentLoader(agent.context, currentDid.didDocument),
    })
}

async function createAppSignatureSuite(agent, didDocument, verificationMethodId) {
    const signatureSuiteRegistry = agent.dependencyManager.resolve(SignatureSuiteRegistry)
    const suiteInfo = signatureSuiteRegistry.getByProofType('Ed25519Signature2018')
    const WalletKeyPair = createWalletKeyPairClass(agent.context.wallet)
    const signingKey = await getKeyFromVerificationMethod(didDocument.verificationMethod[0])
    const keyPair = new WalletKeyPair({
        controller: didDocument.id,
        id: verificationMethodId,
        key: signingKey,
        wallet: agent.context.wallet,
    })

    const SuiteClass = suiteInfo.suiteClass
    return new SuiteClass({
        key: keyPair,
        LDKeyClass: WalletKeyPair,
        proof: {
            verificationMethod: verificationMethodId,
        },
        useNativeCanonize: false,
    })
}

function toCompactW3cDate(value) {
    return value.toISOString().replace(/\d{2}\.\d{3,}(?=Z$)/, (num) =>
        Number(num).toFixed(2).padStart(5, '0')
    )
}

// Verifies an NRO/NRR credential and extracts the commitment C it signs (credentialSubject.signedHash).
async function verifyCommitmentCredential(agent, signed) {
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
