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
    Key,
    ConsoleLogger, LogLevel,
    PeerDidNumAlgo,
    HttpOutboundTransport,
    KeyType, ConnectionEventTypes, DidExchangeState, TypedArrayEncoder, ProofEventTypes, ProofState, DidDocument,
    DifPresentationExchangeProofFormatService, JsonLdCredentialFormatService, JwaSignatureAlgorithm, DidDocumentBuilder,
    getEd25519VerificationKey2018, W3cCredentialsModule, CredentialEventTypes, SignatureSuiteRegistry,
    getEd25519VerificationKey2020, W3cJsonLdVerifiableCredential, CredentialState, W3cJsonLdVerifiablePresentation,
    JsonTransformer, W3cCredentialService, WebDidResolver, WalletKeyExistsError
} = require('@credo-ts/core')
const {
  defaultDocumentLoader
} = require('@credo-ts/core/build/modules/vc/data-integrity/libraries/documentLoader')
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
const {EnvelopeService} = require("@credo-ts/core/build/agent/EnvelopeService");
const issuerDid = process.env.ISSUER_DID || "did:web:secureissuer.solidcommunity.net:public";
const defaultHolderDid = process.env.DEMO_USER_SUBJECT_DID || "did:web:bboi.solidcommunity.net:public";

const ISSUER_DID = issuerDid

const ISSUER_VERIFICATION_FRAGMENT =
  process.env.ISSUER_VERIFICATION_FRAGMENT || 'z6MkhesMp8iSdumBExtuozsz3PYfapPpQUCarQA5uLcRee4d'

const ISSUER_PUBLIC_KEY_BASE58 =
  process.env.ISSUER_PUBLIC_KEY_BASE58 || '4CcKDtU1JNGi8U4D8Rv9CHzfmF7xzaxEAPFA54eQjRHF'

const ISSUER_KID =
  `${ISSUER_DID}#${ISSUER_VERIFICATION_FRAGMENT}`

const issuerDidDocument = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/ed25519-2018/v1'
  ],
  id: ISSUER_DID,
  verificationMethod: [
    {
      id: ISSUER_KID,
      type: 'Ed25519VerificationKey2018',
      controller: ISSUER_DID,
      publicKeyBase58: ISSUER_PUBLIC_KEY_BASE58
    }
  ],
  authentication: [ISSUER_KID],
  assertionMethod: [ISSUER_KID]
}

const getGenesisTransaction = async (url) => {
    const response = await fetch(url)
    return await response.text()
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

async function buildIssuerDidDocument(agent, did) {
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
        label: 'SecureIssuer',
        walletConfig: {
            id: sys_config.get('wallet.id'),//'SecureUserWalletNuovo',
            key: sys_config.get('wallet.key'),//'solidserver000000000000000000000',
        },
        endpoints: [endPoint],
        autoUpdateStorageOnStartup: true,
        logger: new ConsoleLogger(LogLevel.debug)
    }

    // A new instance of an agent is created here
    const agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet)
    })


    // Register a simple `WebSocket` outbound transport - not needed
    // agent.registerOutboundTransport(new WsOutboundTransport())

    // Register a simple `Http` outbound transport
    agent.registerOutboundTransport(new HttpOutboundTransport())

    // Register a simple `Http` inbound transport
    agent.registerInboundTransport(new HttpInboundTransport({port: 3011}))


    // Initialize the agent
    await agent.initialize()

    const { didDocument, verificationMethodId } = await buildIssuerDidDocument(agent, issuerDid)

    console.log(JSON.stringify(didDocument))

    await agent.dids.import({
        did: issuerDid,
        didDocument,
        overwrite: true,
    })

    return {
        agent,
        verificationMethodId,
    }
}

let agent
let startPromise
let issuerVerificationMethodId

async function startEverything() {
    if (agent) return agent
    const issuerState = await initializeIssuerAgent(sys_config.get('wallet.ledger_url'), sys_config.get('wallet.endpoint'));
    agent = issuerState.agent
    issuerVerificationMethodId = issuerState.verificationMethodId
    await activateListener(agent)
    return agent
}

async function ensureStarted() {
    if (agent) return agent
    if (!startPromise) {
        startPromise = startEverything().catch((error) => {
            startPromise = undefined
            throw error
        })
    }

    return startPromise
}

async function activateListener(agent) {
    agent.events.on(ConnectionEventTypes.ConnectionStateChanged, ({payload}) => {
        runAsyncTask('secure issuer connection state change', async () => {
            if (payload.connectionRecord.state !== DidExchangeState.Completed) return

            await agent.basicMessages.sendMessage(payload.connectionRecord.id, "Hello, we can start to communicate")

            await agent.credentials.offerCredential({
                connectionId: payload.connectionRecord.id,
                protocolVersion: 'v2',
                credentialFormats: {
                    jsonld: {
                        credential: {
                            "@context": [
                                "https://www.w3.org/2018/credentials/v1",
                                "https://www.w3.org/2018/credentials/examples/v1"
                            ],
                            id: 'https://example.com/credentials/321122',
                            type: ["VerifiableCredential", "ExampleDegreeCredential"],
                            issuer: issuerDid,
                            issuanceDate: "2010-01-01T19:23:24Z",
                            credentialSubject: {
                                "id": defaultHolderDid,
                                "degree": {
                                    "type": "ExampleBachelorDegree",
                                    "name": "Engineering"
                                }
                            },
                        },
                        options: {
                            proofPurpose: 'assertionMethod',
                            proofType: "Ed25519Signature2018"
                        }
                    }
                }
            })
        })
    })

    agent.events.on(CredentialEventTypes.CredentialStateChanged, ({payload}) => {
        runAsyncTask('secure issuer credential state change', async () => {
            if (payload.credentialRecord.state !== CredentialState.RequestReceived) return

            await agent.credentials.acceptRequest({
                credentialRecordId: payload.credentialRecord.id,
                credentialFormats: {
                    jsonld: {
                        verificationMethod: issuerVerificationMethodId,
                    }
                }
            })
        })
    })
}

const express = require('express');
const {randomUUID} = require("crypto");

const app = express();
const PORT = 8080;
ensureStarted().then(result => {
    /* Empty */
}).catch((error) => {
    console.error(error)
})
app.use(express.static('public'))
var bodyParser = require('body-parser');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.get('/', (req, res) => {
    res.status(200);
    //let url = `/index.html?user=${user}&application=${application}&vcissuer=${vcissuer}&nonce=${encodeURIComponent(nonce)}&domain=${domain}&redirect_uri=${redirect_uri}&code=${encodeURIComponent(code)}`;
    let url = 'index.html'
    res.redirect(url);
});

app.get('/generateInvitation', async (req, res) => {
    res.status(200);
    await ensureStarted();
    const outOfBandRecord = await agent.oob.createInvitation({
        autoAcceptConnection: true,
        handshake: true,
        invitationDid: issuerDid,
    })
    const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({domain: sys_config.get('wallet.endpoint')})
    let qrcode_png
    await QRCode.toDataURL(invitationUrl, {version: 22}).then(qrcode_generated => {
        qrcode_png = qrcode_generated
    })
    res.json({url: invitationUrl, connectionId: outOfBandRecord.id, qrcode: qrcode_png})
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

  return async (url) => {
    if (url === ISSUER_DID) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: issuerDidDocument
      }
    }

    if (url === ISSUER_KID) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: {
          '@context': issuerDidDocument['@context'],
          ...issuerDidDocument.verificationMethod[0]
        }
      }
    }

    return fallbackLoader(url)
  }
}

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
  documentLoader: customDocumentLoader
}),
    }
}
