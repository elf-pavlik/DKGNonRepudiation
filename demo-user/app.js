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
    HttpOutboundTransport,
    KeyType, ConnectionEventTypes, DidExchangeState, TypedArrayEncoder, ProofEventTypes, ProofState,
    DifPresentationExchangeProofFormatService, JsonLdCredentialFormatService, DidDocumentBuilder,
    getEd25519VerificationKey2018, W3cCredentialsModule, CredentialEventTypes, WebDidResolver, DidCommV1Service, ConsoleLogger,
    LogLevel, WalletKeyExistsError
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
const sys_config = require('config');
const QRCode = require('qrcode')
const http = require('http')
const fs = require('fs')
const path = require('path')

const {agentDependencies, HttpInboundTransport} = require('@credo-ts/node')
const {IndyVdrIndyDidResolver, IndyVdrAnonCredsRegistry, IndyVdrModule} = require('@credo-ts/indy-vdr')
const {indyVdr} = require('@hyperledger/indy-vdr-nodejs')
const {ariesAskar} = require('@hyperledger/aries-askar-nodejs')
const {AskarModule} = require('@credo-ts/askar')
const {anoncreds} = require('@hyperledger/anoncreds-nodejs')
const {AnonCredsRsModule} = require('@credo-ts/anoncreds')
const {defaultDocumentLoader} = require('@credo-ts/core/build/modules/vc/data-integrity/libraries/documentLoader')
const getGenesisTransaction = async (url) => {
    const response = await fetch(url)
    return await response.text()
}
const holderPublicDid = process.env.DEMO_USER_PUBLIC_DID || 'did:web:bboi.solidcommunity.net:public'
let holderDidDocumentJson
let holderVerificationMethodId

function normalizeHostInvitationUrl(invitationUrl) {
    console.log("Normalizing invitation URL: " + invitationUrl)
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

let current_connection = {
    label: undefined,
    did: undefined,
    connection_id: undefined
}

let walletAgent
const walletState = {
    ready: false,
    did: undefined,
    currentConnection: current_connection,
    activities: [],
    credentialOffers: {},
    proofRequests: {},
}

function addActivity(type, message, details = undefined) {
    walletState.activities.unshift({
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        type,
        message,
        details,
        createdAt: new Date().toISOString(),
    })
    walletState.activities = walletState.activities.slice(0, 50)
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

async function requestCredentialFromSecureIssuer(agent, issuerBaseUrl) {
    const invitationEndpoint = new URL('/generateInvitation', issuerBaseUrl).toString()
    const response = await fetch(invitationEndpoint)

    let responseJson = {}
    try {
        responseJson = await response.json()
    } catch (error) {
        responseJson = {}
    }

    if (!response.ok) {
        throw new Error(responseJson.error || `Issuer request failed with status ${response.status}.`)
    }

    if (!responseJson.url) {
        throw new Error('Issuer did not provide an invitation URL.')
    }

    const normalizedInvitationUrl = normalizeHostInvitationUrl(responseJson.url)
    const invitation = await agent.oob.receiveInvitationFromUrl(normalizedInvitationUrl)

    addActivity('issuer-request', 'Credential requested from secure issuer.', {
        issuerBaseUrl,
        connectionId: invitation?.connectionRecord?.id,
        invitationUrl: responseJson.url,
        normalizedInvitationUrl,
    })

    return {
        connectionId: invitation?.connectionRecord?.id,
        invitationUrl: responseJson.url,
        normalizedInvitationUrl,
    }
}

function snapshotConnection(connectionRecord) {
    if (!connectionRecord) {
        return {
            id: undefined,
            did: undefined,
            invitationDid: undefined,
            label: undefined,
        }
    }

    return {
        id: connectionRecord.id,
        did: connectionRecord.did,
        invitationDid: connectionRecord.invitationDid,
        label: connectionRecord.theirLabel,
    }
}

function getCredentialSummary(credential) {
    const types = Array.isArray(credential?.type) ? credential.type.filter((type) => type !== 'VerifiableCredential') : []
    const issuer = typeof credential?.issuer === 'string' ? credential.issuer : credential?.issuer?.id
    const subject = Array.isArray(credential?.credentialSubject)
        ? credential.credentialSubject[0]
        : credential?.credentialSubject

    return {
        issuer,
        types,
        subject,
    }
}

function getCredentialSubjectId(credential) {
    const subject = Array.isArray(credential?.credentialSubject)
        ? credential.credentialSubject[0]
        : credential?.credentialSubject

    return subject?.id
}

function sortByCreatedAtDescending(left, right) {
    const leftTimestamp = new Date(left?.createdAt ?? 0).getTime()
    const rightTimestamp = new Date(right?.createdAt ?? 0).getTime()
    return rightTimestamp - leftTimestamp
}

function serializeStoredCredential(record) {
    const credential = record?.credential
    const summary = getCredentialSummary(credential)

    return {
        id: record.id,
        recordId: record.id,
        credentialId: credential?.id,
        claimFormat: credential?.claimFormat,
        issuer: summary.issuer,
        types: summary.types,
        subjectId: getCredentialSubjectId(credential),
        summary,
        createdAt: record.createdAt,
        credential,
    }
}

async function getWalletSnapshot(agent) {
    const credentialRecords = agent
        ? await agent.w3cCredentials.getAllCredentialRecords()
        : []

    const credentials = credentialRecords
        .slice()
        .sort(sortByCreatedAtDescending)
        .map(serializeStoredCredential)

    return {
        ...walletState,
        credentials,
        stats: {
            credentials: credentials.length,
            pendingOffers: Object.keys(walletState.credentialOffers).length,
            pendingProofs: Object.keys(walletState.proofRequests).length,
            activities: walletState.activities.length,
        },
        updatedAt: new Date().toISOString(),
    }
}

async function buildProofRequestState(agent, proofRecord) {
    const proofRecordId = proofRecord.id
    const formatData = await agent.proofs.getFormatData(proofRecordId)

    return {
        id: proofRecordId,
        connection: snapshotConnection({
            id: proofRecord.connectionId,
            did: current_connection.did,
            invitationDid: current_connection.invitationDid,
            theirLabel: current_connection.label,
        }),
        acpRequest: getACPRequest(formatData),
        areRequirementsSatisfied: false,
        requirements: [],
        availableCredentials: [],
        isLoadingCredentials: true,
        credentialsLoadError: undefined,
        createdAt: new Date().toISOString(),
    }
}

async function loadProofRequestCredentials(agent, proofRecordId) {
    const credentialsForRequest = await agent.proofs.getCredentialsForRequest({
        proofRecordId,
    })
    const presentationExchange = credentialsForRequest.proofFormats.presentationExchange
    const availableCredentialsById = {}

    for (const requirement of presentationExchange.requirements) {
        for (const submissionEntry of requirement.submissionEntry) {
            for (const credentialEntry of submissionEntry.verifiableCredentials) {
                const credentialRecord = credentialEntry.credentialRecord
                const credentialSubjectId = getCredentialSubjectId(credentialRecord.credential)

                if (credentialSubjectId && credentialSubjectId !== holderPublicDid) {
                    continue
                }

                const existing = availableCredentialsById[credentialRecord.id]
                const descriptor = {
                    id: submissionEntry.inputDescriptorId,
                    name: submissionEntry.name,
                    purpose: submissionEntry.purpose,
                }

                if (existing) {
                    existing.descriptors.push(descriptor)
                    continue
                }

                availableCredentialsById[credentialRecord.id] = {
                    id: credentialRecord.id,
                    type: credentialEntry.type,
                    credential: credentialRecord.credential,
                    summary: getCredentialSummary(credentialRecord.credential),
                    descriptors: [descriptor],
                }
            }
        }
    }

    return {
        areRequirementsSatisfied: presentationExchange.areRequirementsSatisfied,
        requirements: presentationExchange.requirements.map((requirement) => ({
            name: requirement.name,
            purpose: requirement.purpose,
            needsCount: requirement.needsCount,
            rule: requirement.rule,
            isRequirementSatisfied: requirement.isRequirementSatisfied,
            submissionEntry: requirement.submissionEntry.map((entry) => ({
                inputDescriptorId: entry.inputDescriptorId,
                name: entry.name,
                purpose: entry.purpose,
                credentialIds: entry.verifiableCredentials.map((credentialEntry) => credentialEntry.credentialRecord.id),
            })),
        })),
        availableCredentials: Object.values(availableCredentialsById),
        isLoadingCredentials: false,
        credentialsLoadError: undefined,
    }
}

async function buildProofAcceptanceFormats(agent, proofRecordId, credentialRecordId) {
    const selectedCredentials = await agent.proofs.selectCredentialsForRequest({
        proofRecordId,
    })
    const selectedProofFormats = selectedCredentials.proofFormats
    const selectedPresentationExchange = selectedProofFormats?.presentationExchange

    if (!selectedPresentationExchange?.credentials) {
        return selectedProofFormats
    }

    const credentialsForRequest = await agent.proofs.getCredentialsForRequest({
        proofRecordId,
    })

    let matched = false
    for (const requirement of credentialsForRequest.proofFormats.presentationExchange.requirements) {
        for (const submissionEntry of requirement.submissionEntry) {
            const selectedCredential = submissionEntry.verifiableCredentials.find(
                (credentialEntry) => credentialEntry.credentialRecord.id === credentialRecordId
            )

            if (!selectedCredential) continue

            const selectedCredentialSubjectId = getCredentialSubjectId(selectedCredential.credentialRecord.credential)
            if (selectedCredentialSubjectId && selectedCredentialSubjectId !== holderPublicDid) {
                throw new Error(
                    `Selected credential subject ${selectedCredentialSubjectId} does not match wallet DID ${holderPublicDid}.`
                )
            }

            selectedPresentationExchange.credentials[submissionEntry.inputDescriptorId] = [selectedCredential.credentialRecord]
            matched = true
        }
    }

    if (!matched) {
        throw new Error('Selected credential does not satisfy this proof request.')
    }

    return selectedProofFormats
}

async function buildHolderDidDocument(agent, did) {
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

const initializeUserAgentWeb = async (ledgerUrl, endPoint) => {

    const genesisTransactionsBCovrinTestNet = await getGenesisTransaction(ledgerUrl)

    const config = {
        label: 'SecureUserWallettttt',
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
    agent.registerOutboundTransport(new WsOutboundTransport())

    // Register a simple `Http` outbound transport
    agent.registerOutboundTransport(new HttpOutboundTransport())

    // Register a simple `Http` inbound transport
    agent.registerInboundTransport(new HttpInboundTransport({port: 3006}))


    // Initialize the agent
    await agent.initialize()


    const { didDocument, verificationMethodId } = await buildHolderDidDocument(agent, holderPublicDid)

    holderVerificationMethodId = verificationMethodId
    holderDidDocumentJson = didDocument.toJSON()
    walletState.did = holderPublicDid

    console.log(JSON.stringify(holderDidDocumentJson))

    await agent.dids.import({
        did: holderPublicDid,
        didDocument,
        overwrite: true,
    })


    return agent
}


async function startEverything() {
    console.log("Welcome to your wallet")
    const agent = await initializeUserAgentWeb(sys_config.get('wallet.ledger_url'), sys_config.get('wallet.endpoint'));
    walletAgent = agent
    walletState.ready = true
    await setUpListners(agent)
    startWalletWebApp(agent)
    addActivity('ready', 'Wallet ready. Submit an invitation URL from the web console.')

}

async function setUpListners(agent) {
    agent.events.on(ConnectionEventTypes.ConnectionStateChanged, ({payload}) => {
        runAsyncTask('wallet connection state change', async () => {
            console.log(payload)
            if (payload.connectionRecord.state !== DidExchangeState.Completed) return

            current_connection.id = payload.connectionRecord.id
            current_connection.did = payload.connectionRecord.did
            current_connection.label = payload.connectionRecord.theirLabel
            current_connection.invitationDid = payload.connectionRecord.invitationDid
            walletState.currentConnection = current_connection
            addActivity('connection-ready', 'Connection completed.', snapshotConnection(payload.connectionRecord))
        })
    })

    agent.events.on(CredentialEventTypes.CredentialStateChanged, ({payload}) => {
        runAsyncTask('wallet credential state change', async () => {
            const status = payload.credentialRecord.state
            const credentialRecordId = payload.credentialRecord.id

            if (status === "offer-received") {
                console.log("You are going to receive these credentials: ")
                const formatData = await agent.credentials.getFormatData(credentialRecordId)
                const credential = formatData.offer.jsonld.credential
                console.log(JSON.stringify(credential, undefined, 2))
                walletState.credentialOffers[credentialRecordId] = {
                    id: credentialRecordId,
                    recordId: credentialRecordId,
                    credentialId: credential?.id,
                    connectionId: payload.credentialRecord.connectionId,
                    state: status,
                    credential,
                    createdAt: new Date().toISOString(),
                }
                addActivity('credential-offer', 'Credential offer received.', walletState.credentialOffers[credentialRecordId])
            }

            if (status === "credential-received") {
                await agent.credentials.acceptCredential({credentialRecordId})
                delete walletState.credentialOffers[credentialRecordId]
                addActivity('credential-received', 'Credential received and stored.', {credentialRecordId})
            }
        })
    })

    agent.events.on(ProofEventTypes.ProofStateChanged, ({payload}) => {
        runAsyncTask('wallet proof state change', async () => {
            const proofRecordId = payload.proofRecord.id
            const status = payload.proofRecord.state
            if (status !== ProofState.RequestReceived) return

            console.clear()
            console.log(
                "I received the following VPR (Connection Record: " +
                    current_connection.id +
                    " with DID " +
                    current_connection.invitationDid +
                    " and label " +
                    current_connection.label +
                    "): "
            )

            const proofRequestState = await buildProofRequestState(agent, payload.proofRecord)
            walletState.proofRequests[proofRecordId] = proofRequestState
            addActivity('proof-request', 'Proof request received.', proofRequestState)

            runAsyncTask('wallet proof credential lookup', async () => {
                try {
                    const credentialDetails = await loadProofRequestCredentials(agent, proofRecordId)
                    const currentProofState = walletState.proofRequests[proofRecordId]
                    if (!currentProofState) return

                    for (const availableCredential of credentialDetails.availableCredentials) {
                        console.log("cred_ex_id: " + availableCredential.id)
                        console.log(JSON.stringify(availableCredential.credential, undefined, 2))
                    }

                    walletState.proofRequests[proofRecordId] = {
                        ...currentProofState,
                        ...credentialDetails,
                    }
                    addActivity('proof-credentials-ready', 'Wallet checked credentials for the proof request.', {
                        proofRecordId,
                        availableCredentials: credentialDetails.availableCredentials.length,
                        areRequirementsSatisfied: credentialDetails.areRequirementsSatisfied,
                    })
                } catch (error) {
                    const currentProofState = walletState.proofRequests[proofRecordId]
                    if (!currentProofState) return

                    walletState.proofRequests[proofRecordId] = {
                        ...currentProofState,
                        isLoadingCredentials: false,
                        credentialsLoadError: error.message,
                    }
                    addActivity('proof-credentials-error', 'Wallet could not load matching credentials for the proof request.', {
                        proofRecordId,
                        error: error.message,
                    })
                    console.error(`[wallet proof credential lookup] ${error.stack || error.message}`)
                }
            })
        })
    })
}


async function receiveConnectionRequest(invitationUrl) {
    this.agent.connections
    const {connectionRecord} = await this.agent.oob.receiveInvitationFromUrl(invitationUrl, {
        ourDid: 'did:web:bboi.solidcommunity.net:public'
    })
    return connectionRecord
}

// Replaces only genuine cycles (an object that is its own ancestor along the current path) with
// '[Circular]', tracked via a path stack - not a "seen anywhere in the whole tree" set, which
// would (and did) wrongly flag the same object reference appearing twice in a DAG (e.g. the same
// acpRequest object attached to both an activity log entry and the live proof record) as circular,
// blanking out perfectly valid, non-circular data.
function decycle(value, ancestors) {
    if (typeof value === 'bigint') return value.toString()
    if (value === null || typeof value !== 'object') return value
    if (ancestors.includes(value)) return '[Circular]'

    ancestors.push(value)
    let result
    if (Array.isArray(value)) {
        result = value.map((item) => decycle(item, ancestors))
    } else {
        result = {}
        for (const key of Object.keys(value)) {
            result[key] = decycle(value[key], ancestors)
        }
    }
    ancestors.pop()
    return result
}

function sendJson(res, statusCode, data) {
    res.writeHead(statusCode, {'Content-Type': 'application/json'})
    res.end(JSON.stringify(decycle(data, [])))
}

async function readJsonBody(req) {
    const chunks = []
    for await (const chunk of req) {
        chunks.push(chunk)
    }
    const rawBody = Buffer.concat(chunks).toString('utf8')
    return rawBody ? JSON.parse(rawBody) : {}
}

function serveStaticFile(res, filePath) {
    const ext = path.extname(filePath)
    const contentTypes = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
    }
    fs.readFile(filePath, (error, content) => {
        if (error) {
            sendJson(res, 404, {error: 'Not found'})
            return
        }
        res.writeHead(200, {'Content-Type': contentTypes[ext] || 'application/octet-stream'})
        res.end(content)
    })
}

function startWalletWebApp(agent) {
    const publicDir = path.join(__dirname, 'public')
    const port = Number(process.env.WALLET_WEB_PORT || 3007)
    const secureIssuerApiBase = process.env.SECURE_ISSUER_API_BASE || 'http://secure-issuer:8080'

    const server = http.createServer(async (req, res) => {
        try {
            const requestUrl = new URL(req.url, `http://${req.headers.host}`)

            if (req.method === 'GET' && requestUrl.pathname === '/api/state') {
                sendJson(res, 200, await getWalletSnapshot(agent))
                return
            }

            if (req.method === 'POST' && requestUrl.pathname === '/api/invitations') {
                const {invitationUrl} = await readJsonBody(req)
                if (!invitationUrl) {
                    sendJson(res, 400, {error: 'invitationUrl is required'})
                    return
                }
                const normalizedInvitationUrl = normalizeHostInvitationUrl(invitationUrl)
                const invitation = await agent.oob.receiveInvitationFromUrl(normalizedInvitationUrl)
                addActivity('invitation', 'Invitation URL received.', {
                    connectionId: invitation?.connectionRecord?.id,
                    invitationUrl,
                    normalizedInvitationUrl,
                })
                sendJson(res, 200, {
                    ok: true,
                    connectionId: invitation?.connectionRecord?.id,
                })
                return
            }

            if (req.method === 'POST' && requestUrl.pathname === '/api/issuer/request-credential') {
                const requestBody = await readJsonBody(req)
                const issuerBaseUrl = requestBody.issuerBaseUrl || secureIssuerApiBase
                const result = await requestCredentialFromSecureIssuer(agent, issuerBaseUrl)

                sendJson(res, 200, {
                    ok: true,
                    issuerBaseUrl,
                    ...result,
                })
                return
            }

            const credentialMatch = requestUrl.pathname.match(/^\/api\/credentials\/([^/]+)\/(accept|decline)$/)
            if (req.method === 'POST' && credentialMatch) {
                const [, credentialRecordId, action] = credentialMatch
                if (!credentialRecordId || credentialRecordId === 'undefined') {
                    sendJson(res, 400, {error: 'credentialRecordId is required'})
                    return
                }
                if (action === 'accept') {
                    await agent.credentials.acceptOffer({credentialRecordId})
                    addActivity('credential-accepted', 'Credential offer accepted.', {credentialRecordId})
                } else {
                    await agent.credentials.declineOffer(credentialRecordId)
                    addActivity('credential-declined', 'Credential offer declined.', {credentialRecordId})
                }
                delete walletState.credentialOffers[credentialRecordId]
                sendJson(res, 200, {ok: true})
                return
            }

            const proofMatch = requestUrl.pathname.match(/^\/api\/proofs\/([^/]+)\/(accept|decline)$/)
            if (req.method === 'POST' && proofMatch) {
                const [, proofRecordId, action] = proofMatch
                if (action === 'accept') {
                    const {credentialRecordId} = await readJsonBody(req)
                    if (!credentialRecordId) {
                        sendJson(res, 400, {error: 'credentialRecordId is required'})
                        return
                    }
                    const proofFormats = await buildProofAcceptanceFormats(agent, proofRecordId, credentialRecordId)
                    await agent.proofs.acceptRequest({
                        proofRecordId,
                        proofFormats,
                    })
                    addActivity('proof-accepted', 'Proof request accepted.', {proofRecordId, credentialRecordId})
                } else {
                    await agent.proofs.declineRequest({
                        proofRecordId,
                        problemReportDescription: "I don't want to exchange these credentials.",
                    })
                    addActivity('proof-declined', 'Proof request declined.', {proofRecordId})
                }
                delete walletState.proofRequests[proofRecordId]
                sendJson(res, 200, {ok: true})
                return
            }

            const safePath = requestUrl.pathname === '/' ? '/index.html' : requestUrl.pathname
            const filePath = path.normalize(path.join(publicDir, safePath))
            if (!filePath.startsWith(publicDir)) {
                sendJson(res, 403, {error: 'Forbidden'})
                return
            }
            serveStaticFile(res, filePath)
        } catch (error) {
            console.error(error)
            sendJson(res, 500, {error: error.message})
        }
    })

    server.listen(port, () => {
        console.log(`Wallet web console is running on port ${port}`)
    })
}

startEverything();


const {randomUUID} = require("crypto");

function getACPRequest(e) {
    let presExchange = e.request.presentationExchange;
    let acpContext = presExchange.presentation_definition.requestACP;
    const normalizedContext = acpContext.type[0] !== "NonRepudiableACPContext"
        ? acpContext
        : acpContext.definedACPContext

    console.log("ACP Policy:")
    console.log("For the target: " + normalizedContext.target + " with the client (app): " + normalizedContext.client)

    return {
        type: acpContext.type,
        target: normalizedContext.target,
        client: normalizedContext.client,
        agent: normalizedContext.agent,
        owner: normalizedContext.owner,
        issuer: normalizedContext.issuer,
        creator: normalizedContext.creator,
        raw: acpContext,
    }
}
function getAskarAnonCredsIndyModules(genesisTransactionsBCovrinTestNet) {
    const legacyIndyCredentialFormatService = new LegacyIndyCredentialFormatService()
    const legacyIndyProofFormatService = new LegacyIndyProofFormatService()
    const customDocumentLoader = (agentContext) => {
        const fallbackLoader = defaultDocumentLoader(agentContext)

        return async (url) => {
            if (holderDidDocumentJson && url === holderPublicDid) {
                return {
                    contextUrl: null,
                    documentUrl: url,
                    document: holderDidDocumentJson,
                }
            }

            if (holderDidDocumentJson && holderVerificationMethodId && url === holderVerificationMethodId) {
                return {
                    contextUrl: null,
                    documentUrl: url,
                    document: {
                        '@context': holderDidDocumentJson['@context'],
                        ...holderDidDocumentJson.verificationMethod[0],
                    },
                }
            }

            return fallbackLoader(url)
        }
    }

    return {
        connections: new ConnectionsModule({
            autoAcceptConnections: true,
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
