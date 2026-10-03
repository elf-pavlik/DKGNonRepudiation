const searchBar = document.querySelector('#searchBar');
const getBtn = document.querySelector('#getBtn');
const responseArea = document.querySelector('#responseArea');
const invitationContainer = document.querySelector('#invitation');
let connectInvitationButton = document.querySelector('#connectInvitationButton');
let invitationAssistMessage = document.querySelector('#invitationAssistMessage');
const labelLoader = document.querySelector('.label-loader');
const loader = document.querySelector('.loader');
const resourceStage = document.querySelector('#resourceStage');
const resourceStateLabel = document.querySelector('#resourceStateLabel');
const resourceOverlay = document.querySelector('#resourceOverlay');
const resourceOverlayEyebrow = document.querySelector('#resourceOverlayEyebrow');
const resourceOverlayTitle = document.querySelector('#resourceOverlayTitle');
const resourceOverlayMessage = document.querySelector('#resourceOverlayMessage');
const auditGraphStatus = document.querySelector('#auditGraphStatus');
const auditGraphRecords = document.querySelector('#auditGraphRecords');
const auditGraphCount = document.querySelector('#auditGraphCount');
const refreshAuditGraphButton = document.querySelector('#refreshAuditGraphButton');
const appBaseUrl = window.location.origin;
let appName;
let user;
let issuer;
let resourceRevealTimeoutId;
let auditGraphRequestId = 0;

//VP may be in the URL parameters after redirecting from User to App
let params = new URLSearchParams(location.search);
const USER_WALLET_EXTENSION_ID = 'migfelocbajkglnebkgkliphjomnfnik';
const USER_WALLET_EXTENSION_URL = `chrome-extension://${USER_WALLET_EXTENSION_ID}/popup.html`;
const WORKFLOW_STEP_ORDER = ['request', 'login', 'approve', 'view'];
const workflowSteps = new Map(
    Array.from(document.querySelectorAll('.workflow-step')).map((stepElement) => [stepElement.dataset.step, stepElement])
);
const RESOURCE_LOCKED_PLACEHOLDER = [
    'Protected patient file preview',
    '',
    'Access is granted only after SSI login and credential approval.',
    '',
    'The content will appear here once the secure exchange is completed.'
].join('\n');

function buildWalletExtensionUrl(invitationUrl) {
    const query = new URLSearchParams({
        invitationUrl,
        autoConnect: '1',
    });
    return `${USER_WALLET_EXTENSION_URL}?${query.toString()}`;
}

function delay(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function buildFormBody(payload) {
    const searchParams = new URLSearchParams();

    Object.entries(payload).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
            searchParams.append(key, value);
        }
    });

    return searchParams.toString();
}

async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);

    if (!response.ok) {
        const errorMessage = await response.text().catch(() => '');
        throw new Error(errorMessage || `Request failed with status ${response.status}.`);
    }

    return await response.json();
}

async function fetchJsonBody(url, options = {}) {
    const response = await fetch(url, options);
    const responseText = await response.text();

    if (!responseText) {
        return {
            ok: response.ok,
            status: response.status,
            headers: response.headers,
            data: undefined,
        };
    }

    try {
        return {
            ok: response.ok,
            status: response.status,
            headers: response.headers,
            data: JSON.parse(responseText),
        };
    } catch (error) {
        if (!response.ok) {
            throw new Error(responseText || `Request failed with status ${response.status}.`);
        }

        throw new Error('The server returned an invalid JSON response.');
    }
}

function parseDidcommAuthenticateHeader(wwwAuthenticateHeader) {
    if (!wwwAuthenticateHeader) {
        return {};
    }

    const headerValue = wwwAuthenticateHeader.replace(/^\s*didcomm\b/i, '');
    const params = {};
    const parameterPattern = /([A-Za-z][A-Za-z0-9_-]*)=(?:"([^"]*)"|([^,\s]+))/g;
    let match;

    while ((match = parameterPattern.exec(headerValue)) !== null) {
        const [, key, quotedValue, rawValue] = match;
        params[key] = quotedValue ?? rawValue;
    }

    if (!params.invitationUrl) {
        const urlMatch = wwwAuthenticateHeader.match(/\b(?:https?|didcomm):\/\/\S+/i);
        params.invitationUrl = urlMatch?.[0]?.replace(/[;,]+$/, '');
    }

    return params;
}

function deserializeProofRequest(serializedProofRequest) {
    if (!serializedProofRequest) {
        return undefined;
    }

    try {
        return JSON.parse(serializedProofRequest);
    } catch (error) {
        const normalized = serializedProofRequest.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
        const decoded = atob(normalized + padding);
        return JSON.parse(decoded);
    }
}

function buildProofRequestPayload(proofRequest, serializedProofRequest, connectionId, extraFields = {}) {
    const requestAcp = proofRequest.presentation_definition?.requestACP ?? {};
    const payload = {
        challenge: proofRequest.options?.challenge,
        domain: proofRequest.options?.domain,
        target: requestAcp.target,
        owner: requestAcp.owner,
        issuer: requestAcp.issuer,
        creator: requestAcp.creator,
        client: requestAcp.client,
        agent: requestAcp.agent,
        connectionId,
        ...extraFields,
    };

    if (proofRequest.presentation_definition?.input_descriptors) {
        payload.input_descriptors = JSON.stringify(proofRequest.presentation_definition.input_descriptors);
    }

    if (serializedProofRequest) {
        payload.vpr = serializedProofRequest;
    }

    return payload;
}

async function postFormJson(url, payload) {
    return await fetchJson(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        },
        body: buildFormBody(payload),
    });
}

function formatResourceContent(content) {
    if (typeof content === 'string') {
        return content;
    }

    return JSON.stringify(content, null, 2);
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function truncateMiddle(value, start = 18, end = 12) {
    const normalizedValue = String(value ?? '');
    if (normalizedValue.length <= start + end + 1) {
        return normalizedValue;
    }

    return `${normalizedValue.slice(0, start)}…${normalizedValue.slice(-end)}`;
}

function formatAuditDate(value) {
    if (!value) {
        return 'Unknown time';
    }

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return new Intl.DateTimeFormat('it-IT', {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(date);
}

function formatDidOrUri(value) {
    if (!value) {
        return 'Not available';
    }

    const stringValue = String(value);
    try {
        const parsedUrl = new URL(stringValue);
        const lastPathSegment = parsedUrl.pathname
            .split('/')
            .filter(Boolean)
            .pop();
        return lastPathSegment || parsedUrl.hostname;
    } catch (error) {
        return truncateMiddle(stringValue, 16, 10);
    }
}

function buildAuditQueryUrl({requestedResource}) {
    const url = new URL('/.internal/nro-audit/query', appBaseUrl);
    const normalizedResource = requestedResource?.trim();

    if (normalizedResource) {
        url.searchParams.set('resource', normalizedResource);
    }

    return url.toString();
}

function setAuditGraphStatus(message, tone = 'neutral') {
    auditGraphStatus.textContent = message;
    auditGraphStatus.dataset.tone = tone;
}

function setAuditGraphCountLabel(label) {
    auditGraphCount.textContent = label;
}

function getCredentialTypes(credential) {
    const types = credential?.type;
    if (Array.isArray(types)) {
        return types.filter((value) => typeof value === 'string' && value !== 'VerifiableCredential');
    }

    if (typeof types === 'string' && types !== 'VerifiableCredential') {
        return [types];
    }

    return [];
}

function getPrimaryCredentialSubject(credential) {
    const credentialSubject = credential?.credentialSubject;
    if (credentialSubject && !Array.isArray(credentialSubject) && typeof credentialSubject === 'object') {
        return credentialSubject;
    }

    if (Array.isArray(credentialSubject)) {
        return credentialSubject.find((subject) => subject && typeof subject === 'object') ?? credentialSubject[0];
    }

    return undefined;
}

function getCredentialSubjectId(credential) {
    const credentialSubject = getPrimaryCredentialSubject(credential);
    return typeof credentialSubject?.id === 'string' ? credentialSubject.id : undefined;
}

function getCredentialVerificationMethod(credential) {
    const proof = Array.isArray(credential?.proof) ? credential.proof[0] : credential?.proof;
    return typeof proof?.verificationMethod === 'string' ? proof.verificationMethod : undefined;
}

function getPrimaryProof(credential) {
    const proof = credential?.proof;
    if (proof && !Array.isArray(proof) && typeof proof === 'object') {
        return proof;
    }

    if (Array.isArray(proof)) {
        return proof.find((entry) => entry && typeof entry === 'object') ?? proof[0];
    }

    return undefined;
}

function buildAuditChipMarkup(values, fallbackLabel) {
    if (!values.length) {
        return `<span class="audit-chip">${escapeHtml(fallbackLabel)}</span>`;
    }

    return values
        .map((value) => `<span class="audit-chip">${escapeHtml(value)}</span>`)
        .join('');
}

function buildAuditGraphSvg(record) {
    const nroCredential = record.nro ?? {};
    const issuerDid = record.issuerDid ?? nroCredential.issuer;
    const subjectDid = getCredentialSubjectId(nroCredential) ?? record.requesterDid;
    const signedHash = nroCredential.signedHash ?? record.messageHash;
    const verificationMethod = getCredentialVerificationMethod(nroCredential) ?? record.signerKid;
    const nroType = getCredentialTypes(nroCredential)[0] ?? 'NonRepudiableOrigin';

    const nodes = [
        {
            id: 'issuer',
            label: 'Issuer',
            title: 'Credential Issuer',
            subtitle: formatDidOrUri(issuerDid),
            fullValue: issuerDid,
            variant: 'identity',
            x: 170,
            y: 40,
        },
        {
            id: 'subject',
            label: 'Subject',
            title: 'Credential Subject',
            subtitle: formatDidOrUri(subjectDid),
            fullValue: subjectDid,
            variant: 'identity',
            x: 60,
            y: 142,
        },
        {
            id: 'nro',
            label: 'NRO VC',
            title: 'NonRepudiableOrigin VC',
            subtitle: nroType,
            fullValue: JSON.stringify(nroCredential),
            variant: 'nro',
            x: 170,
            y: 142,
        },
        {
            id: 'hash',
            label: 'Hash',
            title: 'Signed Hash',
            subtitle: truncateMiddle(signedHash, 10, 8),
            fullValue: signedHash,
            variant: 'hash',
            x: 280,
            y: 142,
        },
        {
            id: 'proof',
            label: 'Proof',
            title: 'Verification Method',
            subtitle: formatDidOrUri(verificationMethod),
            fullValue: verificationMethod,
            variant: 'proof',
            x: 170,
            y: 242,
        },
    ];

    const nodeById = new Map(nodes.map((node) => [node.id, node]));
    const edges = [
        {from: 'issuer', to: 'nro', label: 'issuedBy', labelX: 180, labelY: 88},
        {from: 'subject', to: 'nro', label: 'subject', labelX: 105, labelY: 126},
        {from: 'nro', to: 'hash', label: 'signedHash', labelX: 218, labelY: 126},
        {from: 'nro', to: 'proof', label: 'proof', labelX: 183, labelY: 198},
    ];

    return `
        <svg class="audit-graph-svg" viewBox="0 0 340 282" role="img" aria-label="NRO knowledge graph for audit record ${escapeHtml(record.id)}">
            ${edges.map((edge) => {
                const from = nodeById.get(edge.from);
                const to = nodeById.get(edge.to);
                return `
                    <line class="audit-graph-link" x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}"></line>
                    <text class="audit-graph-label" x="${edge.labelX}" y="${edge.labelY}">${escapeHtml(edge.label)}</text>
                `;
            }).join('')}
            ${nodes.map((node) => `
                <g class="audit-graph-node audit-graph-node--${node.variant}">
                    <title>${escapeHtml(`${node.title}: ${node.fullValue ?? 'Not available'}`)}</title>
                    <circle cx="${node.x}" cy="${node.y}" r="${node.id === 'nro' ? 36 : 28}"></circle>
                    <text x="${node.x}" y="${node.y - 4}">
                        <tspan x="${node.x}" dy="0">${escapeHtml(node.label)}</tspan>
                        <tspan x="${node.x}" dy="12">${escapeHtml(truncateMiddle(node.subtitle, 11, 8))}</tspan>
                    </text>
                </g>
            `).join('')}
        </svg>
    `;
}

function buildProofGraphSvg(record) {
    const nroCredential = record.nro ?? {};
    const proof = getPrimaryProof(nroCredential) ?? {};
    const verificationMethod = typeof proof?.verificationMethod === 'string'
        ? proof.verificationMethod
        : record.signerKid;
    const proofPurpose = typeof proof?.proofPurpose === 'string'
        ? proof.proofPurpose
        : 'assertionMethod';
    const proofCreated = typeof proof?.created === 'string'
        ? proof.created
        : record.verifiedAt;
    const proofType = typeof proof?.type === 'string'
        ? proof.type
        : 'Linked Data Proof';
    const proofJws = typeof proof?.jws === 'string'
        ? proof.jws
        : undefined;

    const nodes = [
        {
            id: 'proof',
            label: 'Proof',
            title: 'Credential Proof',
            subtitle: proofType,
            fullValue: JSON.stringify(proof),
            variant: 'proof',
            x: 170,
            y: 54,
        },
        {
            id: 'method',
            label: 'Method',
            title: 'Verification Method',
            subtitle: formatDidOrUri(verificationMethod),
            fullValue: verificationMethod,
            variant: 'identity',
            x: 62,
            y: 168,
        },
        {
            id: 'purpose',
            label: 'Purpose',
            title: 'Proof Purpose',
            subtitle: proofPurpose,
            fullValue: proofPurpose,
            variant: 'meta',
            x: 170,
            y: 168,
        },
        {
            id: 'created',
            label: 'Created',
            title: 'Proof Creation Time',
            subtitle: formatAuditDate(proofCreated),
            fullValue: proofCreated,
            variant: 'meta',
            x: 278,
            y: 168,
        },
        {
            id: 'signature',
            label: 'JWS',
            title: 'Proof Signature',
            subtitle: truncateMiddle(proofJws ?? 'Not available', 10, 8),
            fullValue: proofJws,
            variant: 'signature',
            x: 170,
            y: 260,
        },
    ];

    const nodeById = new Map(nodes.map((node) => [node.id, node]));
    const edges = [
        {from: 'proof', to: 'method', label: 'verificationMethod', labelX: 78, labelY: 112},
        {from: 'proof', to: 'purpose', label: 'proofPurpose', labelX: 183, labelY: 118},
        {from: 'proof', to: 'created', label: 'created', labelX: 264, labelY: 112},
        {from: 'proof', to: 'signature', label: 'jws', labelX: 181, labelY: 214},
    ];

    return `
        <svg class="audit-graph-svg audit-graph-svg--proof" viewBox="0 0 340 300" role="img" aria-label="Proof graph for audit record ${escapeHtml(record.id)}">
            ${edges.map((edge) => {
                const from = nodeById.get(edge.from);
                const to = nodeById.get(edge.to);
                return `
                    <line class="audit-graph-link" x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}"></line>
                    <text class="audit-graph-label" x="${edge.labelX}" y="${edge.labelY}">${escapeHtml(edge.label)}</text>
                `;
            }).join('')}
            ${nodes.map((node) => `
                <g class="audit-graph-node audit-graph-node--${node.variant}">
                    <title>${escapeHtml(`${node.title}: ${node.fullValue ?? 'Not available'}`)}</title>
                    <circle cx="${node.x}" cy="${node.y}" r="${node.id === 'proof' ? 34 : 28}"></circle>
                    <text x="${node.x}" y="${node.y - 4}">
                        <tspan x="${node.x}" dy="0">${escapeHtml(node.label)}</tspan>
                        <tspan x="${node.x}" dy="12">${escapeHtml(truncateMiddle(node.subtitle, 11, 8))}</tspan>
                    </text>
                </g>
            `).join('')}
        </svg>
    `;
}

function buildAuditFactMarkup(label, value) {
    return `
        <div class="audit-fact">
            <span class="audit-fact-label">${escapeHtml(label)}</span>
            <p class="audit-fact-value" title="${escapeHtml(value ?? 'Not available')}">${escapeHtml(value ?? 'Not available')}</p>
        </div>
    `;
}

function buildAuditDetailItemMarkup(label, value, {fullWidth = false, code = false} = {}) {
    const normalizedValue = value ?? 'Not available';

    return `
        <div class="audit-detail-item${fullWidth ? ' audit-detail-item--full' : ''}">
            <span class="audit-detail-label">${escapeHtml(label)}</span>
            ${code
                ? `<pre class="audit-detail-code">${escapeHtml(normalizedValue)}</pre>`
                : `<p class="audit-detail-value" title="${escapeHtml(normalizedValue)}">${escapeHtml(normalizedValue)}</p>`}
        </div>
    `;
}

function buildAuditNodeSectionMarkup({title, subtitle, items, modifier = ''}) {
    return `
        <section class="audit-node-section${modifier ? ` audit-node-section--${modifier}` : ''}">
            <div class="audit-node-section-heading">
                <strong>${escapeHtml(title)}</strong>
                <span>${escapeHtml(subtitle)}</span>
            </div>
            <div class="audit-node-grid">
                ${items.join('')}
            </div>
        </section>
    `;
}

function buildAuditCardMarkup(record, index) {
    const nroCredential = record.nro ?? {};
    const subjectNode = getPrimaryCredentialSubject(nroCredential) ?? {};
    const issuerDid = record.issuerDid ?? nroCredential.issuer;
    const subjectDid = getCredentialSubjectId(nroCredential) ?? record.requesterDid;
    const subjectResource = typeof subjectNode?.requestedResource === 'string'
        ? subjectNode.requestedResource
        : record.requestedResource;
    const signedHash = nroCredential.signedHash ?? record.messageHash;
    const proof = getPrimaryProof(nroCredential) ?? {};
    const verificationMethod = getCredentialVerificationMethod(nroCredential) ?? record.signerKid;
    const credentialId = typeof nroCredential?.id === 'string' ? nroCredential.id : 'Not available';
    const issuanceDate = typeof nroCredential?.issuanceDate === 'string'
        ? formatAuditDate(nroCredential.issuanceDate)
        : 'Not available';
    const proofType = typeof proof?.type === 'string' ? proof.type : 'Not available';
    const proofPurpose = typeof proof?.proofPurpose === 'string' ? proof.proofPurpose : 'Not available';
    const proofCreated = typeof proof?.created === 'string' ? formatAuditDate(proof.created) : 'Not available';
    const proofJws = typeof proof?.jws === 'string' ? proof.jws : 'Not available';
    const proofJson = Object.keys(proof).length ? JSON.stringify(proof, null, 2) : 'Not available';
    const subjectJson = Object.keys(subjectNode).length ? JSON.stringify(subjectNode, null, 2) : 'Not available';
    const credentialTypes = getCredentialTypes(nroCredential);

    const issuerSection = buildAuditNodeSectionMarkup({
        title: 'Issuer Node',
        subtitle: 'Details of the node that issued the NRO VC.',
        items: [
            buildAuditDetailItemMarkup('Issuer DID', issuerDid),
            buildAuditDetailItemMarkup('Credential ID', credentialId),
            buildAuditDetailItemMarkup('Issuance Date', issuanceDate),
        ],
    });

    const subjectSection = buildAuditNodeSectionMarkup({
        title: 'Subject Node',
        subtitle: 'Details of the credential subject linked by the NRO.',
        items: [
            buildAuditDetailItemMarkup('Subject DID', subjectDid),
            buildAuditDetailItemMarkup('Requested Resource', subjectResource),
            buildAuditDetailItemMarkup('Subject Payload', subjectJson, {fullWidth: true, code: true}),
        ],
    });

    const proofSection = buildAuditNodeSectionMarkup({
        title: 'Proof Node',
        subtitle: 'Details of the proof graph embedded in the NRO VC.',
        modifier: 'proof',
        items: [
            buildAuditDetailItemMarkup('Proof Type', proofType),
            buildAuditDetailItemMarkup('Verification Method', verificationMethod),
            buildAuditDetailItemMarkup('Proof Purpose', proofPurpose),
            buildAuditDetailItemMarkup('Proof Created', proofCreated),
            buildAuditDetailItemMarkup('Signed Hash', signedHash),
            buildAuditDetailItemMarkup('Credential Type', credentialTypes.join(', ') || 'NonRepudiableOrigin'),
            buildAuditDetailItemMarkup('JWS', proofJws, {fullWidth: true, code: true}),
            buildAuditDetailItemMarkup('Proof Payload', proofJson, {fullWidth: true, code: true}),
        ],
    });

    return `
        <article class="audit-record-card audit-record-card--nro">
            <div class="audit-record-header">
                <div>
                    <p class="eyebrow">CSS Credential</p>
                    <h4>NRO Graph ${index + 1}</h4>
                </div>
                <span class="audit-record-time">${escapeHtml(formatAuditDate(record.verifiedAt))}</span>
            </div>
            <div class="audit-record-body">
                <div class="audit-graph-stack">
                    <section class="audit-graph-section">
                        <div class="audit-graph-section-heading">
                            <strong>NRO Graph</strong>
                            <span>The credential and its direct relationships.</span>
                        </div>
                        <div class="audit-graph-viewport">
                            ${buildAuditGraphSvg(record)}
                        </div>
                    </section>
                    <section class="audit-graph-section">
                        <div class="audit-graph-section-heading">
                            <strong>Proof Subgraph</strong>
                            <span>The internal structure of the proof embedded in the NRO.</span>
                        </div>
                        <div class="audit-graph-viewport audit-graph-viewport--proof">
                            ${buildProofGraphSvg(record)}
                        </div>
                    </section>
                </div>
                <div class="audit-details-stack">
                    ${issuerSection}
                    ${subjectSection}
                    ${proofSection}
                </div>
            </div>
        </article>
    `;
}

function renderAuditGraphRecords(records, requestedResource) {
    if (!records.length) {
        auditGraphRecords.innerHTML = '';
        setAuditGraphCountLabel('0 NRO graphs');
        setAuditGraphStatus(
            requestedResource
                ? `No saved NRO graph was found yet for ${requestedResource}. Complete a verified exchange with the CSS and refresh this panel.`
                : 'No saved NRO graphs were found yet. Complete a verified exchange with the CSS and refresh this panel.',
            'neutral'
        );
        return;
    }

    const sortedRecords = [...records].sort((firstRecord, secondRecord) => {
        const firstTimestamp = new Date(firstRecord.verifiedAt ?? 0).getTime();
        const secondTimestamp = new Date(secondRecord.verifiedAt ?? 0).getTime();
        return secondTimestamp - firstTimestamp;
    });

    auditGraphRecords.innerHTML = sortedRecords
        .map((record, index) => buildAuditCardMarkup(record, index))
        .join('');

    setAuditGraphCountLabel(`${sortedRecords.length} saved ${sortedRecords.length === 1 ? 'NRO graph' : 'NRO graphs'}`);
    setAuditGraphStatus(
        requestedResource
            ? `Showing ${sortedRecords.length} saved ${sortedRecords.length === 1 ? 'NRO graph' : 'NRO graphs'} for the current protected resource.`
            : `Showing ${sortedRecords.length} saved ${sortedRecords.length === 1 ? 'NRO graph' : 'NRO graphs'} across all protected resources.`,
        'success'
    );
}

async function refreshAuditGraphs({requestedResource = searchBar.value} = {}) {
    const normalizedResource = requestedResource?.trim() ?? '';
    const currentRequestId = ++auditGraphRequestId;

    refreshAuditGraphButton.disabled = true;
    setAuditGraphCountLabel('Loading NRO...');
    setAuditGraphStatus(
        normalizedResource
            ? `Loading the saved NRO graph for ${normalizedResource}...`
            : 'Loading the saved NRO graphs...',
        'loading'
    );

    try {
        const response = await fetchJson(buildAuditQueryUrl({requestedResource: normalizedResource}));
        if (currentRequestId !== auditGraphRequestId) {
            return;
        }

        renderAuditGraphRecords(Array.isArray(response.records) ? response.records : [], normalizedResource);
    } catch (error) {
        console.error('Unable to load audit graphs.', error);
        if (currentRequestId !== auditGraphRequestId) {
            return;
        }

        auditGraphRecords.innerHTML = '';
        setAuditGraphCountLabel('NRO query failed');
        setAuditGraphStatus('Unable to load the saved NRO graphs from the internal audit endpoint.', 'error');
    } finally {
        if (currentRequestId === auditGraphRequestId) {
            refreshAuditGraphButton.disabled = false;
        }
    }
}

function setLoaderState(state) {
    loader.classList.remove('loader-almost-load', 'loader-loaded');

    if (state === 'hidden') {
        loader.style.display = 'none';
        return;
    }

    if (state === 'almost') {
        loader.classList.add('loader-almost-load');
    }

    if (state === 'loaded') {
        loader.classList.add('loader-loaded');
    }

    loader.style.display = 'block';
}

function setWorkflowStatus(message) {
    labelLoader.textContent = message;
    labelLoader.style.display = message ? 'block' : 'none';
}

function setWorkflowProgress(stepName, markCurrentAsComplete = false) {
    const currentStepIndex = WORKFLOW_STEP_ORDER.indexOf(stepName);

    WORKFLOW_STEP_ORDER.forEach((currentName, index) => {
        const stepElement = workflowSteps.get(currentName);
        if (!stepElement) {
            return;
        }

        stepElement.classList.remove('is-current', 'is-complete');

        if (index < currentStepIndex || (markCurrentAsComplete && index === currentStepIndex)) {
            stepElement.classList.add('is-complete');
            return;
        }

        if (index === currentStepIndex) {
            stepElement.classList.add('is-current');
        }
    });
}

function setResourceOverlayState({
    label,
    eyebrow = 'Protected Resource',
    title,
    message,
    state = 'locked',
    hideAfterMs = 0,
}) {
    window.clearTimeout(resourceRevealTimeoutId);
    resourceStateLabel.textContent = label;
    resourceOverlayEyebrow.textContent = eyebrow;
    resourceOverlayTitle.textContent = title;
    resourceOverlayMessage.textContent = message;
    resourceStage.dataset.state = state;
    resourceOverlay.classList.remove('is-hidden');

    if (hideAfterMs > 0) {
        resourceRevealTimeoutId = window.setTimeout(() => {
            resourceOverlay.classList.add('is-hidden');
        }, hideAfterMs);
    }
}

function resetResourcePreview() {
    responseArea.textContent = RESOURCE_LOCKED_PLACEHOLDER;
    resourceStage.classList.remove('has-content');
    setResourceOverlayState({
        label: 'Locked until SSI approval',
        title: 'Resource locked',
        message: 'The patient file stays hidden until the user logs in with SSI and accepts the credential exchange.',
        state: 'locked',
    });
}

function showPreparationState() {
    responseArea.textContent = RESOURCE_LOCKED_PLACEHOLDER;
    resourceStage.classList.remove('has-content');
    setResourceOverlayState({
        label: 'Preparing secure access',
        title: 'Creating SSI verification request',
        message: 'The resource remains locked while the wallet invitation is being prepared.',
        state: 'preparing',
    });
    setWorkflowProgress('request');
    setWorkflowStatus('Preparing the SSI verification request...');
    setLoaderState('loading');
}

function showInvitationPendingState() {
    setResourceOverlayState({
        label: 'Waiting for SSI login',
        title: 'Waiting for wallet connection',
        message: 'The file will remain locked until the user logs in with SSI and approves the credential exchange.',
        state: 'awaiting-login',
    });
    setWorkflowProgress('login');
    setWorkflowStatus('Invitation ready. Ask the user to log in with SSI and approve the credential exchange.');
    setLoaderState('loading');
}

function showInvitationSetupState() {
    ensureInvitationControls();
    invitationContainer.hidden = false;
    invitationContainer.innerHTML = '';

    const invitationCard = document.createElement('div');
    invitationCard.className = 'invitation-card';

    const invitationTitle = document.createElement('strong');
    invitationTitle.textContent = 'Invitation received';
    invitationCard.appendChild(invitationTitle);

    const invitationText = document.createElement('p');
    invitationText.textContent = 'The protected resource returned an invitation. Preparing the SSI wallet sign-in now.';
    invitationCard.appendChild(invitationText);

    invitationContainer.appendChild(invitationCard);
    connectInvitationButton.hidden = false;
    connectInvitationButton.disabled = true;
    connectInvitationButton.textContent = 'Log In with SSI';
    connectInvitationButton.dataset.invitationUrl = '';
    setInvitationAssistMessage('Preparing the wallet sign-in. The button will become available in a moment.');
    setResourceOverlayState({
        label: 'Preparing SSI login',
        title: 'Invitation received from the resource',
        message: 'We received the invitation URL and are preparing the SSI wallet handoff.',
        state: 'awaiting-login',
    });
    setWorkflowProgress('login');
    setWorkflowStatus('Invitation URL received. Preparing the SSI wallet login...');
    setLoaderState('loading');
}

function showWalletApprovalState() {
    setResourceOverlayState({
        label: 'Awaiting credential approval',
        title: 'Waiting for credential exchange approval',
        message: 'The protected resource will appear here as soon as the SSI wallet accepts the exchange.',
        state: 'awaiting-approval',
    });
    setWorkflowProgress('approve');
    setWorkflowStatus('Wallet opened. Waiting for the user to approve the credential exchange.');
    setLoaderState('loading');
}

function showResourceUnlockingState() {
    setResourceOverlayState({
        label: 'Fetching protected resource',
        eyebrow: 'Verification Complete',
        title: 'SSI verification succeeded',
        message: 'Access has been granted. Retrieving the protected patient file now.',
        state: 'unlocking',
    });
    setWorkflowProgress('view');
    setWorkflowStatus('Credential exchange approved. Retrieving the protected resource...');
    setLoaderState('almost');
}

function finalizeUnlockedState(resourceContent) {
    responseArea.textContent = formatResourceContent(resourceContent);
    resourceStage.classList.add('has-content');
    setResourceOverlayState({
        label: 'Protected resource unlocked',
        eyebrow: 'Access Granted',
        title: 'Resource unlocked',
        message: 'SSI verification succeeded. The patient file is now visible.',
        state: 'unlocked',
        hideAfterMs: 900,
    });
    setWorkflowProgress('view', true);
    setWorkflowStatus('Access granted. The protected resource is now visible.');
    setLoaderState('loaded');
    getBtn.disabled = false;
    void refreshAuditGraphs({requestedResource: searchBar.value});
}

function handleAccessError(error, fallbackMessage = 'Unable to unlock the protected resource.') {
    console.error(error);
    let detail = '';

    if (error?.message) {
        try {
            const parsedMessage = JSON.parse(error.message);
            if (parsedMessage?.invitationUrl) {
                detail = ' The invitation was received, but the SSI wallet handoff could not be prepared.';
            } else {
                detail = ` ${error.message}`;
            }
        } catch (parseError) {
            detail = ` ${error.message}`;
        }
    }

    clearInvitation();
    responseArea.textContent = RESOURCE_LOCKED_PLACEHOLDER;
    resourceStage.classList.remove('has-content');
    setResourceOverlayState({
        label: 'Resource still locked',
        eyebrow: 'Verification Needed',
        title: 'SSI verification not completed',
        message: `${fallbackMessage}${detail}`,
        state: 'locked',
    });
    setWorkflowProgress('request');
    setWorkflowStatus(`${fallbackMessage}${detail}`);
    setLoaderState('hidden');
    getBtn.disabled = false;
}

function ensureInvitationControls() {
    if (!connectInvitationButton) {
        connectInvitationButton = document.createElement('button');
        connectInvitationButton.type = 'button';
        connectInvitationButton.id = 'connectInvitationButton';
        connectInvitationButton.className = 'invitation-connect-button';
        connectInvitationButton.textContent = 'Log In with SSI';
        connectInvitationButton.hidden = true;
        invitationContainer.insertAdjacentElement('afterend', connectInvitationButton);
    }

    if (!invitationAssistMessage) {
        invitationAssistMessage = document.createElement('p');
        invitationAssistMessage.id = 'invitationAssistMessage';
        invitationAssistMessage.className = 'invitation-helper';
        invitationAssistMessage.hidden = true;
        connectInvitationButton.insertAdjacentElement('afterend', invitationAssistMessage);
    }
}

async function copyTextToClipboard(value) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        return;
    }

    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', 'true');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
}

function requestWalletExtensionPopup(invitationUrl) {
    return new Promise((resolve) => {
        if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage) {
            resolve({opened: false, error: 'Extension messaging unavailable.'});
            return;
        }

        try {
            chrome.runtime.sendMessage(
                USER_WALLET_EXTENSION_ID,
                {
                    type: 'open-wallet-popup',
                    invitationUrl,
                    autoConnect: true,
                },
                (response) => {
                    const runtimeError = chrome.runtime.lastError;
                    if (runtimeError) {
                        resolve({opened: false, error: runtimeError.message});
                        return;
                    }

                    if (!response?.ok) {
                        resolve({opened: false, error: response?.error || 'Extension refused the request.'});
                        return;
                    }

                    resolve({opened: true});
                }
            );
        } catch (error) {
            resolve({opened: false, error: error.message});
        }
    });
}

function setInvitationAssistMessage(text) {
    ensureInvitationControls();
    if (!text) {
        invitationAssistMessage.hidden = true;
        invitationAssistMessage.textContent = '';
        return;
    }

    invitationAssistMessage.textContent = text;
    invitationAssistMessage.hidden = false;
}

function clearInvitation() {
    ensureInvitationControls();
    invitationContainer.innerHTML = '';
    invitationContainer.hidden = true;
    connectInvitationButton.hidden = true;
    connectInvitationButton.disabled = false;
    connectInvitationButton.textContent = 'Log In with SSI';
    connectInvitationButton.dataset.invitationUrl = '';
    setInvitationAssistMessage('');
}

function renderInvitation(invitation) {
    ensureInvitationControls();
    clearInvitation();

    invitationContainer.hidden = false;

    const invitationCard = document.createElement('div');
    invitationCard.className = 'invitation-card';

    const invitationTitle = document.createElement('strong');
    invitationTitle.textContent = 'Wallet invitation ready';
    invitationCard.appendChild(invitationTitle);

    const invitationText = document.createElement('p');
    invitationText.textContent = invitation.qrcode
        ? 'Scan the QR code with the SSI wallet or use the button below to continue.'
        : 'Use the button below to continue the secure SSI wallet connection.';
    invitationCard.appendChild(invitationText);

    invitationContainer.appendChild(invitationCard);
    connectInvitationButton.dataset.invitationUrl = invitation.url;
    connectInvitationButton.hidden = false;
    connectInvitationButton.textContent = 'Log In with SSI';
    setInvitationAssistMessage('Scan the QR code or launch the wallet extension to continue.');

    if (invitation.qrcode) {
        const qrCodeImage = document.createElement('img');
        qrCodeImage.src = invitation.qrcode;
        qrCodeImage.alt = 'Invitation QR code';
        invitationContainer.appendChild(qrCodeImage);
    }

    showInvitationPendingState();
}

resetResourcePreview();
setWorkflowProgress('request');
setWorkflowStatus('Click Request Access to start the SSI verification flow.');
setLoaderState('hidden');
void refreshAuditGraphs({requestedResource: searchBar.value});

getBtn.onclick = async function () {
    if (getBtn.disabled) {
        return;
    }

    user = "did:web:bboi.solidcommunity.net:public";
    issuer = "did:web:secureissuer.solidcommunity.net:public";
    appName = "did:web:privateclinic.solidcommunity.net:public";

    getBtn.disabled = true;
    clearInvitation();
    showPreparationState();

    //Send requests following protocol
    //VcBasedrequests();
    try {
        await VcBasedrequestsDID();
    } catch (error) {
        handleAccessError(error);
    }
    //VcBasedrequestsFake();
    //Send requests following protocol - without user input and measure average time taken
    //speedTests(500);
};

document.addEventListener('click', async (event) => {
    const connectButton = event.target.closest('#connectInvitationButton');
    if (!connectButton) {
        return;
    }

    const invitationUrl = connectButton.dataset.invitationUrl;
    if (!invitationUrl) {
        return;
    }

    const originalLabel = connectButton.textContent;
    connectButton.disabled = true;
    connectButton.textContent = 'Opening...';
    let copied = false;
    let popupResult = {opened: false, error: 'Popup request not sent.'};
    let extensionWindow = null;

    try {
        try {
            await copyTextToClipboard(invitationUrl);
            copied = true;
        } catch (error) {
            console.warn('Unable to copy invitation URL automatically.', error);
        }

        try {
            popupResult = await requestWalletExtensionPopup(invitationUrl);
        } catch (error) {
            popupResult = {opened: false, error: error.message};
        }

        if (!popupResult.opened) {
            const walletExtensionUrl = buildWalletExtensionUrl(invitationUrl);
            extensionWindow = window.open(walletExtensionUrl, '_blank', 'noopener,noreferrer');
        }
    } finally {
        connectButton.disabled = false;
        connectButton.textContent = originalLabel;
    }

    if (popupResult.opened) {
        showWalletApprovalState();
        setInvitationAssistMessage(copied
            ? 'The wallet popup opened and the connection link was copied to the clipboard.'
            : 'The wallet popup opened and the connection request was forwarded automatically.');
        return;
    }

    if (!extensionWindow) {
        showInvitationPendingState();
        setInvitationAssistMessage(`Unable to open the wallet automatically. ${popupResult.error || 'Please scan the QR code to continue.'}`);
        return;
    }

    showWalletApprovalState();

    if (copied) {
        setInvitationAssistMessage('The fallback wallet tab was opened and the connection link was copied to the clipboard.');
        return;
    }

    setInvitationAssistMessage('The fallback wallet tab was opened. If the automatic handoff does not start, continue with the QR code.');
});

refreshAuditGraphButton.addEventListener('click', () => {
    void refreshAuditGraphs({requestedResource: searchBar.value});
});

searchBar.addEventListener('change', () => {
    void refreshAuditGraphs({requestedResource: searchBar.value});
});

async function VcBasedrequests() {
    const url = searchBar.value;
    //If we have a VP and just arrived from a redirect, use it to send a request for the resource from CSS server
    if (params.get("vp")) {
        const VP = params.get("vp");
        console.log('Sending request for the resource with a VP...');
        showResourceUnlockingState();
        const resource = await requestWithVP(url, VP);
        console.log(resource);
        finalizeUnlockedState(resource);
        //Otherwise, send first request and follow protocol to acquire VP
    } else {
        console.log("Sending first request for the resource...");
        //Message containing the app, issuer and user, requesting the resource at the url entered in the input box
        const initialResponse = await fetchJsonBody(url, {
            method: "GET",
            headers: {
                'vc': 'true'//So the server's VcHttpHandler component handles it
            },
            body: JSON.stringify({
                'VPCompliant': false,
                'agent': user,
                'client': appName,
                'issuer': issuer,
            })
        });
        const VPrequest = initialResponse.data;

        if (!VPrequest) {
            throw new Error('The resource server did not return a verification request.');
        }

        console.log(VPrequest);

        let obj_new_request;
        if (VPrequest.VerifiablePresentation !== undefined) { // Classical, no agent used
            obj_new_request = {
                challenge: VPrequest.VerifiablePresentation.challenge,
                domain: VPrequest.VerifiablePresentation.domain,
                owner: VPrequest.VerifiablePresentation.query.credentialQuery.owner.id,
                issuer: VPrequest.VerifiablePresentation.query.credentialQuery.issuer.id,
                creator: VPrequest.VerifiablePresentation.query.credentialQuery.creator.id,
                client: VPrequest.VerifiablePresentation.query.credentialQuery.client.id,
                agent: VPrequest.VerifiablePresentation.query.credentialQuery.agent.id
            }
        } else {
            obj_new_request = {
                challenge: VPrequest.options.challenge,
                domain: VPrequest.options.domain,
                target: VPrequest.presentation_definition.requestACP.target,
                owner: VPrequest.presentation_definition.requestACP.owner,
                issuer: VPrequest.presentation_definition.requestACP.issuer,
                creator: VPrequest.presentation_definition.requestACP.creator,
                client: VPrequest.presentation_definition.requestACP.client,
                agent: VPrequest.presentation_definition.requestACP.agent,
                input_descriptors: JSON.stringify(VPrequest.presentation_definition.input_descriptors)
            }
            if (VPrequest.type[0] === "VerifiablePresentationRequest") {
                // It is signed, so, we have almost all the fields, except for the new proof field
                obj_new_request.vpr = JSON.stringify(VPrequest)
            }
        }

        if (obj_new_request.target && url !== obj_new_request.target) {
            throw new Error("The resource server returned a mismatched target.");
        }

        console.log(obj_new_request);

        await delay(1000);
        const invitation = await fetchJson(`${appBaseUrl}/generateInvitation`);
        obj_new_request.connectionId = invitation.connectionId;
        renderInvitation(invitation);

        const proof = await postFormJson(`${appBaseUrl}/requestUserCredential`, obj_new_request);
        clearInvitation();
        showResourceUnlockingState();
        const resource = await requestWithVP(url, JSON.stringify(proof));
        console.log(resource);
        finalizeUnlockedState(resource);
    }
}


async function VcBasedrequestsDID() {
    const url = searchBar.value;
    //If we have a VP and just arrived from a redirect, use it to send a request for the resource from CSS server
    console.log("Sending first request for the resource...");
    //Message containing the app, issuer and user, requesting the resource at the url entered in the input box

    const initialResponse = await fetchJsonBody(url, {
        method: "GET",
        headers: {
            'didvc': true,
                'agent': user,
                'client': appName,
                'issuer': issuer,
            
        }
    });
    const result = initialResponse.data;
    const didcommAuthenticate = parseDidcommAuthenticateHeader(initialResponse.headers?.get('Www-Authenticate'));
    console.log(didcommAuthenticate);
    const invitationUrl = didcommAuthenticate.invitationUrl;
    const serializedProofRequest = didcommAuthenticate.proofRequest;

    if (serializedProofRequest) {
        const proofRequest = deserializeProofRequest(serializedProofRequest);
        console.log(proofRequest);
        // Disabled this check for testing
        /*if (proofRequest.presentation_definition?.requestACP?.target && url !== proofRequest.presentation_definition.requestACP.target) {
            throw new Error("The resource server returned a mismatched target.");
        }*/

        showInvitationSetupState();
        await delay(1000);
        const invitation = await fetchJson(`${appBaseUrl}/generateInvitation`);
        renderInvitation(invitation);

        const proofRequestPayload = buildProofRequestPayload(proofRequest, serializedProofRequest, invitation.connectionId);
        const proof = await postFormJson(`${appBaseUrl}/requestUserCredential`, proofRequestPayload);
        clearInvitation();
        showResourceUnlockingState();
        const resource = await requestWithVP(url, JSON.stringify(proof));
        finalizeUnlockedState(resource);
        return;
    }

    if (!invitationUrl) {
        if (!initialResponse.ok && result) {
            throw new Error(JSON.stringify(result));
        }

        throw new Error('The resource server did not return an invitation URL.');
    }

    showInvitationSetupState();
    await delay(1000);
    const invitation = await postFormJson(`${appBaseUrl}/generateInvitation`, {
        cssInvitationUrl: invitationUrl
    });

    const obj_new_request = {
        challenge: invitation.payload.options.challenge,
        domain: invitation.payload.options.domain,
        target: invitation.payload.presentation_definition.requestACP.target,
        owner: invitation.payload.presentation_definition.requestACP.owner,
        issuer: invitation.payload.presentation_definition.requestACP.issuer,
        creator: invitation.payload.presentation_definition.requestACP.creator,
        client: invitation.payload.presentation_definition.requestACP.client,
        agent: invitation.payload.presentation_definition.requestACP.agent,
        cssInvitationConnection: invitation.cssInvitationConnection,
        input_descriptors: JSON.stringify(invitation.payload.presentation_definition.input_descriptors)
    };

    if (invitation.payload.type[0] === "VerifiablePresentationRequest") {
        // It is signed, so, we have almost all the fields, except for the new proof field
        obj_new_request.vpr = JSON.stringify(invitation.payload);
    }

    obj_new_request.connectionId = invitation.connectionId;
    renderInvitation(invitation);

    const decryptedResource = await postFormJson(`${appBaseUrl}/requestUserCredential`, obj_new_request);
    clearInvitation();
    showResourceUnlockingState();
    finalizeUnlockedState(decryptedResource.content ?? decryptedResource);

}

//Sends request to User app and ask for a VP
//Gets redirected to User HTML page and should return to App with VP
async function getVP(nonce, domain) {
    console.log("Sending request to the User app...");
    let url = 'http://localhost:8081/vprequest';
    let response = await fetch(url, {
        redirect: "follow",
        method: "POST",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            user: user,
            application: appName,
            vcissuer: issuer,
            nonce: nonce,
            domain: domain,
            redirect_uri: window.location.href
        })
    });
    if (response.url !== undefined) {
        window.location = response.url;
    } else {
        console.log('Redirect URI not included in response.');
        return;
    }
}

async function requestWithVP(url, vpJwt) {
    const msg = {
        method: "GET",
        headers: {
            'vp': vpJwt,
            'Cache-Control': 'no-cache'
        }
    };
    const response2 = await fetch(url, msg);
    console.log(`Sent second request: ${JSON.stringify(msg)}`);

    if (!response2.ok) {
        const errorMessage = await response2.text().catch(() => '');
        throw new Error(errorMessage || `Request failed with status ${response2.status}.`);
    }

    const res = await response2.text();
    return res;
}

//full protocol from start to finish
async function speedTest() {
    let startTime = performance.now();
    //console.log(`Start Time: ${startTime}`);

    let url = searchBar.value;
    //Send first request and follow protocol to acquire VP
    //console.log("Sending first request for the resource...");
    //Message containing the app, issuer and user, requesting the resource at the url entered in the input box
    let response = await fetch(url, {
        method: "POST",
        headers: {
            'vc': 'true'//So the server's VcHttpHandler component handles it
        },
        body: JSON.stringify({
            'user': user,
            'app': appName,
            'vcissuer': issuer,
        })
    });
    let result = await response.json();
    responseArea.textContent = JSON.stringify(result);
    let VPrequest = result;
    let nonce = undefined;
    let domain = undefined;
    try {
        nonce = VPrequest.VerifiablePresentation.challenge;
        domain = VPrequest.VerifiablePresentation.domain;
    } catch (e) {
        console.log("No nonce or domain received in response");
        return;
    }
    //Send request to User to acquire VP
    console.log("Sending request to the User app...");
    let uri = 'http://localhost:8081/vprequest_speed_test';
    let res = await fetch(uri, {
        method: "POST",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            user: user,
            application: appName,
            vcissuer: issuer,
            nonce: nonce,
            domain: domain,
        })
    });

    //Request resource with VP
    let VP = await res.text();
    //console.log(VP);
    //console.log('Sending request for the resource with a VP...');
    let resource = await requestWithVP(url, VP);
    //console.log(resource);

    responseArea.textContent = resource;
    let endTime = performance.now();
    //console.log(`End Time: ${endTime}`);
    let timeTaken = endTime - startTime;
    //console.log(`Time Taken: ${timeTaken} milliseconds`);
    return timeTaken;
}

async function speedTests(sampleSize) {
    console.log(`Sending ${sampleSize} requests using VC-based protocol...`)
    let i = 1;
    let totalTime = 0;
    while (i <= sampleSize) {
        console.log(`Request ${i}:`);
        totalTime += await speedTest();
        i++;
    }
    let averageTime = totalTime / sampleSize;
    console.log(`Average Time: ${averageTime}`);
}

function syntaxHighlight(json) {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        var cls = 'number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'key';
            } else {
                cls = 'string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'boolean';
        } else if (/null/.test(match)) {
            cls = 'null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}
