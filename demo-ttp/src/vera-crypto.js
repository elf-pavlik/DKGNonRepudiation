// Cryptographic building blocks of the VERA non-repudiable release (paper Section 3.1, ProVerif model
// didcomm_ver_upd_agreement_complete_23nov.pv).
//
// This file is duplicated verbatim in demo-app/src and demo-ttp/src, and mirrors
// CommunitySolidServer/src/util/VeraCrypto.ts: CSS, App and TTP must compute byte-identical values
// for E, Y, h, h_K and C, so any change here has to be applied to all three copies.
//
//  - E   = AEAD_{K_R}(R, salt)
//  - Y   = kid . AEAD_{K_ttp}(K_R, DID_A, n_c, H(E))
//  - h   = H(R, salt)
//  - h_K = H(K_R)
//  - C   = H(DID_V, DID_A, DID_U, URI, n_c, H(E), Y, h, h_K)

const {
    createCipheriv,
    createDecipheriv,
    createHash,
    createHmac,
    createPublicKey,
    diffieHellman,
    generateKeyPairSync,
    randomBytes,
} = require('crypto')

const AEAD_ALGORITHM = 'aes-256-gcm'
const AEAD_NONCE_LENGTH = 12
const AEAD_TAG_LENGTH = 16
// DER prefix of an X25519 SubjectPublicKeyInfo, followed by the 32-byte raw public key.
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')

// Domain-separation tags, playing the role of tag_resenc, tag_enc_k15, tag_C, ... in the ProVerif model.
const TAG_E = 'VERA-E'
const TAG_Y = 'VERA-Y'
const TAG_H = 'VERA-h'
const TAG_C = 'VERA-C'
const TAG_KTTP = 'VERA-Kttp'
const TAG_KEX_CSS = 'VERA-KEX-CSS'
const TAG_KEX_TTP = 'VERA-KEX-TTP'
const TAG_TTP_RECEIPT = 'VERA-M17'

function toBase64Url(data) {
    return Buffer.from(data).toString('base64').replace(/\+/gu, '-').replace(/\//gu, '_').replace(/[=]+$/u, '')
}

function fromBase64Url(value) {
    return Buffer.from(value.replace(/-/gu, '+').replace(/_/gu, '/'), 'base64')
}

function sha256Hex(data) {
    return createHash('sha256').update(data).digest('hex')
}

function seal(key, plaintext, tag) {
    const nonce = randomBytes(AEAD_NONCE_LENGTH)
    const cipher = createCipheriv(AEAD_ALGORITHM, key, nonce, {authTagLength: AEAD_TAG_LENGTH})
    cipher.setAAD(Buffer.from(tag, 'utf8'))
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    return toBase64Url(Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]))
}

function open(key, sealed, tag) {
    const bytes = fromBase64Url(sealed)
    if (bytes.length < AEAD_NONCE_LENGTH + AEAD_TAG_LENGTH) {
        throw new Error('The sealed value is too short.')
    }
    const nonce = bytes.subarray(0, AEAD_NONCE_LENGTH)
    const ciphertext = bytes.subarray(AEAD_NONCE_LENGTH, bytes.length - AEAD_TAG_LENGTH)
    const decipher = createDecipheriv(AEAD_ALGORITHM, key, nonce, {authTagLength: AEAD_TAG_LENGTH})
    decipher.setAAD(Buffer.from(tag, 'utf8'))
    decipher.setAuthTag(bytes.subarray(bytes.length - AEAD_TAG_LENGTH))
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

function hashCiphertext(E) {
    return sha256Hex(fromBase64Url(E))
}

function hashSaltedResource(resource, salt) {
    return sha256Hex(JSON.stringify([TAG_H, resource, salt]))
}

function hashKey(kR) {
    return sha256Hex(kR)
}

function computeCommitment({didV, didA, didU, uri, nc, hE, Y, h, hK}) {
    return sha256Hex(JSON.stringify([TAG_C, didV, didA, didU, uri, nc, hE, Y, h, hK]))
}

// Decrypts E with the released K_R and checks it against h. Throws if K_R is wrong, E was
// tampered with, or the plaintext does not match the commitment h.
function decryptResource(E, kR, h) {
    const {resource, salt} = JSON.parse(open(kR, E, TAG_E).toString('utf8'))
    if (typeof resource !== 'string' || typeof salt !== 'string') {
        throw new Error('The decrypted resource is malformed.')
    }
    if (hashSaltedResource(resource, salt) !== h) {
        throw new Error('The decrypted resource does not match the commitment h.')
    }
    return {resource, salt}
}

function splitKid(sealedWithKid) {
    const separator = sealedWithKid.indexOf('.')
    if (separator <= 0) {
        throw new Error('The value does not carry a K_ttp key id.')
    }
    return {kid: sealedWithKid.slice(0, separator), sealed: sealedWithKid.slice(separator + 1)}
}

// Opens Y with K_ttp, returning K_R and the DID_A, n_c and H(E) it is bound to.
function unwrapKey(ttpKey, Y) {
    const {sealed} = splitKid(Y)
    const {kR, didA, nc, hE} = JSON.parse(open(ttpKey, sealed, TAG_Y).toString('utf8'))
    return {kR: fromBase64Url(kR), didA, nc, hE}
}

function generateEphemeralKeyPair() {
    const {privateKey, publicKey} = generateKeyPairSync('x25519')
    const spki = publicKey.export({type: 'spki', format: 'der'})
    return {privateKey, publicKey: toBase64Url(spki.subarray(X25519_SPKI_PREFIX.length))}
}

// The bytes signed by each party during the K_ttp exchange (m10/m11 in the ProVerif model).
function keyExchangePayload(tag, did, ...publicKeys) {
    return Buffer.from(JSON.stringify([tag, did, ...publicKeys]), 'utf8')
}

// Derives K_ttp = HKDF(X25519(own, peer)), salted with both ephemeral public keys (CSS first).
function deriveTtpKey(privateKey, peerPublicKey, cssPublicKey, ttpPublicKey) {
    const publicKey = createPublicKey({
        key: Buffer.concat([X25519_SPKI_PREFIX, fromBase64Url(peerPublicKey)]),
        format: 'der',
        type: 'spki',
    })
    const shared = diffieHellman({privateKey, publicKey})
    const salt = Buffer.concat([fromBase64Url(cssPublicKey), fromBase64Url(ttpPublicKey)])
    // HKDF-SHA256 (RFC 5869) with a single output block.
    const prk = createHmac('sha256', salt).update(shared).digest()
    const key = createHmac('sha256', prk).update(Buffer.concat([Buffer.from(TAG_KTTP, 'utf8'), Buffer.from([1])])).digest()
    return {kid: sha256Hex(salt).slice(0, 32), key}
}

module.exports = {
    TAG_KEX_CSS,
    TAG_KEX_TTP,
    TAG_TTP_RECEIPT,
    toBase64Url,
    fromBase64Url,
    sha256Hex,
    seal,
    open,
    hashCiphertext,
    hashSaltedResource,
    hashKey,
    computeCommitment,
    decryptResource,
    splitKid,
    unwrapKey,
    generateEphemeralKeyPair,
    keyExchangePayload,
    deriveTtpKey,
}
