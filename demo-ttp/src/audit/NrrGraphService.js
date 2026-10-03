const { createHash } = require('crypto')
const fs = require('fs/promises')
const path = require('path')

const DEFAULT_RELATIVE_DIRECTORY = path.join('.internal', 'nrr-audit', 'records')
const RECORD_SUBJECT_PREFIX = 'urn:demo-ttp:nrr-audit:record:'

const TURTLE_PREFIXES = [
  '@prefix dc: <http://purl.org/dc/terms/> .',
  '@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .',
  '@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .',
  '@prefix nrraudit: <urn:demo-ttp:nrr-audit#> .',
  '',
].join('\n')

class NrrGraphService {
  constructor(args) {
    const relativeDirectory = args?.relativeDirectory ?? DEFAULT_RELATIVE_DIRECTORY
    this.recordsDirectory = path.join(args.rootFilePath, relativeDirectory)
  }

  async storeReceivedNrr(args) {
    const receivedAt = args.receivedAt ?? new Date().toISOString()
    const record = {
      id: this.createRecordId(args, receivedAt),
      messageHash: args.messageHash,
      receivedAt,
      signerKid: this.extractSignerKid(args.signedResource),
      signedResourceFingerprint: this.createSignedResourceFingerprint(args.signedResource),
      signedResource: args.signedResource,
      encryptedResource: args.encryptedResource,
    }

    await fs.mkdir(this.recordsDirectory, { recursive: true })
    await fs.writeFile(this.getRecordFilePath(record.id), this.recordToTurtle(record), 'utf8')
    return record
  }

  async findReceivedNrr(args = {}) {
    if (!await this.pathExists(this.recordsDirectory)) {
      return []
    }

    const signedResourceFingerprint = args.signedResource !== undefined
      ? this.createSignedResourceFingerprint(args.signedResource)
      : args.signedResourceFingerprint

    const files = (await fs.readdir(this.recordsDirectory))
      .filter((file) => file.endsWith('.ttl'))
      .sort()

    const records = await Promise.all(
      files.map(async(file) => this.readRecord(path.join(this.recordsDirectory, file)))
    )

    return records.filter((record) => (
      (!args.messageHash || record.messageHash === args.messageHash) &&
      (!args.signerKid || record.signerKid === args.signerKid) &&
      (!signedResourceFingerprint || record.signedResourceFingerprint === signedResourceFingerprint)
    ))
  }

  getRecordFilePath(id) {
    return path.join(this.recordsDirectory, `${id}.ttl`)
  }

  createRecordId(args, receivedAt) {
    return createHash('sha256')
      .update(JSON.stringify({
        encryptedResource: args.encryptedResource,
        messageHash: args.messageHash ?? '',
        receivedAt,
        signedResource: args.signedResource,
      }))
      .digest('hex')
  }

  createSignedResourceFingerprint(signedResource) {
    return createHash('sha256')
      .update(JSON.stringify(signedResource))
      .digest('hex')
  }

  extractSignerKid(jws) {
    const header = typeof jws?.header === 'object' && jws.header ? jws.header : undefined
    if (typeof header?.kid === 'string') {
      return header.kid
    }

    const proof = Array.isArray(jws?.proof) ? jws.proof[0] : jws?.proof
    return typeof proof?.verificationMethod === 'string' ? proof.verificationMethod : undefined
  }

  recordToTurtle(record) {
    const subject = `<${RECORD_SUBJECT_PREFIX}${record.id}>`
    const statements = [
      'rdf:type nrraudit:ReceivedNrrRecord',
      `nrraudit:messageHash "${this.escapeLiteral(record.messageHash)}"`,
      `nrraudit:receivedAt "${this.escapeLiteral(record.receivedAt)}"^^xsd:dateTime`,
      `nrraudit:signedResourceFingerprint "${this.escapeLiteral(record.signedResourceFingerprint)}"`,
      `nrraudit:signedResourceJson "${this.escapeLiteral(JSON.stringify(record.signedResource))}"`,
      `dc:modified "${this.escapeLiteral(record.receivedAt)}"^^xsd:dateTime`,
    ]

    if (record.signerKid) {
      statements.push(`nrraudit:signerKid <${this.escapeIri(record.signerKid)}>`)
    }

    if (record.encryptedResource) {
      statements.push(`nrraudit:encryptedResourceJson "${this.escapeLiteral(JSON.stringify(record.encryptedResource))}"`)
    }

    return `${TURTLE_PREFIXES}${subject}\n  ${statements.join(' ;\n  ')} .\n`
  }

  async readRecord(filePath) {
    const turtle = await fs.readFile(filePath, 'utf8')
    return this.turtleToRecord(turtle)
  }

  turtleToRecord(turtle) {
    const subjectMatch = turtle.match(/<urn:demo-ttp:nrr-audit:record:([^>]+)>/)
    if (!subjectMatch) {
      throw new Error('Could not find an NRR audit subject in the stored graph.')
    }

    const signedResourceJson = this.getRequiredLiteral(turtle, 'nrraudit:signedResourceJson')
    const encryptedResourceJson = this.getOptionalLiteral(turtle, 'nrraudit:encryptedResourceJson')

    return {
      id: subjectMatch[1],
      messageHash: this.getRequiredLiteral(turtle, 'nrraudit:messageHash'),
      receivedAt: this.getRequiredLiteral(turtle, 'nrraudit:receivedAt'),
      signerKid: this.getOptionalNamedNode(turtle, 'nrraudit:signerKid'),
      signedResourceFingerprint: this.getRequiredLiteral(turtle, 'nrraudit:signedResourceFingerprint'),
      signedResource: JSON.parse(signedResourceJson),
      encryptedResource: encryptedResourceJson ? JSON.parse(encryptedResourceJson) : undefined,
    }
  }

  getRequiredNamedNode(turtle, predicate) {
    const value = this.getOptionalNamedNode(turtle, predicate)
    if (!value) {
      throw new Error(`Missing required NRR audit field ${predicate}.`)
    }
    return value
  }

  getOptionalNamedNode(turtle, predicate) {
    const match = turtle.match(new RegExp(`${this.escapeRegex(predicate)}\\s+<([^>]+)>`))
    return match ? match[1] : undefined
  }

  getRequiredLiteral(turtle, predicate) {
    const value = this.getOptionalLiteral(turtle, predicate)
    if (!value) {
      throw new Error(`Missing required NRR audit field ${predicate}.`)
    }
    return value
  }

  getOptionalLiteral(turtle, predicate) {
    const match = turtle.match(new RegExp(`${this.escapeRegex(predicate)}\\s+"((?:\\\\.|[^"\\\\])*)"`))
    return match ? this.unescapeLiteral(match[1]) : undefined
  }

  escapeLiteral(value) {
    return JSON.stringify(value).slice(1, -1)
  }

  unescapeLiteral(value) {
    return JSON.parse(`"${value}"`)
  }

  escapeIri(value) {
    return String(value).replace(/\\/g, '\\\\').replace(/>/g, '\\>')
  }

  escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }

  async pathExists(filePath) {
    try {
      await fs.access(filePath)
      return true
    } catch {
      return false
    }
  }
}

module.exports = {
  NrrGraphService,
}
