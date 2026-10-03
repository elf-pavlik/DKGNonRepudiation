const { createHash } = require('crypto')
const fs = require('fs/promises')
const path = require('path')

const DEFAULT_RELATIVE_DIRECTORY = path.join('.internal', 'nro-audit', 'records')
const RECORD_SUBJECT_PREFIX = 'urn:demo-app:nro-audit:record:'

const TURTLE_PREFIXES = [
  '@prefix dc: <http://purl.org/dc/terms/> .',
  '@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .',
  '@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .',
  '@prefix nroaudit: <urn:demo-app:nro-audit#> .',
  '',
].join('\n')

class NroGraphService {
  constructor(args) {
    const relativeDirectory = args?.relativeDirectory ?? DEFAULT_RELATIVE_DIRECTORY
    this.recordsDirectory = path.join(args.rootFilePath, relativeDirectory)
  }

  async storeVerifiedNro(args) {
    const verifiedAt = args.verifiedAt ?? new Date().toISOString()
    const signerKid = this.extractSignerKid(args.nro)

    const record = {
      id: this.createRecordId(args, verifiedAt),
      nro: args.nro,
      requestedResource: args.requestedResource,
      requesterDid: args.requesterDid,
      messageHash: args.messageHash,
      verifiedAt,
      connectionId: args.connectionId,
      issuerDid: args.issuerDid,
      signerKid,
    }

    await fs.mkdir(this.recordsDirectory, { recursive: true })
    await fs.writeFile(this.getRecordFilePath(record.id), this.recordToTurtle(record), 'utf8')
    return record
  }

  async findVerifiedNro(args = {}) {
    if (!await this.pathExists(this.recordsDirectory)) {
      return []
    }

    const files = (await fs.readdir(this.recordsDirectory))
      .filter((file) => file.endsWith('.ttl'))
      .sort()

    const records = await Promise.all(
      files.map(async(file) => this.readRecord(path.join(this.recordsDirectory, file)))
    )

    return records.filter((record) => (
      (!args.requestedResource || record.requestedResource === args.requestedResource) &&
      (!args.requesterDid || record.requesterDid === args.requesterDid) &&
      (!args.messageHash || record.messageHash === args.messageHash) &&
      (!args.issuerDid || record.issuerDid === args.issuerDid)
    ))
  }

  getRecordFilePath(id) {
    return path.join(this.recordsDirectory, `${id}.ttl`)
  }

  createRecordId(args, verifiedAt) {
    return createHash('sha256')
      .update(JSON.stringify({
        connectionId: args.connectionId ?? '',
        issuerDid: args.issuerDid ?? '',
        messageHash: args.messageHash,
        nro: args.nro,
        requestedResource: args.requestedResource,
        requesterDid: args.requesterDid,
        verifiedAt,
      }))
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
    const recordSubject = `${RECORD_SUBJECT_PREFIX}${record.id}`
    const statements = [
      'rdf:type nroaudit:VerifiedNroRecord',
      `nroaudit:requestedResource <${this.escapeIri(record.requestedResource)}>`,
      `nroaudit:requesterDid <${this.escapeIri(record.requesterDid)}>`,
      `nroaudit:messageHash "${this.escapeLiteral(record.messageHash)}"`,
      `nroaudit:verifiedAt "${this.escapeLiteral(record.verifiedAt)}"^^xsd:dateTime`,
      `dc:modified "${this.escapeLiteral(record.verifiedAt)}"^^xsd:dateTime`,
    ]
    const blocks = []

    if (record.connectionId) {
      statements.push(`nroaudit:connectionId "${this.escapeLiteral(record.connectionId)}"`)
    }

    if (record.issuerDid) {
      statements.push(`nroaudit:issuerDid <${this.escapeIri(record.issuerDid)}>`)
    }

    if (record.signerKid) {
      statements.push(`nroaudit:signerKid <${this.escapeIri(record.signerKid)}>`)
    }

    if (record.nro) {
      const nroSubject = `${recordSubject}:nro`
      statements.push(`nroaudit:nro <${this.escapeIri(nroSubject)}>`)
      blocks.push(this.credentialToTurtle(nroSubject, record.nro))
    }

    return `${TURTLE_PREFIXES}${[
      this.renderBlock(recordSubject, statements),
      ...blocks,
    ].join('\n')}`
  }

  async readRecord(filePath) {
    const turtle = await fs.readFile(filePath, 'utf8')
    return this.turtleToRecord(turtle)
  }

  turtleToRecord(turtle) {
    const blocks = this.parseTurtleBlocks(turtle)
    const recordSubject = Array.from(blocks.keys()).find((subject) => subject.startsWith(RECORD_SUBJECT_PREFIX))
    if (!recordSubject) {
      throw new Error('Could not find an NRO audit subject in the stored graph.')
    }

    const recordStatements = this.getRequiredBlock(blocks, recordSubject, 'NRO audit record')
    const nroSubject = this.getOptionalNamedNodeFromBlock(recordStatements, 'nroaudit:nro')
    const legacyNroJson = this.getOptionalLiteralFromBlock(recordStatements, 'nroaudit:nroJson')

    return {
      id: recordSubject.slice(RECORD_SUBJECT_PREFIX.length),
      nro: nroSubject
        ? this.credentialFromBlocks(blocks, nroSubject)
        : JSON.parse(this.getRequiredLegacyLiteral(legacyNroJson, 'nroaudit:nroJson')),
      requestedResource: this.getRequiredNamedNodeFromBlock(recordStatements, 'nroaudit:requestedResource'),
      requesterDid: this.getRequiredNamedNodeFromBlock(recordStatements, 'nroaudit:requesterDid'),
      messageHash: this.getRequiredLiteralFromBlock(recordStatements, 'nroaudit:messageHash'),
      verifiedAt: this.getRequiredLiteralFromBlock(recordStatements, 'nroaudit:verifiedAt'),
      connectionId: this.getOptionalLiteralFromBlock(recordStatements, 'nroaudit:connectionId'),
      issuerDid: this.getOptionalNamedNodeFromBlock(recordStatements, 'nroaudit:issuerDid'),
      signerKid: this.getOptionalNamedNodeFromBlock(recordStatements, 'nroaudit:signerKid'),
    }
  }

  credentialToTurtle(subject, credential) {
    const statements = [
      'rdf:type nroaudit:StoredCredential',
    ]
    const blocks = []

    for (const context of this.toArray(credential?.['@context'])) {
      if (typeof context === 'string') {
        statements.push(`nroaudit:credentialContext <${this.escapeIri(context)}>`)
      } else {
        statements.push(`nroaudit:credentialContextJson "${this.escapeLiteral(JSON.stringify(context))}"`)
      }
    }

    if (typeof credential?.id === 'string') {
      statements.push(`nroaudit:credentialId <${this.escapeIri(credential.id)}>`)
    }

    for (const type of this.toArray(credential?.type).filter((value) => typeof value === 'string')) {
      statements.push(`nroaudit:credentialType "${this.escapeLiteral(type)}"`)
    }

    const issuerDid = typeof credential?.issuer === 'string'
      ? credential.issuer
      : credential?.issuer?.id
    if (issuerDid) {
      statements.push(`nroaudit:credentialIssuer <${this.escapeIri(issuerDid)}>`)
    }

    if (typeof credential?.issuanceDate === 'string') {
      statements.push(`nroaudit:issuanceDate "${this.escapeLiteral(credential.issuanceDate)}"^^xsd:dateTime`)
    }

    if (typeof credential?.signedHash === 'string') {
      statements.push(`nroaudit:signedHash "${this.escapeLiteral(credential.signedHash)}"`)
    }

    this.toArray(credential?.credentialSubject)
      .filter((value) => value && typeof value === 'object')
      .forEach((credentialSubject, index) => {
        const credentialSubjectNode = `${subject}:subject-${index + 1}`
        statements.push(`nroaudit:credentialSubject <${this.escapeIri(credentialSubjectNode)}>`)
        blocks.push(this.credentialSubjectToTurtle(credentialSubjectNode, credentialSubject))
      })

    this.toArray(credential?.proof)
      .filter((value) => value && typeof value === 'object')
      .forEach((proof, index) => {
        const proofNode = `${subject}:proof-${index + 1}`
        statements.push(`nroaudit:proof <${this.escapeIri(proofNode)}>`)
        blocks.push(this.proofToTurtle(proofNode, proof))
      })

    return [
      this.renderBlock(subject, statements),
      ...blocks,
    ].join('\n')
  }

  credentialSubjectToTurtle(subject, credentialSubject) {
    const statements = [
      'rdf:type nroaudit:CredentialSubject',
    ]

    if (typeof credentialSubject?.id === 'string') {
      statements.push(`nroaudit:subjectId <${this.escapeIri(credentialSubject.id)}>`)
    }

    if (typeof credentialSubject?.requestedResource === 'string') {
      statements.push(`nroaudit:requestedResource <${this.escapeIri(credentialSubject.requestedResource)}>`)
    }

    if (typeof credentialSubject?.signedHash === 'string') {
      statements.push(`nroaudit:signedHash "${this.escapeLiteral(credentialSubject.signedHash)}"`)
    }

    return this.renderBlock(subject, statements)
  }

  proofToTurtle(subject, proof) {
    const statements = [
      'rdf:type nroaudit:CredentialProof',
    ]

    if (typeof proof?.verificationMethod === 'string') {
      statements.push(`nroaudit:verificationMethod <${this.escapeIri(proof.verificationMethod)}>`)
    }

    if (typeof proof?.type === 'string') {
      statements.push(`nroaudit:proofType "${this.escapeLiteral(proof.type)}"`)
    }

    if (typeof proof?.created === 'string') {
      statements.push(`nroaudit:created "${this.escapeLiteral(proof.created)}"^^xsd:dateTime`)
    }

    if (typeof proof?.proofPurpose === 'string') {
      statements.push(`nroaudit:proofPurpose "${this.escapeLiteral(proof.proofPurpose)}"`)
    }

    if (typeof proof?.jws === 'string') {
      statements.push(`nroaudit:jws "${this.escapeLiteral(proof.jws)}"`)
    }

    return this.renderBlock(subject, statements)
  }

  credentialFromBlocks(blocks, subject) {
    const statements = this.getRequiredBlock(blocks, subject, 'credential')
    const credential = {}
    const contexts = [
      ...this.getNamedNodesFromBlock(statements, 'nroaudit:credentialContext'),
      ...this.getLiteralsFromBlock(statements, 'nroaudit:credentialContextJson').map((value) => JSON.parse(value)),
    ]

    if (contexts.length) {
      credential['@context'] = contexts.length === 1 ? contexts[0] : contexts
    }

    const credentialId = this.getOptionalNamedNodeFromBlock(statements, 'nroaudit:credentialId')
    if (credentialId) {
      credential.id = credentialId
    }

    const types = this.getLiteralsFromBlock(statements, 'nroaudit:credentialType')
    if (types.length) {
      credential.type = types.length === 1 ? types[0] : types
    }

    const issuerDid = this.getOptionalNamedNodeFromBlock(statements, 'nroaudit:credentialIssuer')
    if (issuerDid) {
      credential.issuer = issuerDid
    }

    const issuanceDate = this.getOptionalLiteralFromBlock(statements, 'nroaudit:issuanceDate')
    if (issuanceDate) {
      credential.issuanceDate = issuanceDate
    }

    const signedHash = this.getOptionalLiteralFromBlock(statements, 'nroaudit:signedHash')
    if (signedHash) {
      credential.signedHash = signedHash
    }

    const credentialSubjects = this.getNamedNodesFromBlock(statements, 'nroaudit:credentialSubject')
      .map((credentialSubjectNode) => this.credentialSubjectFromBlocks(blocks, credentialSubjectNode))
    if (credentialSubjects.length) {
      credential.credentialSubject = credentialSubjects.length === 1
        ? credentialSubjects[0]
        : credentialSubjects
    }

    const proofs = this.getNamedNodesFromBlock(statements, 'nroaudit:proof')
      .map((proofNode) => this.proofFromBlocks(blocks, proofNode))
    if (proofs.length) {
      credential.proof = proofs.length === 1 ? proofs[0] : proofs
    }

    return credential
  }

  credentialSubjectFromBlocks(blocks, subject) {
    const statements = this.getRequiredBlock(blocks, subject, 'credential subject')
    const credentialSubject = {}
    const subjectId = this.getOptionalNamedNodeFromBlock(statements, 'nroaudit:subjectId')
    const requestedResource = this.getOptionalNamedNodeFromBlock(statements, 'nroaudit:requestedResource')
    const signedHash = this.getOptionalLiteralFromBlock(statements, 'nroaudit:signedHash')

    if (subjectId) {
      credentialSubject.id = subjectId
    }

    if (requestedResource) {
      credentialSubject.requestedResource = requestedResource
    }

    if (signedHash) {
      credentialSubject.signedHash = signedHash
    }

    return credentialSubject
  }

  proofFromBlocks(blocks, subject) {
    const statements = this.getRequiredBlock(blocks, subject, 'credential proof')
    const proof = {}
    const verificationMethod = this.getOptionalNamedNodeFromBlock(statements, 'nroaudit:verificationMethod')
    const proofType = this.getOptionalLiteralFromBlock(statements, 'nroaudit:proofType')
    const created = this.getOptionalLiteralFromBlock(statements, 'nroaudit:created')
    const proofPurpose = this.getOptionalLiteralFromBlock(statements, 'nroaudit:proofPurpose')
    const jws = this.getOptionalLiteralFromBlock(statements, 'nroaudit:jws')

    if (verificationMethod) {
      proof.verificationMethod = verificationMethod
    }

    if (proofType) {
      proof.type = proofType
    }

    if (created) {
      proof.created = created
    }

    if (proofPurpose) {
      proof.proofPurpose = proofPurpose
    }

    if (jws) {
      proof.jws = jws
    }

    return proof
  }

  renderBlock(subject, statements) {
    return `<${this.escapeIri(subject)}>\n  ${statements.join(' ;\n  ')} .\n`
  }

  parseTurtleBlocks(turtle) {
    const blocks = new Map()
    const lines = turtle.split(/\r?\n/)
    let currentLines = []

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('@prefix')) {
        continue
      }

      currentLines.push(line)
      if (trimmed.endsWith(' .')) {
        const block = this.parseTurtleBlock(currentLines)
        blocks.set(block.subject, block.statements)
        currentLines = []
      }
    }

    if (currentLines.length > 0) {
      throw new Error('Encountered an unterminated Turtle block while reading the NRO audit graph.')
    }

    return blocks
  }

  parseTurtleBlock(lines) {
    const [subjectLine, ...statementLines] = lines
    const subjectMatch = subjectLine.trim().match(/^<((?:\\.|[^>])*)>$/)
    if (!subjectMatch) {
      throw new Error(`Could not parse Turtle subject line: ${subjectLine}`)
    }

    const statements = statementLines
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const statementMatch = line.match(/^([^\s]+)\s+(.+?)(?:\s*[.;])$/)
        if (!statementMatch) {
          throw new Error(`Could not parse Turtle statement: ${line}`)
        }

        return {
          predicate: statementMatch[1],
          object: statementMatch[2].trim(),
        }
      })

    return {
      subject: this.unescapeIri(subjectMatch[1]),
      statements,
    }
  }

  getRequiredBlock(blocks, subject, label) {
    const statements = blocks.get(subject)
    if (!statements) {
      throw new Error(`Missing ${label} block ${subject}.`)
    }
    return statements
  }

  getRequiredNamedNodeFromBlock(statements, predicate) {
    const value = this.getOptionalNamedNodeFromBlock(statements, predicate)
    if (!value) {
      throw new Error(`Missing required NRO audit field ${predicate}.`)
    }
    return value
  }

  getOptionalNamedNodeFromBlock(statements, predicate) {
    return this.getNamedNodesFromBlock(statements, predicate)[0]
  }

  getNamedNodesFromBlock(statements, predicate) {
    return this.getObjectsFromBlock(statements, predicate)
      .map((value) => this.parseNamedNode(value))
      .filter((value) => value !== undefined)
  }

  getRequiredLiteralFromBlock(statements, predicate) {
    const value = this.getOptionalLiteralFromBlock(statements, predicate)
    if (!value) {
      throw new Error(`Missing required NRO audit field ${predicate}.`)
    }
    return value
  }

  getOptionalLiteralFromBlock(statements, predicate) {
    return this.getLiteralsFromBlock(statements, predicate)[0]
  }

  getLiteralsFromBlock(statements, predicate) {
    return this.getObjectsFromBlock(statements, predicate)
      .map((value) => this.parseLiteral(value))
      .filter((value) => value !== undefined)
  }

  getObjectsFromBlock(statements, predicate) {
    return statements
      .filter((statement) => statement.predicate === predicate)
      .map((statement) => statement.object)
  }

  getRequiredLegacyLiteral(value, predicate) {
    if (!value) {
      throw new Error(`Missing required legacy NRO audit field ${predicate}.`)
    }
    return value
  }

  parseNamedNode(value) {
    const match = value.match(/^<((?:\\.|[^>])*)>$/)
    return match ? this.unescapeIri(match[1]) : undefined
  }

  parseLiteral(value) {
    const match = value.match(/^"((?:\\.|[^"\\])*)"(?:(?:\^\^[^\s]+)|(?:@[A-Za-z-]+))?$/)
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

  unescapeIri(value) {
    return value.replace(/\\>/g, '>').replace(/\\\\/g, '\\')
  }

  toArray(value) {
    if (value === undefined || value === null) {
      return []
    }

    return Array.isArray(value) ? value : [value]
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
  NroGraphService,
}
