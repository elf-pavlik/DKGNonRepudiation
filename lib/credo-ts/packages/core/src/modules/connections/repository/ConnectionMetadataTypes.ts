export enum ConnectionMetadataKeys {
  UseDidKeysForProtocol = '_internal/useDidKeysForProtocol',
  DidRotate = '_internal/didRotate',
  TheirPublicDid = '_internal/theirPublicDid',
}

export type ConnectionMetadata = {
  [ConnectionMetadataKeys.UseDidKeysForProtocol]: {
    [protocolUri: string]: boolean
  }
  [ConnectionMetadataKeys.DidRotate]: {
    did: string
    threadId: string
    mediatorId?: string
  }
  // Set during DID Exchange request processing once the requester's long-form (did:web) DID has
  // been verified against the signed attachment - see DidExchangeProtocol.processRequest and
  // DidExchangeRequestMessage's `didlong` field. Lets application code (e.g. an issuer/verifier)
  // learn who is really on the other end of the connection, not just the ephemeral peer DID.
  [ConnectionMetadataKeys.TheirPublicDid]: {
    did: string
  }
}
