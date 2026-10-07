// Zero-code OpenTelemetry setup for the demo parties.
//
// Mounted at /otel/register.js and loaded through NODE_OPTIONS=--require, so the
// SDK starts before the application code. The packages live in the otel-node
// volume at /otel/node_modules.
//
// It mirrors @opentelemetry/auto-instrumentations-node/register and adds:
//   - HTTP header capture (server and client),
//   - HTTP server request and response body capture,
//   - DIDComm and internal-operation spans, patched on load so no application
//     source changes are needed.
const path = require('path');
const Module = require('module');

const { NodeSDK } = require('@opentelemetry/sdk-node');
const { diag, DiagConsoleLogger, trace, SpanStatusCode } = require('@opentelemetry/api');
const { getStringFromEnv, diagLogLevelFromString } = require('@opentelemetry/core');
const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
// Not a public export, but it is what the default register uses.
const {
  getResourceDetectorsFromEnv,
} = require('/otel/node_modules/@opentelemetry/auto-instrumentations-node/build/src/utils.js');

const MAX = Number(process.env.VERA_PAYLOAD_MAX_LENGTH || 16384);
const TEXTUAL = /json|text|xml|javascript|graphql|turtle|ld\+json|form-urlencoded/i;

function clip(value) {
  if (value === undefined || value === null) return undefined;
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (text === undefined) return undefined;
  return text.length > MAX ? `${text.slice(0, MAX)}...[truncated]` : text;
}

const logLevel = getStringFromEnv('OTEL_LOG_LEVEL');
if (logLevel != null) {
  diag.setLogger(new DiagConsoleLogger(), { logLevel: diagLogLevelFromString(logLevel) });
}

// --- HTTP body capture -----------------------------------------------------
//
// Buffers the request body on the server 'request' event and the response body
// by wrapping ServerResponse.write/end, then attaches both to the active span
// when the response ends. Must run after sdk.start(), because requiring http
// earlier would stop the http instrumentation from patching it.

function captureBodies() {
  const http = require('http');
  const https = require('https');
  const requestBodies = new WeakMap();
  const responseBodies = new WeakMap();

  const append = (store, key, chunk) => {
    let rec = store.get(key);
    if (!rec) {
      rec = { chunks: [], size: 0 };
      store.set(key, rec);
    }
    if (rec.size >= MAX) return;
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    rec.chunks.push(buf);
    rec.size += buf.length;
  };
  const text = (rec) => (rec && rec.chunks.length ? Buffer.concat(rec.chunks).subarray(0, MAX).toString('utf8') : undefined);

  for (const mod of [http, https]) {
    const Server = mod.Server;
    if (Server && !Server.prototype.__veraPatched) {
      Server.prototype.__veraPatched = true;
      const emit = Server.prototype.emit;
      Server.prototype.emit = function (event, ...args) {
        if (event === 'request' && args.length >= 2) {
          const [req, res] = args;
          try {
            req.on('data', (chunk) => append(requestBodies, res, chunk));
          } catch { /* ignore */ }
        }
        return emit.apply(this, arguments);
      };
    }

    const proto = mod.ServerResponse && mod.ServerResponse.prototype;
    if (proto && !proto.__veraPatched) {
      proto.__veraPatched = true;
      const write = proto.write;
      const end = proto.end;
      proto.write = function (chunk, ...rest) {
        try { append(responseBodies, this, chunk); } catch { /* ignore */ }
        return write.call(this, chunk, ...rest);
      };
      proto.end = function (chunk, ...rest) {
        try {
          if (chunk !== undefined && chunk !== null) append(responseBodies, this, chunk);
          const span = trace.getActiveSpan();
          if (span) {
            const requestBody = text(requestBodies.get(this));
            if (requestBody && requestBody.trim().length > 0) span.setAttribute('http.request.body', clip(requestBody));
            const contentType = this.getHeader ? String(this.getHeader('content-type') || '') : '';
            const responseBody = text(responseBodies.get(this));
            if (responseBody !== undefined && (!contentType || TEXTUAL.test(contentType))) {
              span.setAttribute('http.response.body', clip(responseBody));
            }
          }
        } catch { /* ignore */ }
        responseBodies.delete(this);
        return end.call(this, chunk, ...rest);
      };
    }
  }
}

const headerLists = {
  requestHeaders: ['agent', 'client', 'issuer', 'didvc', 'vp', 'signedresource', 'x-forwarded-host', 'x-forwarded-proto'],
  responseHeaders: ['www-authenticate', 'encryptedresource', 'keyfordecrypt'],
};

const instrumentations = getNodeAutoInstrumentations({
  '@opentelemetry/instrumentation-http': {
    // In @opentelemetry/instrumentation-http >= 0.53 this nests under server/client.
    headersToSpanAttributes: { server: headerLists, client: headerLists },
  },
});

// --- Internal operation spans ---------------------------------------------

function instrumentMethod(target, method, name, extract) {
  if (!target || typeof target[method] !== 'function' || target[method].__vera) return false;
  const original = target[method];
  const wrapped = function (...args) {
    const span = trace.getTracer('vera').startSpan(name);
    const finish = (error, result) => {
      try {
        const attributes = extract ? extract(args, result, error) : undefined;
        if (attributes) span.setAttributes(attributes);
        if (error) {
          span.recordException(error);
          span.setStatus({ code: SpanStatusCode.ERROR, message: String(error.message || error) });
        }
      } catch { /* ignore */ }
      span.end();
    };
    try {
      const result = original.apply(this, args);
      if (result && typeof result.then === 'function') {
        return result.then((r) => { finish(null, r); return r; }, (e) => { finish(e); throw e; });
      }
      finish(null, result);
      return result;
    } catch (error) {
      finish(error);
      throw error;
    }
  };
  wrapped.__vera = true;
  target[method] = wrapped;
  return true;
}

function messageJson(payload) {
  if (!payload) return undefined;
  if (typeof payload.toJSON === 'function') {
    try { return payload.toJSON(); } catch { /* ignore */ }
  }
  return payload;
}
function messageType(payload) {
  const json = messageJson(payload);
  return json && json['@type'];
}
const didcommPack = (args, result) => {
  const payload = messageJson(args[1]);
  const keys = args[2];
  return {
    'didcomm.direction': 'out',
    'didcomm.type': payload && payload['@type'],
    'didcomm.payload': clip(payload),
    'didcomm.recipients': keys && Array.isArray(keys.recipientKeys) ? keys.recipientKeys.length : undefined,
    'didcomm.encrypted': result ? 'true' : undefined,
  };
};
const didcommUnpack = (args, result) => {
  const plaintext = result && (result.plaintextMessage || result.message || result);
  return {
    'didcomm.direction': 'in',
    'didcomm.type': messageType(plaintext),
    'didcomm.payload': clip(messageJson(plaintext)),
  };
};

function patchEnvelopeService(exports) {
  const Service = exports && exports.EnvelopeService;
  if (!Service) return;
  for (const method of ['packMessage', 'packMessageWithReturn']) instrumentMethod(Service.prototype, method, 'didcomm.pack', didcommPack);
  for (const method of ['unpackMessage', 'unpackMessageWithReturn']) instrumentMethod(Service.prototype, method, 'didcomm.unpack', didcommUnpack);
}

function patchW3cCredentialService(exports) {
  const Service = exports && exports.W3cCredentialService;
  if (!Service) return;
  const proto = Service.prototype;
  instrumentMethod(proto, 'createPresentationWrapper', 'vc.wrapPresentation', (args, result) => ({ 'vera.presentation': clip(args[0] && args[0].vp), 'vera.wrapper': clip(result) }));
  instrumentMethod(proto, 'createPresentationRequestWrapper', 'vc.wrapPresentationRequest', (args, result) => ({ 'vera.vpr': clip(args[0] && args[0].vpr), 'vera.wrapper': clip(result) }));
  instrumentMethod(proto, 'signWrappedPresentation', 'vc.signWrappedPresentation', (args, result) => ({ 'vera.wrapper': clip(args[0] && args[0].presentation), 'vera.signed': clip(result) }));
  instrumentMethod(proto, 'signWrappedPresentationRequest', 'vc.signWrappedPresentationRequest', (args, result) => ({ 'vera.wrapper': clip(args[0] && args[0].wrappedVPR), 'vera.signed': clip(result) }));
  instrumentMethod(proto, 'verifyWrappedPresentation', 'vc.verifyWrappedPresentation', (args, result) => ({ 'vera.wrapper': clip(args[0] && args[0].wrappedPresentation), 'vera.verified': result && result.isValid, 'vera.error': result && result.error }));
  instrumentMethod(proto, 'verifyPresentation', 'vc.verifyPresentation', (args, result) => ({ 'vera.presentation': clip(args[0] && args[0].presentation), 'vera.verified': result && result.isValid, 'vera.error': result && result.error }));
  instrumentMethod(proto, 'createPresentation', 'vc.createPresentation', (args, result) => ({ 'vera.presentation': clip(args[0]), 'vera.created': clip(result) }));
}

function patchW3cJsonLdCredentialService(exports) {
  const Service = exports && exports.W3cJsonLdCredentialService;
  if (!Service) return;
  instrumentMethod(Service.prototype, 'verifyCredential', 'vc.verifyCredential', (args, result) => ({
    'vera.credential': clip(args[0] && args[0].credential),
    'vera.verified': result && (result.isValid !== undefined ? result.isValid : result.verified),
    'vera.error': result && result.error,
  }));
}

function patchDigitalCredentials(exports) {
  if (!exports || typeof exports.issue !== 'function') return;
  instrumentMethod(exports, 'issue', 'vc.issue', (args, result) => ({
    'vera.credential': clip(args[0] && args[0].credential),
    'vera.signedCredential': clip(result),
  }));
}

function patchAgentInitializer(exports) {
  const Service = exports && exports.AgentInitializer;
  if (!Service) return;
  const proto = Service.prototype;
  instrumentMethod(proto, 'attachNonRepudiationMaterial', 'css.attachNonRepudiationMaterial', (args) => ({ 'vera.messageHash': args[2], 'vera.requesterDid': args[1] }));
  instrumentMethod(proto, 'verifySignedResource', 'css.verifySignedResource', (args, result) => ({ 'vera.nrr': clip(args[0]), 'vera.verified': result ? 'true' : undefined }));
  instrumentMethod(proto, 'generateHashCredentials', 'css.generateHashCredentials', (args, result) => ({ 'vera.holderDid': args[0], 'vera.messageHash': args[1], 'vera.nro': clip(result) }));
}

function patchJwsGraphService(exports) {
  const Service = exports && exports.JwsGraphService;
  if (!Service) return;
  instrumentMethod(Service.prototype, 'storeVerifiedJws', 'css.storeVerifiedJws', (args, result) => ({ 'vera.nrr': clip(args[0]), 'vera.record': clip(result) }));
}

function patchVpChecker(exports) {
  const Service = exports && exports.VpChecker;
  if (!Service) return;
  instrumentMethod(Service.prototype, 'verifyNew', 'css.VpChecker.verifyNew', (args, result) => ({
    'vera.vp': clip(args[0] && args[0].headers && args[0].headers.vp),
    'vera.credentials': clip(result),
  }));
}

// Patch on load, so the app's own require triggers it and modules that need a
// reflect-metadata polyfill are only loaded by the app, not by this register.
function installOnLoadPatchers() {
  const patched = new Set();
  const load = Module._load;
  Module._load = function (request, parent, isMain) {
    const exports = load.apply(this, arguments);
    try {
      if (exports) {
        const filename = Module._resolveFilename(request, parent);
        if (!patched.has(filename)) {
          patched.add(filename);
          const base = path.basename(filename);
          if (base === 'EnvelopeService.js') patchEnvelopeService(exports);
          else if (base === 'W3cCredentialService.js') patchW3cCredentialService(exports);
          else if (base === 'W3cJsonLdCredentialService.js') patchW3cJsonLdCredentialService(exports);
          else if (base === 'AgentInitializer.js') patchAgentInitializer(exports);
          else if (base === 'JwsGraphService.js') patchJwsGraphService(exports);
          else if (base === 'VpChecker.js') patchVpChecker(exports);
          else if (request === '@digitalcredentials/vc') patchDigitalCredentials(exports);
        }
      }
    } catch { /* ignore */ }
    return exports;
  };
}

// --- Start -----------------------------------------------------------------

const sdk = new NodeSDK({
  instrumentations,
  resourceDetectors: getResourceDetectorsFromEnv(),
  spanLimits: {
    attributeValueLengthLimit: 65536,
    attributeCountLimit: 1024,
  },
});

if (logLevel != null) diag.disable();

try {
  sdk.start();
  captureBodies();
  installOnLoadPatchers();
  diag.info('OpenTelemetry automatic instrumentation started successfully');
} catch (error) {
  diag.error('Error initializing OpenTelemetry SDK. Application will not produce telemetry', error);
}

async function shutdown() {
  try {
    await sdk.shutdown();
    diag.debug('OpenTelemetry SDK terminated');
  } catch (error) {
    diag.error('Error terminating OpenTelemetry SDK', error);
  }
}

process.on('SIGTERM', shutdown);
process.once('beforeExit', shutdown);
