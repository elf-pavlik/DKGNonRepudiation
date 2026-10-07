// Zero-code OpenTelemetry setup for the demo parties.
//
// Mounted at /otel/register.js and loaded through NODE_OPTIONS=--require, so the
// SDK starts before the application code. The packages live in the otel-node
// volume at /otel/node_modules. It mirrors
// @opentelemetry/auto-instrumentations-node/register, adding HTTP header capture.
const { NodeSDK } = require('@opentelemetry/sdk-node');
const { diag, DiagConsoleLogger } = require('@opentelemetry/api');
const { getStringFromEnv, diagLogLevelFromString } = require('@opentelemetry/core');
const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
// Not a public export, but it is what the default register uses.
const {
  getResourceDetectorsFromEnv,
} = require('/otel/node_modules/@opentelemetry/auto-instrumentations-node/build/src/utils.js');

const logLevel = getStringFromEnv('OTEL_LOG_LEVEL');
if (logLevel != null) {
  diag.setLogger(new DiagConsoleLogger(), { logLevel: diagLogLevelFromString(logLevel) });
}

// In @opentelemetry/instrumentation-http >= 0.53 this option nests under
// server/client. The flat { requestHeaders, responseHeaders } shape of earlier
// versions is ignored.
const headersToSpanAttributes = {
  server: {
    requestHeaders: [
      'agent', 'client', 'issuer', 'didvc', 'vp', 'signedresource',
      'x-forwarded-host', 'x-forwarded-proto',
    ],
    responseHeaders: ['www-authenticate', 'encryptedresource', 'keyfordecrypt'],
  },
  client: {
    requestHeaders: [
      'agent', 'client', 'issuer', 'didvc', 'vp', 'signedresource',
      'x-forwarded-host', 'x-forwarded-proto',
    ],
    responseHeaders: ['www-authenticate', 'encryptedresource', 'keyfordecrypt'],
  },
};

const instrumentations = getNodeAutoInstrumentations({
  '@opentelemetry/instrumentation-http': { headersToSpanAttributes },
});

const sdk = new NodeSDK({
  instrumentations,
  resourceDetectors: getResourceDetectorsFromEnv(),
});

// NodeSDK installs its own DiagConsoleLogger from OTEL_LOG_LEVEL, so drop the one
// above to avoid a "Current logger will be overwritten" warning on start.
if (logLevel != null) {
  diag.disable();
}

try {
  sdk.start();
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
