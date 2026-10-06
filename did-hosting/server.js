// Minimal HTTPS static server for the did:web documents.
// It maps request Host + path to a file under /dids, e.g.
//   Host: secureissuer.solidcommunity.net  GET /public/did.json
//   -> /dids/secureissuer.solidcommunity.net/public/did.json
const https = require('https');
const fs = require('fs');
const path = require('path');

const ROOT = process.env.DIDS_ROOT || '/dids';
const KEY = process.env.TLS_KEY || '/certs/server.key';
const CERT = process.env.TLS_CERT || '/certs/server.crt';
const PORT = Number(process.env.PORT || 443);

const server = https.createServer(
  { key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) },
  (req, res) => {
    try {
      const host = String(req.headers.host || '').split(':')[0];
      const urlPath = decodeURIComponent(String(req.url || '/').split('?')[0]);
      const hostRoot = path.join(ROOT, host);
      const filePath = path.normalize(path.join(hostRoot, urlPath));
      if (!filePath.startsWith(hostRoot)) {
        res.writeHead(403, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'forbidden' }));
      }
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const isLd = filePath.endsWith('.jsonld');
        res.writeHead(200, { 'content-type': isLd ? 'application/ld+json' : 'application/json' });
        return res.end(fs.readFileSync(filePath));
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found', host, path: urlPath }));
    } catch (error) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String(error && error.message || error) }));
    }
  },
);

server.listen(PORT, () => console.log(`did-host listening on :${PORT} serving ${ROOT}`));
