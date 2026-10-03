# Demo Application for Solid CSS
Demo Application to interact with Community Solid Server using Verifiable Credentials.
Similarly to the other packages of this project, it requires updated version of the four libraries.
```
credo-ts-core-0.5.3.tgz
digitalcredentials-vc-7.0.0.tgz
sphereon-pex-3.3.3.tgz
sphereon-pex-models-2.2.4.tgz
```

```bash
yarn build # To build the webpack project
yarn install
```

Before to run the server, you have to rename the config file contained in ```config/custom.json``` to ```config/default.json```.
Once you customized the parameters, then it is possible to start the server, which in first execution will print out the DIDDocument that you need to host in somewhere (I suggest did:web in you github repo, as existing in this under ```config/did.json```).

Finally, copy the content of ```dist``` to ```public``` folder.
```bash
yarn run start-express
```
At this point you can re-run the server by changing the variable did on line 80 of ```app.js```
```javascript
did = "<Insert here the new DID, depending on where you hosted the DIDDocument>"
```

When the CSS sends an encrypted resource with a `NonRepudiableOrigin`, the demo app now validates that material and stores it as RDF Turtle under `.internal/nro-audit/records`. The read-only query endpoint is:
```bash
GET /.internal/nro-audit/query?resource=<resource-url>&requesterDid=<did>
```
You can use one filter or both, and optionally add `messageHash=<sha256>` or `issuerDid=<did>`.
