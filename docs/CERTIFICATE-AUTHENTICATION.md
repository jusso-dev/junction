# Certificate client credentials

Junction can authenticate an Entra application with an RSA certificate through
the `certificate` flow. CLI execution, batch, token-info, MCP and the local HTTP
host use the shared environment credential selector. This currently implements
application client credentials; certificate-backed authorization-code and OBO
exchanges remain unfinished.

Use your own application registration and upload its public certificate to Entra.
Junction does not register applications or grant permissions. Copy
`examples/certificate-context.json`, replace its tenant/subscription, and select
the appropriate cloud and service. Explicit contexts put `flow: certificate`
inside `token_request`. The context chooses the authority and API audience;
Graph scopes are never substituted for another resource.

Supply these variables through the operator-owned process environment:

```sh
export AZURE_TENANT_ID="your-concrete-tenant-id"
export AZURE_CLIENT_ID="your-application-guid"
export AZURE_CLIENT_CERTIFICATE_PATH="/private/credentials/leaf-certificate.der"
export AZURE_CLIENT_PRIVATE_KEY_PATH="/private/credentials/key.pkcs8.der"
junction context add cert --file my-certificate-context.json
junction --context cert auth token-info
```

The certificate must be binary DER and the key must be unencrypted RSA PKCS#8
DER supported by ring. PEM, PFX, encrypted key containers and hardware-backed
signers are not supported yet. Conversion can be performed separately with your
certificate tooling; Junction needs no external executable at runtime. Unix key
files must be private (no group/other permission bits). Windows files rely on
operator-configured ACLs. Each file is bounded to 64 KiB; non-regular files and
symlinks are rejected. Protect the containing directories. Files are reread for
each acquisition so operator rotation takes effect without process restart.

Each exchange creates a fresh PS256 assertion containing the base64url SHA-256
certificate thumbprint, application issuer/subject, random UUID JWT ID, issuance
time and a five-minute lifetime. Its audience is the selected tenant's v2 token
endpoint, including sovereign/custom authorities. This follows
[Microsoft's certificate assertion format](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials).
Only the selected API's `.default` scope is requested. Explicit scopes must match
that scope. Environment tenant and requested flow are checked before reading
credential files; no client-secret or workload fallback occurs.

Private DER, signature and assertion buffers use zeroizing owners and are never
serialized or logged. The signing library's internal allocations are outside
that buffer-wiping guarantee. Public certificate bytes are hashed locally;
Junction does not parse the complete X.509 certificate, validate its chain/expiry,
or compare its public key with the private key. Entra verifies the registered
certificate and signature. Use a matching, valid certificate/key pair.

Token exchange shares the HTTPS-only, redirect-disabled, 30-second authentication
transport with bounded token responses and safe errors. Returned tenant/audience
metadata comes from trusted request bindings; granted roles and account identity
are not invented. Local tests verify signatures, claims, isolation, scope/flow
rejection, file limits and permissions. Live Entra certificate exchange and
platform acceptance remain unverified. Repository fixtures are public test-only
keys and must never be used as real credentials.
