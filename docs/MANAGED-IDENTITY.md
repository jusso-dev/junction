# Azure VM managed identity

The Rust authentication library exposes
`junction_auth::managed_identity::ManagedIdentityProvider`. Construct it with a
validated `TokenRequest` using `AuthFlow::ManagedIdentity` and, optionally, the
UUID client ID of a user-assigned identity. Call `acquire().await` to obtain a
redacted `AccessToken`. Reused provider instances cache one token in memory and
serialize acquisition across concurrent callers. Tokens with 60 seconds or less
remaining are evicted before refresh, including when refresh fails. The total
deadline includes time waiting for another acquisition. Cached secrets remain
zeroized and are never persisted by this provider. Each provider is bound to its request; it cannot accept
another tenant, audience or credential profile at acquisition time.

The request's tenant and authority must be configured by the operator for the
identity attached to this Azure VM. IMDS cannot select a tenant and this provider
does not verify JWT claims. Its tenant metadata reflects that trusted binding,
not independently verified token identity. It never infers authorization from
unverified claims. Use a separate correctly configured provider for each identity.

Requests go directly to the fixed Azure VM IMDS address with `Metadata: true`,
API version `2018-02-01`, and the exact requested audience as `resource`. Optional
scopes must contain only that audience's `/.default` scope. Proxy use and redirects
are disabled; each HTTP request times out after ten seconds. Acquisition has a
120-second total deadline and at most five attempts. HTTP 404, 429 and 5xx
responses retry after 2, 6, 14 and 30 seconds; HTTP 410 waits 70 seconds for
IMDS upgrades. Numeric Retry-After values increase the delay, up to 70 seconds.
Larger or unsupported Retry-After values stop acquisition rather than retrying
early. Redirects, other status codes, transport failures and malformed successful
responses are terminal. Error bodies are discarded before waiting. Responses are bounded to
64 KiB, must return a Bearer token for the exact resource, and must have more than
60 seconds and at most seven days remaining. Response buffers and parsed token
strings are zeroized. Errors contain no token or upstream response content.

This follows Microsoft's [Azure VM token protocol](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token).
App Service, Azure Arc and other managed identity protocols need separate
adapters. CLI, MCP and HTTP execution select this provider when the trusted context uses
`"flow": "managed_identity"`. Set `AZURE_TENANT_ID` to the same concrete tenant as
the context. For a user-assigned identity set `AZURE_CLIENT_ID` to its UUID; leave
it unset for the system-assigned identity. No client secret or federated token
file is read for this explicitly selected flow. Wrong tenant or flow fails before
IMDS acquisition. See `examples/managed-identity-context.json`.

```sh
export AZURE_TENANT_ID=your-tenant-id
junction execute azure.resources.resource_groups.list --context-file examples/managed-identity-context.json --input '{}'
```

Replace the example tenant/subscription values and use a registry containing the
operation. The local default catalog currently includes only Graph.
Unit tests cover query binding, flow/scope restrictions, identity selection,
resource mismatches, expiry and redaction. Live VM acquisition remains unverified.

Returned token strings must satisfy the bearer-token syntax from
[RFC 6750 section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1).
Malformed whitespace, non-ASCII bytes, delimiters and misplaced padding are
rejected before authorization-header construction. A hosted transport test also
checks the Metadata header, absence of Authorization on acquisition, redirect
rejection, and declared/streamed response size limits. This socket test has not
been run in the local restricted environment.

Transport regression tests also exercise 429 → 503 → successful acquisition,
verify identical identity requests across retries and the minimum backoff, and
check termination after five consecutive 503 responses without error-body echo.
They compile and pass all-target Clippy. Local execution was attempted but
localhost socket binding was denied by the environment before any HTTP request;
the CI and daily release workflows run the full workspace tests without these
local exclusions. Hosted execution remains unverified.

The library cache belongs to a single provider instance, including its selected
user-assigned identity. `ManagedIdentityPool` retains at most 64 providers and
keys them by concrete tenant, authority, audience, normalized scope set, credential
profile, flow and optional client ID. The environment adapter uses one process-wide
pool, so CLI batch, MCP and HTTP execution can reuse tokens without sharing them
across different identities or contexts. Each acquisition still reads and validates
the selected environment identity before accessing the pool. Provider eviction
releases cached secrets once any in-flight callers finish. Separate processes
have independent caches; tokens are never persisted by this pool.
A non-socket test proves concurrent cached reuse, expiry boundaries, redaction
and isolation from a separately selected identity.
