# Interactive authentication

> Junction is independent and not affiliated with or endorsed by Microsoft. Use of Microsoft services is governed by Microsoft's terms; the software is provided as is, without warranty or liability. See [DISCLAIMER.md](../DISCLAIMER.md).


Device-code CLI login currently requires macOS Keychain. The native adapter
uses Apple's Security framework through Rust bindings. Windows and Linux native
storage adapters remain pending; interactive login returns an error on those
platforms. Existing headless environment credentials continue to work.

Copy `examples/device-code-context.json`, replace the tenant with your concrete
Entra tenant ID, and choose the delegated scopes your operations require. Use an
operator-owned Entra public-client application configured to permit device-code
authentication. Junction does not register applications or grant permissions.

```sh
junction context add work --file my-device-code-context.json
junction --context work auth login --client-id YOUR_APPLICATION_ID
junction --context work auth status
junction auth accounts
junction --context work auth token-info
junction --context work describe graph.users.list
junction --context work auth logout
```

Login prints the verification URL and human-facing user code to stderr. Follow
that prompt in your browser. The default timeout is 600 seconds;
`--timeout-seconds` accepts 1 through 3,600 seconds, and Ctrl-C cancels polling.
Successful stdout contains only safe token metadata. The secret device code and
access token never enter the prompt or command output.

Access credentials are stored in Keychain under the service
`dev.jusso.junction.tokens.v1`. The account key is a SHA-256 digest of the complete
normalized acquisition context: tenant, authority, audience, scopes, credential
profile and flow. A loaded record must match that context. Expired credentials
are unavailable for execution. When `offline_access` was requested and Entra
returns a refresh token, login saves that credential and its original client ID
in the same Keychain record. No plaintext credential-file fallback exists.

Rust callers can take a refresh credential from a completed device-code or
authorization-code session, or retrieve it with `StoredTokens::load_refresh`.
`RefreshTokenProvider::acquire` exchanges that credential against its original
tenant and authority, retaining the original audience, scopes and client ID.
Confidential clients must supply their client secret separately. Successful
renewal returns an access/refresh pair for `StoredTokens::save_with_refresh`;
any rotated refresh token replaces the previous secret. If the server omits a
replacement, the existing refresh credential remains in the returned pair.

CLI execution automatically renews an expired access credential when a saved
refresh credential is available, then stores the new pair before execution.
Login, acquisition/renewal and logout hold the same OS file lock for the complete
credential transaction. Contending commands return a busy error and can be
retried. CLI stderr identifies contention as `credential_busy` with
`retryable: true` and a nonzero exit status. MCP tool errors include
`status: credential_busy` and `retryable: true`; the local HTTP API returns the
same structured error with HTTP 429. Other lock failures are not mislabeled as
contention. A completed logout therefore cannot be overwritten by an earlier
renewal from a cooperating Junction process. Revoked refresh credentials and
failed renewal never automatically initiate an interactive prompt.

Locks live in `$HOME/.junction-credential-locks`, independently of the current
project directory. All processes accessing the same Keychain must use the same
operator home. On Unix, the directory must be operator-owned with mode 0700 and
files must be regular, singly linked, operator-owned and private. Symlink files
and directories are rejected. Files contain no credentials and remain after
release to preserve stable lock identities. Rust callers performing their own
storage writes remain responsible for equivalent coordination.

CLI execution, batch execution, LRO waiting, MCP execution and the local HTTP
host read stored device-code credentials without automatically initiating login.
`auth status` reads storage without contacting Microsoft. An expired access token
with a saved refresh credential reports `renewal_available`; that means renewal
can be attempted, not that the server will accept the grant. For headless flows,
it reports `environment_credential`, which does not establish that credentials
are present or valid; `auth token-info` acquires or validates those credentials.

`auth accounts` lists interactive profiles referenced by named local contexts;
it does not enumerate all Keychain entries or claim to identify signed-in users.
Identity/account claims and granted scopes/roles remain unknown unless verified.
`auth logout` removes the exact selected acquisition context. Credentials stored
for other audiences, scope sets, profiles or tenants remain separate. Logout
does not revoke Microsoft tokens or terminate browser sessions.

Browser PKCE/confidential authorization-code providers are available to Rust
callers, but CLI browser login, profile-wide logout and
Windows/Linux secure persistence remain in development. Live Entra login and
native Keychain round-trip acceptance testing are still required.

Headless RSA certificate client credentials are also available through the
`certificate` flow. See [certificate authentication](CERTIFICATE-AUTHENTICATION.md)
for environment variables, DER key requirements, context bindings and verification limits.

## Out-of-band API keys

Some Microsoft services issue credentials outside Entra ID. Junction supports
them with the `api_key` flow and an explicit placement:

| Service | Placement | Example context |
| --- | --- | --- |
| Defender for Cloud Apps API token | `{"header":"authorization","prefix":"Token"}` | `examples/defender-cloud-apps-api-key-context.json` |
| Azure DevOps personal access token | `{"header":"authorization","prefix":"Basic"}` (sent as Basic `:<PAT>`) | `examples/azure-devops-pat-context.json` |
| Subscription or function keys | `{"header":"ocp-apim-subscription-key"}`, `{"header":"x-functions-key"}`, `{"header":"api-key"}` or `{"header":"x-api-key"}` | |

Only these credential headers are accepted. Declared operation parameters can
never set them. Junction never accepts the key as a command-line argument or
context value. It looks for a key in this order:

1. the `JUNCTION_API_KEY_<PROFILE>` environment variable (profile upper-cased,
   other characters replaced by `_`), for headless and CI use;
2. the OS credential store (macOS Keychain), saved by `junction auth login`;
3. CLI execution only: a prompt on the controlling terminal. Echo is disabled
   before the prompt appears, and you can optionally save the key.

MCP and HTTP hosts never prompt. Agents receive a secret-free
`{"status":"credential_required","flow":"api_key","environment_variable":...,"remediation":...}`
response telling the operator to provide the key out of band.

```sh
junction context add mdca --file examples/defender-cloud-apps-api-key-context.json
junction --context mdca auth login          # prompts for the key, saves it
junction --context mdca auth status         # api_key_saved | api_key_environment | api_key_required
junction --context mdca execute defender.cloud_apps.alerts.list --input '{}'
junction --context mdca auth logout         # removes the saved key
```

Saved keys are bound to tenant, audience, profile and placement. They are kept
for up to a year (access tokens: one day), and are replaced by logging in again.
On platforms without native secure storage (currently Windows and Linux), use
the environment variable or the per-run prompt; keys are never written to
files.
