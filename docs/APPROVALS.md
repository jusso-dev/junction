# Trusted approvals

> Junction is independent and not affiliated with or endorsed by Microsoft. Use of Microsoft services is governed by Microsoft's terms; the software is provided as is, without warranty or liability. See [DISCLAIMER.md](../DISCLAIMER.md).


The policy library now exposes an in-memory `ApprovalGrant` capability through
`Policy::issue_approval` and `Policy::authorize_with_approval`. Issuance is an
explicit trusted operator action. It is not exposed through MCP or HTTP tools,
and agents cannot deserialize a grant or set an approval boolean.

A grant binds the complete operation metadata, current policy, concrete tenant,
exact JSON input, and a typed `ApprovalContext` containing cloud, endpoint, audience and credential
profile. Its constructor requires a plain HTTPS destination and nonempty audience
and profile, rejecting URL credentials, query strings and fragments. Concrete
tenant validation excludes shared login aliases such as common/organizations. Grants last at most
five minutes and are consumed by value. Private fields and the absence of Clone,
Debug, Serialize and Deserialize prevent ordinary copying, logging or importing
capabilities from untrusted input.

Authorization always checks current policy first. Deny rules and read-only mode
cannot be overridden. Changed input, context, operation metadata, policy or
expired lifetime rejects a request that still requires approval. Input is bounded
to 128 KiB for issuance. Grants hold request input in memory and must never be
placed in diagnostics or agent output.

The Rust runtime now provides `prepare_with_approval` for preparing an approved
request using the same input, endpoint, parameter and schema validation as ordinary
preparation. It consumes the grant and takes its destination from the bound
ApprovalContext. This helper does not acquire credentials or send a request,
and unresolved external schema references still fail validation.

The trusted Rust `Executor::execute_with_approval` API now consumes a grant,
rechecks current policy and exact input, validates the execution endpoint and
audience against the grant binding, and validates token tenant, audience and
expiry before transport. It retains registry schema validation and governed HTTP
retries. The trusted caller must independently establish cloud and credential
profile; token metadata does not attest those fields.

Ordinary runtime execution still rejects approval-required requests.

## CLI operator approval

`junction execute <operation> --approve` is the operator path. It:

1. resolves the operation and requires a current `approval_required` decision
   (allowed requests are refused with `approval_not_required`; deny rules and
   read-only mode return their usual `policy_rejected` error);
2. validates the complete request against registry schemas by issuing and
   discarding a grant, so invalid input never reaches a human reviewer;
3. opens the controlling terminal directly (`/dev/tty`; `CONIN$`/`CONOUT$` on
   Windows), never stdin or arguments, and shows operation, risk, policy reason,
   method and path, API version, tenant, cloud, endpoint, audience, credential
   profile and the exact JSON input with control characters neutralised;
4. requires the operator to retype the operation identifier and a fresh random
   six-character code shown only on that terminal;
5. issues a single-use grant (five minutes) bound to the same tenant, input,
   policy and `ApprovalContext`, acquires credentials and consumes the grant in
   `execute_with_approval` or `start_lro_with_approval`.

Status polling of an approved long-running operation is a read: polling accepts
`approval_required` decisions but still stops on deny rules or read-only mode.

Limits: a process that controls a pseudo-terminal can still type into it, so
the terminal prompt proves operator presence only when agents do not run with
the operator's terminal. Do not give agents an interactive shell on the
operator's TTY. Grants are not persisted, are not shared across processes and
are not available through MCP or HTTP; `--approve` cannot be combined with
`--all`. Durable, cross-process or remote approvals remain future work.
