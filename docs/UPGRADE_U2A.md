# GitHub Issues read adapter - U2-A, 12 October 2026

U1 passed main independent local acceptance on 12 October 2026 at
06:45:14 UTC: 88 tests, 13 commands, 137 direct SQLite/fixture assertions and
four negative controls. The reviewed U1 V3 manifest SHA-256 is
03286cef620e30bc45a274849d6b44579bdaab4be0aadf5b6d98d3654f813e24.
The acceptance-bound U1 actor code SHA-256 is
044534ac943f15fcff8077326478ef3cd011b4fbf025daf9f9a88574fc19aa15.
Those results concern fictional scripted/local-double observations. They do
not establish actual model quality, billing, GitHub access or deployment.
The original U1 walkthrough and all three source manifests retain their dated
historical content; this update does not rebind their evidence to new source.
Adding U2-A modules changes the directory-wide source fingerprint used by
future runs. Every original U1 module remains byte-identical; the new manifest
records both fingerprints. Existing run receipts remain bound to their old
code/configuration, and cannot be silently resumed against a new fingerprint.

U2-A adds Python 3.11 stdlib modules `sandbox`, `sandbox_transport` and
`sandbox_worker`, with an injected read contract and a prepared local HTTP
batch. The adapter is separate from the original evidence/provider loop.
There is no CLI credential loader, model tool registration, POST method,
comment executor, containment action or new evaluation dataset in this slice.

## Read contract

Trusted operator configuration supplies numeric account, app, installation,
repository and issue IDs; issue numbers are pinned separately because the
[Get an issue route](https://docs.github.com/en/rest/issues/issues#get-an-issue)
uses an issue number. At most three approved issue bindings also pin the
fixture SHA-256 and canonical record version. Labels or a title alone never
grant authority. The title must start `[STA-SANDBOX-20261011] `, the labels
must include `security-triage-sandbox`, and the body must contain the exact
`[STA-FIXTURE-SHA256:<reviewed hash>]` marker. PR-shaped objects are rejected.

All calls are GETs to fixed `api.github.com` routes constructed from the
configuration: installation repository list, configured repository, approved
issues and their comments. Repository responses must match numeric repository
and owner IDs, owner login, full name and canonical URL. Comment records must
match the issue URL and canonical comment URL. No response URL is dispatched.

The future main loader must supply a short-lived installation token with a
trusted attestation binding app/installation/account IDs, exactly this numeric
repository, Issues read and Metadata read permissions, expiry, dispatch ID and
configuration hash. The adapter checks that attestation before every request.
It then requires exactly one repository from
[installation repository access](https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation)
and cross-checks repository/account identity. This API response does not attest
the token's installation ID or permission grant, and public GET success alone
does not prove authenticated access. Those facts remain main loader and external
review gates. No real loader, token or account was accessed for U2-A.

Issue version is SHA-256 over canonical ID/number, title, body, state,
updated_at, comment count, sorted label names and canonical route URLs.
Comments are read between two checks of the approved issue version. The
snapshot binds the configuration, issue version and each comment's ID,
timestamp, body and actor. This bookend detects observed issue drift; it is
not a remote transaction and cannot rule out unobserved intermediate changes.
Only a complete snapshot is returned; no partial read authorizes effects.

One session reserves before dispatch, halts on any failure and permits at most
20 requests, 60 seconds, two pages of 50 comments, 64 KiB per response and
128 KiB per returned snapshot. Concurrent session/transport use is rejected.
An owned child covers DNS, connect, headers and body; the parent checks total
deadline/cancellation and allows at most two seconds cleanup. The child uses
certificate-verified HTTPS or explicit credential-free loopback mode, inherits
the U1 Windows runtime environment allowlist and sends secrets only in private
stdin. It follows no redirect, inherits no ambient proxy and emits no error
body or reflected token. Pagination links are validated against the fixed
comment route and two-page bound; the next request path is constructed locally.

Failures distinguish authentication (401), forbidden (403), absent (404), rate
limit (429 or rate-signalled 403), service failure (5xx), redirect, invalid
schema/version, byte/page/request limits, deadline, cancellation and transport
loss. There are zero automatic retries. Numeric Retry-After and reset metadata
are retained without shortening them; a trusted later dispatch must wait and
recheck authority. Unknown rate metadata stays unknown. No sleep or retry is
performed inside the read session.

## API contract and source attribution

Official GitHub documentation was checked on 12 October 2026. The adapter pins
`Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2026-03-10`.
[API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
documents this supported version and additive fields; incompatible required
fields or a reported different selected version fail closed. No automatic
version migration occurs. Get issue requires Issues read; the
[issue comments endpoint](https://docs.github.com/en/rest/issues/comments#list-issue-comments)
also accepts Issues read. The installation repository list has no additional
permission requirement. [Get repository](https://docs.github.com/en/rest/repos/repos#get-a-repository)
requires Metadata read for restricted repository metadata inspection.
U2-A rejects write scopes in its trusted token attestation; a later write slice
requires a separately reviewed token/grant.

[GitHub best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)
describe serial calls and rate delays. This sandbox deliberately hands off on
redirect or rate failure instead of adopting a new target or retrying. Such
changes require a new trusted manifest or dispatch. Documentation examples are
not copied as datasets; the one test case is author-created fictional data
under the repository MIT license. No new dependency or framework was added.

## Later comment intent and reconciliation design - unimplemented

A later explicit assignment may add a separate trusted operator apply path.
The model would prepare a read-only proposal; it cannot supply authority.
PREPARED intent must bind repository/account/issue IDs, approved issue version,
snapshot hash, raw/guarded packet hashes, exact UTF-8 note SHA-256 and bytes
(at most16 KiB), stable intent ID/marker, expected numeric app actor identity,
operator identity/approval source, nonce and expiry of at most24 hours.
Approval binds the full canonical intent digest. No SIMULATED approval suffices.

Apply would claim one durable local owner atomically, verify live manifest,
token scope, approval and expiry, and reread identity/marker/version immediately
before one POST. The intended states are PREPARED, APPROVED_SANDBOX_NOTE,
SENT, CONFIRMED, REJECTED, EXPIRED, STALE and UNKNOWN_REMOTE_OUTCOME.
201 alone would not confirm completion: independent GET must match exact
comment ID/body digest, intent marker, issue and expected app actor. A lost or
ambiguous POST response must never trigger an automatic retry. Bounded reads
would reconcile exactly one matching marker/digest/actor; zero, multiple,
partial or rate-limited matches remain unknown and hand off. A local unique
owner prevents local replay, not network exactly-once semantics. This design
has no executable write path in U2-A and is untested as a remote workflow.

## Checks and remaining gates

Pure injected checks use fake clocks, mock connections and blocked sockets /
subprocesses. Run only this module for the source/pure slice:

```powershell
py -3.11 -m unittest tests.test_upgrade_sandbox -v
```

The local HTTP/owned-child command below is authored and **UNEXECUTED**.
It requires main's separate heavy lease and checks complete GET reads, HTTP
failures/no replay, header/body deadlines, cancellation and connection loss:

```powershell
py -3.11 -m unittest tests.test_upgrade_sandbox_http -v
```

The worker handoff records exact source hashes, pure commands/results and a
minimal proposed native batch. U2-A main independent review, local HTTP batch,
regression suite, actual account/installation/token identity verification,
approved sandbox ID/fixture/version manifest and genuine GET receipts remain
pending. Any write, fresh evaluation/baseline, live model, operating comparison,
hosted CI or publication requires later explicit scope. U1 acceptance and v1
34/36 guarded versus32/36 raw results remain separate historical evidence.
