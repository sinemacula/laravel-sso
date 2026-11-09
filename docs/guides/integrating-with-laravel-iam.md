# Integrating with `laravel-iam`

This package references no class, interface or configuration of another package of the suite. Every point where the
suite cooperates is a seam of its own: a contract with a default that fails closed, an event, or a helper the
application calls. `laravel-iam` holds the adapters that bind those seams to `laravel-authentication` and `laravel-mfa`.
This guide is the adapter's specification: every contract under `Contracts` and every event, the
`laravel-authentication` requirement (`AUTH-…`) each one meets, the transaction rule, the lock order, the one place each
write happens, and the checks an adapter must pass before it ships. An application that wires the siblings itself,
without `laravel-iam`, follows it the same way.

> [!IMPORTANT]
> Sibling names here are not released contracts. Each is marked by where it comes from (see
> [Where the sibling names come from](#where-the-sibling-names-come-from)), and an adapter is written against the
> sibling's release, not against this guide. Where a release differs, the release wins and this guide is corrected.

## Where the sibling names come from

- **PR #127**: `laravel-authentication`'s phase 14a, merged as commit `c7b6b119` on its `master` (2026-11-03):
  `ExternalIdentityLinks::find()`, `signInExternally()`, `reauthenticateExternally()`, `externalStanding()`,
  `ExternalResult`, `ExternalEvidencePolicy`, `linkRemoved()`, `linkScopeWidened()`, the connection guard rows, its
  storage setting, its events and their context keys, its provenance table, its application policy and its identifier
  normaliser, all read in that merged tree.
- **PR #128**: `laravel-authentication`'s phase 14b, merged as commit `a29d2751` on its `master` (2026-11-03):
  `Auth::context()`, `Contracts\AuthenticationContextContributor`, `Context\ContributionSubject`,
  `Context\ContextContributors`, `ExternalResult::$requestReference`, and the `connection_id` and `request_reference`
  keys of its event context, all read in that merged tree.
- **PR #129**: `laravel-authentication`'s per-session issuance guard and provider context, merged as commit `86ec3ba6`
  on its `master` (2026-11-03): `External\ProviderContext`, `ExternalResult::$providerContext`,
  `Proofs\Provenance::$providerContext` and the issuance guard every issuance of an access token for a session writes
  (`issuance_sequence` on its sessions table), all read in that merged tree.

No tagged release carries any of the three PRs yet, so their names are final and merged but not a released contract.

- **Reported**: what `laravel-authentication`'s maintainer reported for its phases 9, 10, 11 and 13 (its PRs #118,
  #119, #120 and #123), and what `laravel-mfa` reported on 2026-11-02, confirmed against this package's PR #14. None
  is released.

Where a PR #127 name supersedes a reported one, both are given. Phase 13 reported `linkRemoved(Identity $identity,
string $connectionId)`; phase 14a re-keyed it to the link, and PR #127 has `linkRemoved(Identity $identity, string
$connectionId, string $linkId)`. Every other name in this guide is the package's own.

## Handoff codes are this package's

The package issues, stores and redeems every handoff code, under `laravel-iam` as alone. `laravel-authentication`
stores no handoff codes: its maintainer decided so for its phase 14a, and it exposes only the external sign-in and
re-authentication entry points the adapter calls inside the transaction, after the package's `admit()`. FEATURES'
SSO-9.2 and its seam table, which bind the codes to AUTH-3.10's under `laravel-iam`, predate that decision; the
requirement closure matrix records the reconciliation (SSO-9.2/f).

So the adapter keeps `Contracts\HandoffIssuer` bound to its default, `Handoffs\DatabaseHandoffStore`, and redeems with
`Handoffs\HandoffRedemption`. It never binds an issuer of its own, and never uses `Handoffs\HandoffRecheck`, which is
for an application that issues codes of its own. AUTH-3.10's obligations hold through the package's codes: single use, a
60-second default lifetime capped at 300, stored only as a hash, bound to the purpose, the application, the connection,
the request's public reference, the verifier's S256 challenge, the identity of a `link` and the session of a
`reauthenticate`, and consumed atomically. A handoff code, a request reference and a verifier are three kinds, never
accepted as one another or as a token (AUTH-5.7). Each code also keeps the connection's trust version it was issued
under: a change to the connection's trust before the code is redeemed (its certificates replaced, one distrusted, an
anchor changed, or the connection disabled and enabled again) voids it and refuses it, so the adapter's `admit()`
answers `handoff_unknown`, and never signs anyone in against the connection as it was; a certificate added alone
changes nothing.

## The transaction rule

Decision D5: every write that must be atomic with the package goes through **the same Laravel connection, inside the
same transaction**. Reaching the same database through another Laravel connection is not atomic, and neither is a write
made after the package's transaction has committed.

- `sso.storage.connection` and `laravel-authentication`'s `authentication.storage.connection` (PR #127) name the same
  Laravel connection. Leaving both unset uses the default connection for both.
- The adapter opens the transaction itself, with
  `DB::connection(SineMacula\Laravel\Sso\Database\StorageConnection::name())->transaction(...)`, and makes the package's
  call and the sibling's call inside it. The package's work is a savepoint in it; so is the sibling's.
- `Contracts\SessionRevocation` is called by the package inside the transaction that makes the change, and the adapter
  revokes inside it, through that connection.
- Any isolation level works, and neither package refuses one. Under PostgreSQL's `REPEATABLE READ` or `SERIALIZABLE`,
  the package locks rows whose versions it raises, and authentication (PR #127) writes a guard row in
  `authentication_connection_guards` (64 per connection, a link taking one by a hash of its id) for every sign-in
  through a link and every revocation of a link's or a connection's sessions, so the later of a racing pair fails to
  serialise (SQLSTATE `40001`) rather than missing the other. Authentication (PR #129) also writes a session's
  issuance guard, one `UPDATE` of the session's row, before every issuance of an access token for it reads the
  session's proofs, `reauthenticateExternally()` included, so of two issuances racing for one session the later fails
  to serialise the same way. A serialisation failure, a deadlock and an `Exceptions\LinkCandidatesChanged` are retried
  only as the caller's whole transaction, from its start, never in part.
- Events wait for the commit, of either package, and none is reported when the transaction rolls back (SSO-10.5). No
  security decision is made by a listener.

## Seam inventory

### Contracts

Every contract under `src/Contracts`, with its default, what `laravel-iam` binds it to and the requirement it meets.
"None" in the AUTH column marks a seam with no `laravel-authentication` counterpart: the adapter leaves it at the
package's default or binds the application's own.

| Contract                   | Default                                       | Under `laravel-iam`                                                                                                                                                | AUTH                    |
|----------------------------|-----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|
| `ApplicationPolicy`        | `Applications\ConfiguredApplicationPolicy`    | `allowed` exactly when the application's sign-in methods allow `external_provider` (PR #127 `Contracts\ApplicationPolicy`, `SignInMethodManager::EXTERNAL_METHOD`) | AUTH-3.7                |
| `AttemptLimiter`           | `RateLimiting\DatabaseAttemptLimiter`         | the default: the package's own limits, apart from authentication's                                                                                                 | AUTH-10.x (rules only)  |
| `Clock`                    | `Clock\SystemClock`, reading Laravel's `Date` | the default, so both packages read one clock                                                                                                                       | AUTH-10.x (rules only)  |
| `CompletionStage`          | the package's stages                          | nothing: a package extension point                                                                                                                                 | None                    |
| `ConfigurationCheck`       | the package's checks                          | nothing                                                                                                                                                            | None                    |
| `DnsResolver`              | `Domains\SystemDnsResolver`                   | the default, or the application's bounded resolver                                                                                                                 | None                    |
| `EndpointResolver`         | `Endpoints\ConfiguredEndpointResolver`        | the default, or the application's                                                                                                                                  | None                    |
| `Enforcement`              | `Enforcement\DatabaseEnforcement`             | the default; folded into the tenant authentication policy ([Enforcement](#enforcement-in-the-tenant-authentication-policy))                                        | AUTH-2.12               |
| `EnforcementExemption`     | `Enforcement\NoExemptions`                    | the application's break-glass rule, asked through `Enforcement\ExemptionGate`                                                                                      | AUTH-2.12               |
| `EnforcementInheritance`   | `Enforcement\OwnTenantInheritance`            | the application's tenant tree                                                                                                                                      | AUTH-2.12 (tenant tree) |
| `EvidencePolicy`           | `Evidence\InsufficientEvidence`               | the application's choice; the first of the two gates ([Evidence](#evidence-and-laravel-mfa))                                                                       | AUTH-3.6, AUTH-3.12     |
| `Fetcher`                  | `Fetching\GuzzleFetcher`                      | the default, or an egress proxy that keeps its rules                                                                                                               | None                    |
| `Freshness`                | `Freshness\RefusingFreshness`                 | authentication's freshness check, with the package's maximum age as the caller's requirement ([Freshness](#freshness))                                             | AUTH-3.11               |
| `HandoffIssuer`            | `Handoffs\DatabaseHandoffStore`               | the default, always ([Handoff codes](#handoff-codes-are-this-packages))                                                                                            | AUTH-3.10 (reconciled)  |
| `HostResolver`             | `Fetching\SystemHostResolver`                 | the default, or the application's bounded resolver                                                                                                                 | None                    |
| `LinkConfirmation`         | `Linking\RefusingLinkConfirmation`            | judged from the given caller's session's provenance and proofs ([Linking](#linking-by-a-verified-domain-and-confirmation))                                         | None (reads AUTH-6.1)   |
| `LinkEligibility`          | `Linking\RefusingLinkEligibility`             | the identity's membership of the connection's tenant                                                                                                               | None (reads AUTH-2.x)   |
| `LinkEmailMatcher`         | `Linking\NoEmailMatches`                      | the identity's verified email, through authentication's identifier normaliser                                                                                      | AUTH-3.1                |
| `LinkLimit`                | `Links\OneLinkPerConnection`                  | the default, or the application's                                                                                                                                  | None                    |
| `LinkStorage`              | none (`Links\NoLinks` is not one)             | `Links\LinkStore`, which it implements                                                                                                                             | AUTH-3.9                |
| `Linker`                   | `Links\NoLinks`                               | `Links\LinkStore`; authentication's link contract answers from the same admission ([Links](#links))                                                                | AUTH-3.9                |
| `PrincipalScope`           | `Linking\RefusingPrincipalScope`              | the identity's complete set of principals                                                                                                                          | None (reads AUTH-2.x)   |
| `ProtocolDriver`           | `saml2`, `oidc`                               | nothing                                                                                                                                                            | None                    |
| `ProtocolSettings`         | each driver's settings                        | nothing                                                                                                                                                            | None                    |
| `ProviderSessionDeadline`  | `Results\ProviderDeadlineLimitsSession`       | the default; the effective deadline becomes the session's cap                                                                                                      | AUTH-6.1                |
| `PurposeBranch`            | the package's three branches (`@internal`)    | nothing                                                                                                                                                            | None                    |
| `ReauthenticationSessions` | `Flows\NoReauthenticationSessions`            | the sessions of authentication ([Re-authentication](#reauthenticate-one-renewal))                                                                                  | AUTH-3.11, AUTH-8.2     |
| `RedirectUriResolver`      | `Applications\ConfiguredRedirectUriResolver`  | the default, or the application's                                                                                                                                  | None                    |
| `ReinitiatingDriver`       | the SAML driver                               | nothing                                                                                                                                                            | None                    |
| `SecretEncrypter`          | `Secrets\LaravelSecretEncrypter`              | the default                                                                                                                                                        | AUTH-10.x (rules only)  |
| `SessionRevocation`        | `Revocation\NoSessionRevocation`              | authentication's revocation helpers ([Revocation](#revocation))                                                                                                    | AUTH-2.12, AUTH-6.4     |
| `SingleUseStore`           | `SingleUse\DatabaseSingleUseStore`            | the default                                                                                                                                                        | None                    |
| `SsoConnection`            | `Models\Connection`                           | nothing: what the other contracts are given                                                                                                                        | None                    |
| `SsoEvent`                 | every package event                           | one listener for every event, `laravel-audit-log`'s mapping among them ([Events](#events))                                                                         | AUTH-9.x                |
| `TenantMembership`         | `Linking\NoTenantMembership`                  | the identity's membership of the tenant and when the person accepted it                                                                                            | None (reads AUTH-2.x)   |

### Helpers the adapter calls

| Helper                                         | What for                                                                                                                                        | AUTH                |
|------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|
| `Handoffs\HandoffRedemption::admit()`          | Redeeming `sign_in` and `reauthenticate` codes inside the adapter's transaction                                                                 | AUTH-3.10, AUTH-8.1 |
| `Handoffs\HandoffRedemption::redeem()`         | Redeeming `link` codes, standalone                                                                                                              | AUTH-3.10           |
| `Linking\ScopeWidening::widened()`             | First in every transaction that gives a person a principal                                                                                      | AUTH-2.x            |
| `Enforcement\ExemptionGate::admit()`           | Asking the exemption contract, and reporting an exemption used, from the tenant authentication policy                                           | AUTH-2.12           |
| `Provisioning\ProvisioningHelper::link()`      | Linking a just-created identity from the one provisioning listener                                                                              | AUTH-3.9            |
| `Links\LinkService`                            | Listing an identity's links (accepting `me`) and removing one                                                                                   | AUTH-3.9            |
| `Sessions\AuthenticationContext::fromStored()` | Projecting a session's stored `Sessions\Provenance` into the `sso` namespace ([The `sso` contributor](#the-sso-contributor))                    | AUTH-11.8           |
| `Config\ConfigurationChecks::add()`            | Adding `laravel-iam`'s checks across the packages it composes to SSO's boot check and `sso:check`, each applying only while SSO is in use       | IAM-13.12           |

Every helper above that counts an attempt or reports an event takes the client it acts for as an `Http\ClientContext`:
the IP address and the user agent, made safe to keep under the rules `laravel-authentication`'s own `ClientContext`
applies to the same two values. None reads the request being served. The adapter builds the context where it reads the
request, with `ClientContext::fromRequest($request)`, and passes `new ClientContext(null, null)` from a job or a
command. So do the contract methods that report: `Linker::resolve()`, `LinkStorage::create()`, `confirm()` and
`suspend()`, and `ProtocolDriver::complete()`; a wrapper of one passes on the client it was given.

### Events

Every event implements `Contracts\SsoEvent`, carries `Events\EventContext`, and is dispatched after the transaction that
caused it commits, except `ResultUnlinked`. None carries a secret, an assertion, a provider token, a verifier, a handoff
code, protocol state, a raw payload or a transport header. Events report: no adapter makes a security decision on one,
since the synchronous contracts do that (SSO-10.5).

| Event                                                                                                       | When                                                                     | AUTH counterpart                                                                                        |
|-------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| `AuthorizationRequestStarted`                                                                               | A flow started                                                           | None                                                                                                    |
| `ResultVerified`                                                                                            | A response verified, at completion                                       | AUTH-9.3's external-provider result verified, at redemption; correlated, never counted twice            |
| `ResultUnlinked`                                                                                            | An unlinked `sign_in`, synchronously, before any handoff                 | AUTH-3.9: provision here only; authentication's own `ExternalResultUnlinked` (PR #127) is informational |
| `HandoffIssued`                                                                                             | A code issued                                                            | AUTH-3.10 (reconciled: the package's code)                                                              |
| `HandoffRedeemed`                                                                                           | A code redeemed, after the adapter's commit                              | AUTH-9.3 at redemption (PR #127 `SessionCreated`, `SignedIn`, `SessionPending`)                         |
| `ReauthenticationCompleted`                                                                                 | A `reauthenticate` renewal committed                                     | AUTH-9.3 reauthenticated (PR #127 `Reauthenticated`)                                                    |
| `FlowFailed`                                                                                                | Every refused start, response, callback and redemption, once             | AUTH-9.x failures (PR #127 `AuthenticationFailed`)                                                      |
| `UnsolicitedResponseReinitiated`                                                                            | An unsolicited SAML response answered by re-initiation                   | None                                                                                                    |
| `LinkCreated`, `LinkRemoved`, `LinkActivated`, `LinkConfirmed`, `LinkSuspended`                             | A link's lifecycle; `LinkRemoved` follows the revocation it already made | None: authentication stores no links (AUTH-3.9)                                                         |
| `ConnectionCreated`, `ConnectionUpdated`, `ConnectionEnabled`, `ConnectionDisabled`, `ConnectionDeleted`    | A connection's administration; disabling and deleting revoked already    | None                                                                                                    |
| `DomainClaimed`, `DomainVerified`, `DomainRecheckFailed`, `DomainRestored`, `DomainLapsed`, `DomainRemoved` | A domain's lifecycle                                                     | None                                                                                                    |
| `EnforcementChanged`                                                                                        | A tenant's rule changed; its revocation ran already                      | AUTH-2.12 (reporting only: the revocation never waits for this event)                                   |
| `ExemptionUsed`                                                                                             | A session established under an exemption                                 | AUTH-2.12                                                                                               |
| `KeyAdded`, `KeyMadeCurrent`, `KeyRetired`, `KeyNearingExpiry`                                              | Keys and certificates                                                    | None                                                                                                    |
| `MetadataRefreshed`, `MetadataRefreshFailed`, `JwksRefreshed`, `JwksRefreshFailed`                          | Metadata and JWKS                                                        | None                                                                                                    |

## Redeeming by purpose

A code is redeemed only by the endpoint of its purpose, which fixes the purpose server side (SSO-9.9). Every response
carrying a code, a verifier or a credential is sent with `Cache-Control: no-store` (SSO-9.8, AUTH-7.6), and a
credential leaves only after the transaction committed.

| Purpose          | Package call                               | Then, in the same transaction                                          | Creates                      |
|------------------|--------------------------------------------|------------------------------------------------------------------------|------------------------------|
| `sign_in`        | `admit()` inside the adapter's transaction | `signInExternally()` (PR #127), once                                   | an active or pending session |
| `reauthenticate` | `admit()` inside the adapter's transaction | `reauthenticateExternally()` (PR #127), once, for the recorded renewal | an access token only         |
| `link`           | `redeem()` standalone, with the caller     | nothing                                                                | a link, no session           |

### Sign-in

<!-- snippet: tests/Integration/Examples/IntegratingWithLaravelIam/redemptions/sign-in.php#iam-sign-in -->
```php
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

$storage = DB::connection(StorageConnection::name());

$answer = $storage->transaction(static function () use ($application, $connectionId, $code, $verifier, $client): RedemptionResult|SignInResult {
    $redemption = app(HandoffRedemption::class)
        ->admit(Purpose::SIGN_IN, $application, $connectionId, $code, $verifier, $client);

    if (!$redemption->isRedeemed()) {
        return $redemption; // a refusal commits: the code is spent and one FlowFailed follows
    }

    if ($redemption->linkedIdentity === null) {
        throw new UnlinkedSignIn; // the adapter always requires a linked identity: roll back
    }

    app(AdmittedRedemptions::class)->record($redemption); // request scoped, for the link contract

    $signIn = Auth::sessions()->signInExternally(ExternalResults::from($redemption)); // PR #127

    if ($signIn->isFailed()) {
        throw new ExternalSignInRefused($signIn); // roll back: the code stays unspent
    }

    return $signIn; // signed in or pending
});

// Only now, after the commit, build the response from $answer, with
// Cache-Control: no-store.
```

`$client` is the `Http\ClientContext` of the request the call is made for, which your controller builds with
`ClientContext::fromRequest($request)`; work with no request (a console command, a queued job) passes
`new ClientContext(null, null)`. Every call that counts an attempt or reports an event takes one, never reading the
request itself, and each event it reports carries the client's IP address and user agent.

`AdmittedRedemptions`, `ExternalResults`, `UnlinkedSignIn` and `ExternalSignInRefused` are the adapter's own. `Auth`
is authentication's facade, `SineMacula\Laravel\Authentication\Facades\Auth` (PR #127), which declares `sessions()`:
Laravel's own facade reaches the same manager but does not declare it. `SignInResult` is authentication's too (PR #127).
The package runs this block in its examples against stand-ins for both, since it does not install
`laravel-authentication`: they ask the adapter's link contract and establish a session or refuse, as PR #127 does.

- **The order.** `admit()` first, then the sibling's entry point, in that one transaction. The sibling's session writes
  come after every lock the package took, so the session row is the last lock.
- **A refusal by the package commits.** It spends the code and reports one `FlowFailed` (`redemption`) after the
  commit; return it as the refusal.
- **A refusal by authentication rolls back.** `sso_required`, `method_not_allowed`, `identity_unknown`,
  `session_expired`, `external_result_unlinked`, `link_mismatch` or any other failed `SignInResult` is thrown out of
  the transaction, so the consumption, a reservation's activation and the connection's completed sign-in (SSO-4.3) are
  undone with it, and no `HandoffRedeemed` reports a sign-in that did not happen. The code stays unspent until it
  expires.
- **Pending is a success.** A pending session (AUTH-6.9) commits with the redemption, and its provenance is written
  with it, kept unchanged when it becomes active. The pending credential leaves only after the commit.
- **An unlinked handoff is refused.** Keep `unlinked_handoffs` off for every application the adapter serves; the
  adapter still treats an admitted result with no `linkedIdentity` as a refusal, and rolls back (SSO-8.6).
- **The result the sibling is given.** `ExternalResults::from()` builds authentication's `External\ExternalResult`
  (PR #127) from the admitted redemption alone: `connectionId`, `issuer` and `subject` from `$redemption->result`,
  `tenantId` from its `tenantId` (the connection's), `authenticatedAt` from
  `$redemption->result->authenticationContext->authenticatedAt`, `sessionNotAfter` from `$redemption->sessionNotAfter`
  (the effective deadline: `null` when `ProviderSessionDeadline` ignored it), `policyVersion` from
  `$redemption->enforcementVersion` (the version the redemption judged under its locks), `evidence` as an
  `External\ExternalEvidence` of `$redemption->evidence` only (its `methods()`, its `rawContext()` and its time), never
  the result's raw authentication context, `linkId` from `$redemption->linkId`, and `requestReference` (PR #128) from
  `$redemption->result->requestReference->value`, which authentication carries on the redemption's own events, and
  `providerContext` (PR #129) from `$redemption->provenance->toArray()`, the package's captured provenance in its stored
  form (see [Keeping the stored form](#keeping-the-stored-form)). Authentication asks its link contract for the
  connection, issuer and subject and refuses the result as `link_mismatch` unless the answer is exactly that link, so a
  link removed and made again since the redemption never stands in for it. Never from anything the client sent.

### Link

A `link` creates a link and no session, so it is the one purpose redeemed through the standalone `redeem()`, with no
transaction open. It needs the caller the application has authenticated, as an `Identities\Caller`: the identity and
the session it is on:

<!-- snippet: tests/Integration/Examples/IntegratingWithLaravelIam/RedeemingByPurposeExampleTest.php#iam-link -->
```php
$redemption = app(HandoffRedemption::class)
    ->redeem(Purpose::LINK, $application, $connectionId, $code, $verifier, $client, $caller);
```

The caller comes from authentication's current session, never from the request body: the authenticated identity and
that session's id. The package checks its identity against the one the code is bound to, then asks freshness
(`sso.link.create`) and, for an identity that holds or held a verified domain link, `LinkConfirmation` for that caller
as given, with eligibility and the link's continuity, then creates or confirms the link and commits before it answers.
`isAdmitted()` is false, and nothing written afterwards is protected by it. FEATURES' SSO-9.9 routes a `link` through
authentication's link redemption first; with the codes this package's, no sibling call is needed.

### Reauthenticate: one renewal

The package's admission already asks `ReauthenticationSessions`: `lockedStanding()` locks the session's row, then
`renewAuthentication()` is called once, with the identity, the session id, the provider's authentication time and the
evidence it accepted. `renewAuthentication()` is not given the result's issuer and subject, which authentication's
external entry point needs to find the link, so the renewal is written once, after `admit()` answers, and never twice:

1. `standing()` (at the start, no transaction): `externalStanding($sessionId, $identity, $connectionId)` (PR #127),
   with no link, which reads on the write connection, writes nothing and locks nothing. `null` is `signed_in`; any
   reason is `not_signed_in`.
2. `lockedStanding()` (inside the adapter's transaction, after the package's locks): `externalStanding($sessionId,
   $identity, $connectionId, $linkId)` (PR #127), which locks the session's row until the transaction ends. Answer
   `signed_in` only when it answers `null` and the session's application is the `$application` given.
3. `renewAuthentication()`: writes nothing. It records the renewal (identity, session id, provider time, accepted
   evidence) in a request-scoped recorder, and a second record in one redemption is a `LogicException`.
4. After `admit()` answers redeemed and admitted, in the same transaction and before anything else: record the
   admitted redemption for the link contract (`AdmittedRedemptions`, as for a sign-in), then call
   `reauthenticateExternally($sessionId, $result)` (PR #127) exactly once, for the session the recorder holds, which
   must be `$redemption->sessionId`, with a result built as for a sign-in (its `linkId` the admitted link), whose
   provider time and evidence are the recorded ones. Authentication accepts it only through the link that established
   the session (`link_mismatch` otherwise), locks and rechecks the session's row last, writes the session's issuance
   guard on that row before it reads the session's proofs (PR #129), and lets a serialisation failure (`40001`)
   propagate. It is the one write: `auth_time` becomes `max(current, provider_time)` under the session's lock, and its
   `AccessTokenResult` is the only token issued. It issues no refresh token, moves no deadline and records no provider
   context: give its result none, since the sign-in's is kept.
5. A failed `AccessTokenResult` (`link_mismatch`, `sso_required`, `additional_factor_required` or any other) is thrown
   out of the transaction: the consumption rolls back with it, and no `ReauthenticationCompleted` reports a renewal that
   did not happen. A recorder still holding a renewal when the transaction is about to commit is a `LogicException`.
6. The access token leaves only after the commit.

Never call `reauthenticateExternally()` from `renewAuthentication()`, never call it when `admit()` refused or recorded
nothing, and never write the session's time anywhere else. A renewal never sets MFA as present, adds an `amr` value,
moves the last step-up time or renews earlier MFA evidence, unless the evidence contract accepted this authentication's
own evidence (SSO-9.5, AUTH-3.11); the sign-in's provenance is never rewritten. What the renewal is enough for is
authentication's decision.

## The lock order

The order is the package's and never broken. Each lock is taken only when its condition holds; the session's row is
always last.

| # | Lock                                                   | Taken when                                                                                                                         | By                                 |
|---|--------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| 1 | The identity's guard (`Linking\IdentityLock`)          | The code holds a reservation (a sign-in by a verified domain), a `link`, or a principal change                                     | `admit()`, `redeem()`, `widened()` |
| 2 | The enforcing tenant's rule                            | The `enforcement` feature is on and `Enforcement\DatabaseEnforcement` is bound                                                     | `admit()`, `redeem()`              |
| 3 | The connection, with the rule's connections, ascending | Always (the connection alone when 2 is not taken); for a `link`, also the connections holding the identity's verified domain links | the package                        |
| 4 | The reservation's domain claim                         | The code holds a reservation                                                                                                       | `admit()`                          |
| 5 | The handoff code                                       | Every redemption                                                                                                                   | `admit()`, `redeem()`              |
| 6 | The links                                              | A link is resolved by a locking read, activated, created, confirmed or suspended                                                   | the package                        |
| 7 | The application's guards                               | A contract the admission asks takes one (principals, memberships, verified emails, session writers)                                | the adapter's contracts            |
| 8 | Authentication's connection guard rows                 | A sign-in through a link (its link's row), and a revocation of a link's (that row) or a connection's (every row) sessions          | authentication (PR #127)           |
| 9 | The session's row                                      | `lockedStanding()`, the sibling's session write, and a re-authentication's issuance guard                                          | authentication (PR #127, PR #129)  |

PR #129 leaves the order as it was: the package's locks, then authentication's guard rows, then the session's row. Its
issuance guard is no new lock but a write of the session's own row: `reauthenticateExternally()` increments it under its
lock of that row, before it reads the session's proofs. Under PostgreSQL's `REPEATABLE READ` or `SERIALIZABLE`, two
issuances racing for one session (two re-authentications, or one and a refresh, a switch or a step-up of the session)
end with the later failing to serialise (`40001`), which the retry of the whole transaction handles: its new snapshot
sees the other. At `READ COMMITTED`, and on MySQL, the later waits on the row and then reads what the earlier committed.
On MySQL at `REPEATABLE READ`, the issuance's locking read of the proofs also holds the gaps beside them, so a sign-in
of a new session can wait for the re-authentication's transaction to commit; the adapter takes no lock after
`reauthenticateExternally()`, so that wait ends at its commit.

A writer of the application's that takes one of these locks takes them in the same relative order, after the package's,
or it deadlocks against an admission. `Contracts\SessionRevocation` is called with the connection's lock held (and the
rule's, or the identity's guard, as the change requires), so revocation locks session rows after them. A logout that
locks only a session's row is safe; anything that locks a session's row and then calls into the package inverts the
order.

## Scope widening

A change that gives a person a principal calls `Linking\ScopeWidening::widened()` first, in its own transaction on the
storage connection, with the identity and the new principal's tenant (`null` for a platform principal); then it takes
the application's principal guard, writes the principal, and commits:

<!-- snippet: tests/Integration/Examples/IntegratingWithLaravelIam/principals/scope-widening.php#iam-scope-widening -->
```php
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;

DB::connection(StorageConnection::name())->transaction(static function () use ($identity, $tenantId, $client): void {
    app(ScopeWidening::class)->widened($identity, $tenantId, $client); // 1. the guard, suspensions, revocation

    $principals = app(Principals::class);

    $principals->guard($identity); // 2. the guard your PrincipalScope documents
    $principals->add($identity, $tenantId); // 3. the principal
});
```

`Principals` is the application's own store of principals, writing through the storage connection. Its `guard()` locks
the person's row of a guard table until the commit, inserting it when missing: locking the person's principals alone
would not hold back one being added.

`widened()` takes the identity's guard and holds it to the commit, suspends the identity's verified domain links in
every connection of another tenant, deletes its reservations there, and revokes the sessions established through each
such link with `RevocationScope::identityLink()` and the reason `scope_widened`. Calling it after the principal is
written, or outside a transaction (a `LogicException`), leaves a window in which a reservation or an activation sees the
old principals.

## Revocation

The adapter binds `Contracts\SessionRevocation` to authentication's revocation helpers (reported for phases 11 and 13,
with the PR #127 names on `Auth::sessions()`). It revokes inside the transaction the package calls it in, through the
same connection, throws on failure (which rolls the change back), and never reports a revocation it did not make. The
count each helper returns is not the package's concern.

| Scope (`RevocationScope::$kind`) | Reason                                      | Helper                                                                                           | Switch                                                                               |
|----------------------------------|---------------------------------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `tenant`                         | `enforcement_changed`                       | `tenantPolicyChanged($tenant)`, for the enforcing tenant and every tenant that inherits its rule | **Mandatory**: none                                                                  |
| `identity_link`                  | `scope_widened`                             | `linkScopeWidened($identity, $connectionId, $linkId)`                                            | **Mandatory**: none                                                                  |
| `connection`                     | `connection_disabled`, `connection_deleted` | `connectionDisabled($connectionId)`, `connectionDeleted($connectionId)`                          | `authentication.revocation.connection_disabled`, `connection_deleted`; on by default |
| `identity_connection`            | `link_removed`                              | `linkRemoved($identity, $connectionId, $linkId)`                                                 | `authentication.revocation.link_removed`; on by default                              |

- An enforcement change and a widened scope are never skipped: no setting of the adapter's or of authentication's turns
  them off, and `scope_widened` is never mapped to the switchable `linkRemoved()`. Authentication records the widened
  scope's revocation under its own reason, `link_scope_widened`.
- Turning a rule off calls nothing, so the adapter revokes nothing then: a rule that requires nothing leaves no session
  out of compliance, and a revocation handed a policy with no connections would end every session of the tenant
  ([Enforcement](enforcement.md#turning-a-rule-off-revokes-nothing)).
- The tenant scope names only the enforcing tenant (`$scope->tenantId`, with `$scope->policy` the rule now in force).
  The tenants that inherit its rule are the application's tree's, through `Contracts\EnforcementInheritance`; leaving
  one out leaves its sessions in place.
- A link-scope revocation is idempotent: the package calls it from the principal change and again from a resolution that
  finds the widening first.
- `identity_connection` names the identity, the connection and the removed link: `$scope->linkId` is the id of the link
  `Links\LinkService::remove()` deleted, or of the old link a connection's subject migration removed or relinked, so
  the adapter passes it straight to `linkRemoved($identity, $connectionId, $linkId)` and revokes exactly that link's
  sessions. Revoking every session of the identity through the connection instead is broader and never narrower;
  revoking fewer never is.

Bearer requests do not recheck the tenant policy's version (reported for phase 11), so a session's access tokens stay
valid until they expire unless a revocation ends the session: synchronous revocation is what makes a change take
effect.

## Enforcement in the tenant authentication policy

The adapter folds the package's enforcement into authentication's tenant authentication policy (AUTH-2.12), reported as
`Contracts\TenantAuthenticationPolicy::requirementFor(TenantPolicyContext): TenantRequirement`, asked at sign-in, at the
choice of principal, on every switch and on refresh:

1. Ask `Contracts\Enforcement::policy($activeTenantId, $application)`. It reads the stored rule on the write connection
   on every call; never cache it.
2. When `isRequired()`, the requirement names the policy's satisfying connections, checked against the session's
   recorded provenance connection, and carries `$policy->version` as its version.
3. A session the rule would refuse is passed to
   `Enforcement\ExemptionGate::admit($policy, $application, $identity, $client, $sessionId)`, with the client of the
   request being judged, which asks the exemption contract and reports `ExemptionUsed` for an exemption it grants. This
   gate is the only place the exemption is asked: the package's own completion and redemption refuse a sign-in through
   an unlisted connection as `enforcement_unsatisfied` without asking ([Enforcement](enforcement.md#exemptions)).
4. A non-compliant session is refused as `sso_required` (reported), with no pending continuation.

The redemption rechecks enforcement under its locks (SSO-4.6), and the version it judged there, never the one the
completion checked, is recorded on the session's provenance (`RedemptionResult::$enforcementVersion`, as the policy
version), so a rule changed between completion and redemption is the one the session names. A change reaches existing
sessions only through the mandatory revocation above, never through `EnforcementChanged` (SSO-9.3).

## Freshness

The adapter binds `Contracts\Freshness` to authentication's freshness check (AUTH-3.11), reported as
`Contracts\FreshnessPolicy`, judged by operation name with the caller's `FreshnessRequirement`:

- the operation name is `FreshnessOperation::$value` as given: `sso.connection.trust`, `sso.connection.enable`,
  `sso.connection.disable`, `sso.connection.delete`, `sso.connection.idp_initiated`, `sso.keys.rotate`,
  `sso.domain.claim`, `sso.domain.verify`, `sso.domain.remove`, `sso.enforcement.update`, `sso.link.create`,
  `sso.link.remove`. These names are stable and never reused;
- the package's `$maxAgeSeconds` is passed on as the caller's requirement's maximum age, and the stricter of it and any
  freshness the application configures for the name applies, so the package's requirement holds where the application
  configures none;
- the caller is the one the package gives, an `Identities\Caller`: the identity and, when the application supplied one,
  its session. The adapter judges that caller and session, never the request or job being served: `fresh` only when
  authentication answers fresh for that session of that identity; with no caller (a scheduled job, a console command),
  no session, a session that is not the caller's, or any doubt, `stale`;
- every helper that asks takes that caller after the client, and the administration events name its identity as the
  acting identity, never its session.

Freshness renewed through a verified domain link, or through its connection, is not the person's independent
confirmation of that link ([Linking](#linking-by-a-verified-domain-and-confirmation)).

## Links

Links are this package's: `laravel-authentication` stores none (AUTH-3.9). The adapter binds `Contracts\Linker` to
`Links\LinkStore` (which implements `Contracts\LinkStorage`), and answers authentication's link contract,
`Contracts\ExternalIdentityLinks::find($connectionId, $issuer, $subject): ?ExternalLink` (PR #127, default
`NoExternalLinks`, which links nothing), from the same store's admission:

- it answers only from the redemption admitted in the current request (`AdmittedRedemptions` above), for a sign-in or
  a re-authentication: an `ExternalLink` of the identity `$redemption->linkedIdentity` names and `$redemption->linkId`
  when the connection, issuer and subject are exactly the admitted result's, and `null` otherwise;
- it never looks a link up again, by email, by any attribute, or by issuer and subject alone: a SAML link is keyed by
  the `NameID` format as well (SSO-6.9), which `find()` cannot carry, and a second lookup after the locks
  could see another link;
- the session records `$redemption->linkId`, so a re-authentication accepts only the exact link that established the
  session, and a link removed and made again for the same identity is another link.

`Links\LinkService` lists an identity's links (accepting `me`) and removes one, asking freshness (`sso.link.remove`) and
revoking through the contract in the same transaction.

## Linking by a verified domain and confirmation

Each contract the admission asks is asked under the package's locks; the adapter's guards come after them.

- **`LinkEmailMatcher`.** Pass the linking email through authentication's bindable identifier normaliser (AUTH-3.1;
  PR #127 `Contracts\IdentifierNormalizer`) and match only verified identifiers, with exactly one match or none. Add no
  subaddress or dot removal, Unicode folding or confusable matching. Rely on a uniqueness guarantee on the verified
  email, or a guard every writer of a verified email takes.
- **`PrincipalScope`.** Judge the identity's complete set of principals against the tenant: a platform principal or
  another tenant's membership is `outside_tenant`, and a set it cannot read completely is `unknown`. Under `laravel-iam`
  it is composed (IAM-6.8) from the application's membership contract (IAM-7.4) and `laravel-authorization`'s grant
  scope query (AUTHZ-14.2): `within_tenant` only when both are, `outside_tenant` when either is, `unknown` otherwise.
- **`TenantMembership`.** Answer the membership and the time the person, not an administrator, accepted it. Memberships
  and their acceptance times are the application's: under `laravel-iam` this is answered by the one membership contract
  the application implements (IAM-7.4), never by `laravel-authorization`.
- **`LinkEligibility`.** For the `link` purpose: whether the identity may link through the connection, for example only
  as a member of its tenant. Under `laravel-iam` the same membership contract answers it (IAM-7.4).
- **`LinkConfirmation`.** `judge()` is given the caller the redemption is made for, an `Identities\Caller`, and judges
  that caller's session, never the request being served. `independent` only when that session was not established
  through a link that had verified domain provenance when it was established, and its freshness was not renewed through
  one or through that link's connection. A password or a passkey the person holds is independent. The session's
  recorded link provenance (`sso.link_provenance` below) is what tells; `dependent` whenever it cannot tell, including
  for a caller with no session and a session it cannot tie to the caller's identity or guard until the redeemer
  commits.

## Provisioning

Provisioning happens on this package's `ResultUnlinked`, never on authentication's `ExternalResultUnlinked` (PR #127),
which is informational: provisioning on both would provision twice (AUTH-3.9).

- **One synchronous listener** creates a new identity, its membership and the link, with
  `Provisioning\ProvisioningHelper::link($event->grant, $event->result, $identity)`. A queued listener is too late: the
  event refuses to be serialised and the grant is void once the dispatch returns.
- **Never an existing identity.** Resolving one from the email or any mapped attribute is forbidden; attaching to an
  existing identity goes through the `link` purpose or linking by a verified domain. The grant proves authority for the
  result, not that the identity is new: that is the adapter's obligation.
- **One transaction.** The identity, the membership and the link are written in one transaction on the storage
  connection; a refusal from the helper (or an exception) rolls all three back together.
- **A later failure does not undo it.** The listener's transaction commits before the completion's final step, which can
  still refuse (a connection disabled in between, a deadline passed). The identity, its membership and the link then
  stay made, an ordinary link the next sign-in resolves through. Treat the identity as made once the listener commits.

## Evidence and `laravel-mfa`

There are two gates, and neither is the other:

1. **The package accepts provider evidence.** `Contracts\EvidencePolicy`, asked at redemption against current policy
   and the provider's authentication time, accepts the result's own `amr`, `acr` or `AuthnContextClassRef` per
   connection, within a maximum age. The default, `Evidence\InsufficientEvidence`, accepts nothing.
2. **`laravel-mfa` decides what accepted evidence satisfies.** Its `CombinationPolicy` (reported) decides; its default
   treats an external provider's first factor as a channel only and never counts the provider's `amr` as MFA. Accepted
   `amr` counts as MFA only when the application rebinds the `CombinationPolicy` to trust that provider.

So by default, even with an `EvidencePolicy` bound, a provider's `mfa` never becomes MFA. The adapter passes on only
`RedemptionResult::$evidence` (`AcceptedEvidence`: the connection id as the credential reference, the provider's time,
the accepted `methods()` and the `rawContext()` as data), never the result's `authenticationContext`. It offers it to
the identity-level requirement (AUTH-3.6) and the tenant's (AUTH-2.12), through authentication's evidence policy
(PR #127 `Contracts\ExternalEvidencePolicy`: `accepts()` decides whether the evidence counts at all, and
`meets(ExternalEvidence, Requirement, EvidenceSubject)` whether accepted evidence meets a requirement; its default,
`InsufficientEvidence`, accepts and meets nothing).

| Purpose          | `laravel-mfa` proof (reported)                                        | Channel                                             |
|------------------|-----------------------------------------------------------------------|-----------------------------------------------------|
| `sign_in`        | `ProofKind::first_factor`                                             | `ChannelKind::external_provider`, the connection id |
| `reauthenticate` | `ProofKind::first_factor_reauthentication`, `Purpose::reauthenticate` | `ChannelKind::external_provider`, the connection id |
| `link`           | none                                                                  | none                                                |

## Session provenance and the authentication context

`Sessions\AuthenticationContext` owns AUTH-11.8's `sso` namespace and fills it by reading the session's
external-provider provenance (SSO-9.7): `AuthenticationContext::fromStored()` projects the stored array, and
`AuthenticationContext::of()` a `Sessions\Provenance`. Both are pure. Authentication exposes that provenance for
reading and never writes into the `sso` namespace itself: the adapter fills it through authentication's contributor
seam (PR #128), with a contributor of its own that projects the stored form the adapter kept with the session (see
[The `sso` contributor](#the-sso-contributor)). The keys, their types and the stored form are in
[Session Provenance](session-provenance.md#with-laravel-iam).

The provenance is captured once, inside the admitted redemption's transaction, by the package itself:
`RedemptionResult::$provenance` is a `Sessions\Provenance` for an admitted `sign_in`, and `null` for anything else. The
adapter writes it with the session, pending or active; nothing rewrites it, on activation, refresh, a switch or a
re-authentication (SSO-9.10). These keys are history: they never stand in for current revocation, enforcement or
freshness checks.

| Key                                    | From `$redemption->provenance`     | Also in authentication's own fields (PR #127 `authentication_provenance`)                     |
|----------------------------------------|------------------------------------|-----------------------------------------------------------------------------------------------|
| `sso.connection`                       | `->connectionId`                   | `connection_id`                                                                               |
| `sso.tenant`                           | `->tenantId`, the connection's     | `tenant_id`                                                                                   |
| `sso.protocol`                         | `->protocol`                       | none                                                                                          |
| `sso.provider_auth_time`               | `->providerAuthenticatedAt`        | `provider_authenticated_at`, to the whole second                                              |
| `sso.provider_amr`                     | `->providerMethods()`, accepted    | `accepted_evidence` (`methods`)                                                               |
| `sso.provider_acr`                     | `->providerAcr()`, not `saml2`     | `accepted_evidence` (`context`), told apart by the protocol                                   |
| `sso.provider_authn_context_class_ref` | `->providerAuthnContextClassRef()` | `accepted_evidence` (`context`), told apart by the protocol                                   |
| `sso.link`                             | `->linkId`                         | `link_id`                                                                                     |
| `sso.link_provenance`                  | `->linkProvenance`, as admitted    | none                                                                                          |
| `sso.provider_session_deadline`        | `->providerSessionDeadline`, raw   | none (`provider_session_expires_at` holds the effective cap)                                  |
| `sso.session_not_after`                | `->sessionNotAfter`, the cap       | `provider_session_expires_at`                                                                 |
| `sso.enforcement_version`              | `->enforcementVersion`             | `policy_version`                                                                              |

Each value is what the redemption admitted under its locks: the methods and raw context class are the evidence the
evidence contract accepted (none accepted: `[]` and `null`), the link and its provenance are those the locked admission
carried out, the raw deadline is kept even when `ProviderSessionDeadline` ignored it, and the enforcement version is
the one the redemption judged under its locks.

Every key's durable home is the package's stored form, kept whole with the session; the third column is only where
authentication's own record holds the same fact. That record has no protocol, no link provenance and only one deadline,
and keeps whole seconds, so the projection never rebuilds the package's provenance from it. The subject, the issuer,
the provider session id, the email, groups, attributes and tokens are never captured.

### Keeping the stored form

The adapter keeps the package's captured provenance in its versioned stored form (`Provenance::toArray()`, read back by
`Provenance::restore()`), written once in the sign-in's transaction from the same capture and never rewritten.

**As authentication's provider context (PR #129).** PR #129, merged as `86ec3ba6` but in no tagged release yet, adds
`SineMacula\Laravel\Authentication\External\ProviderContext` and a last optional argument to `ExternalResult`,
`providerContext: ?ProviderContext`. `ExternalResults::from()` passes the stored form as it,
`new ProviderContext($redemption->provenance->toArray())`, and `signInExternally()` does the rest. There is one path:
the stored form always fits.

- **What it takes.** `new ProviderContext(array $values)` takes a non-empty map with string keys whose values are
  `null`, booleans, integers, finite floats, strings or arrays of them, nesting at most four arrays deep (the map the
  first). Its JSON-encoded form, every character outside ASCII escaped (with `JSON_THROW_ON_ERROR` and
  `JSON_PRESERVE_ZERO_FRACTION`), is capped at 4,096 bytes; over the cap, invalid UTF-8, `NAN` or `INF` is an
  `InvalidArgumentException`, never truncated.
- **Why the stored form always fits.** Its shape is thirteen string keys, the version an integer and every other value a
  string, `null` or a list of strings, two arrays deep. Its size is bounded by the package: a `Provenance` holds only
  what a capture can produce (a connection id of at most 64 bytes, a link id of 255 and an enforcement version of 64,
  all printable ASCII; a tenant id of at most 255 bytes of UTF-8; a driver's name; RFC 8176's registered methods, each
  once; a raw context class of at most 255 bytes of printable ASCII) and refuses anything else, and a capture keeps an
  unregistered method out and a raw class outside its domain as `null` rather than fail. With every part at its limit
  and every character one JSON escapes the most, it takes 3,364 bytes encoded with those flags, 732 under the cap
  (`Provenance::MAX_STORED_JSON_BYTES`; the arithmetic is in
  [the design note](../design/session-provenance.md#the-stored-form)). An ordinary one takes about 500.
- **Its lifetime.** Authentication writes it once at the external sign-in, in its provenance's `provider_context`
  column, with the session, pending or active, and never rewrites it: activation, refresh and switch keep it, and a
  re-authentication keeps the sign-in's and records none of its own. It never appears in an event, the event context or
  an exception message, and is hidden from the provenance model's serialisation. It is provider metadata, not a
  secret, and is not protected as a credential is, which suits the stored form: it holds no subject, issuer, email or
  token, though it holds the accepted methods and raw class, so the adapter never logs it either.
- **Reading it.** The contributor reads it from the contribution subject's provenance,
  `$subject->provenance()?->providerContext`, and projects its values through `AuthenticationContext::fromStored()`.
  So the adapter needs no table of its own for the package's provenance: authentication keeps it with the session's.

**Without PR #129.** Against a `laravel-authentication` that has no provider context, the adapter stores `toArray()`
itself: one row per session in a table of its own on the storage connection, keyed by the session's id, written in the
sign-in's transaction from the same capture, never updated, and removed with the session. Its contributor reads that
row in place of the provider context. Either way, a session with no stored form, one not established through this
package, contributes no `sso.*` key.

### The `sso` contributor

Authentication builds its context (`Auth::context()`, PR #128) once per unchanged authentication state, and asks every
registered contributor once per build. A contributor implements
`SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor`, whose one method is
`contribute(ContributionSubject $subject): array`. The subject carries `context` (authentication's own keys, with
nothing contributed yet), the live `identity`, `principal`, `?tenant` and `?session` the guard bound, and
`provenance(): ?Proofs\Provenance`, authentication's own record of the session's external provenance, with the
provider context the adapter gave at sign-in as its `providerContext` (PR #129), read on the write connection the first
time a contributor asks, and `null` for a session no external provider established or one that is not an Eloquent
session.

The adapter's contributor reads the stored form the adapter handed authentication as the provider context, never
authentication's own fields: they are the narrower record (no protocol, no link provenance, one deadline, whole
seconds), and the projection never rebuilds the package's provenance from them. It projects the stored form through
`AuthenticationContext::fromStored()` and answers the keys without their `sso.` prefix, each value as the projection
answers it. The adapter's `final readonly class SsoContextContributor implements AuthenticationContextContributor`
imports `Context\ContributionSubject` and `Contracts\AuthenticationContextContributor` from
`SineMacula\Laravel\Authentication`, and `Sessions\AuthenticationContext` from `SineMacula\Laravel\Sso`:

<!-- snippet: tests/Integration/Examples/IntegratingWithLaravelIam/SsoContextContributor.php#iam-context-contributor -->
```php
/**
 * The session's `sso` keys, without their prefix.
 *
 * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
 * @return array<string, mixed>
 */
#[\Override]
public function contribute(ContributionSubject $subject): array
{
    // Provenance::toArray(), passed as the provider context at sign-in
    // (PR #129); null for a session this package did not establish.
    $stored = $subject->provenance()?->providerContext?->toArray();

    $keys = [];

    foreach (AuthenticationContext::fromStored($stored) as $key => $value) {
        $keys[substr($key, strlen(AuthenticationContext::NAMESPACE) + 1)] = $value; // sso.connection -> connection
    }

    return $keys;
}
```

Without PR #129, `$stored` is the adapter's own row for `$subject->session?->getSessionIdentifier()` instead, read on
the write connection. The contributor is registered in the adapter's service provider's `boot()`, never in
configuration, with `SineMacula\Laravel\Authentication\Context\ContextContributors` imported:

<!-- snippet: tests/Integration/Examples/IntegratingWithLaravelIam/AdapterServiceProvider.php#iam-contributors -->
```php
$this->app->make(ContextContributors::class)->register('sso', SsoContextContributor::class);
```

- **The namespace.** A namespace is a lower-case letter and then up to 31 lower-case letters, digits or underscores
  (`/^[a-z][a-z0-9_]{0,31}$/`), never authentication's own `authentication`, and taken once: a malformed, reserved or
  repeated registration is a `LogicException`. `sso` is kept for this package's adapter (and `mfa` for
  `laravel-mfa`'s); authentication registers neither, so the adapter registers `sso` exactly once, under
  `AuthenticationContext::NAMESPACE`.
- **The keys.** Each is answered without the namespace and is a lower-case letter and then up to 63 lower-case letters,
  digits or underscores (`/^[a-z][a-z0-9_]{0,63}$/`), so no key holds the dot that joins it to its namespace. Every key
  of `AuthenticationContext::KEYS`, with `sso.` removed, fits: `connection`, `tenant`, `protocol`,
  `provider_auth_time`, `provider_amr`, `provider_acr`, `provider_authn_context_class_ref` (32 characters, the longest),
  `link`, `link_provenance`, `provider_session_deadline`, `session_not_after` and `enforcement_version`. A policy reads
  them back by their full names, `Auth::context()?->get('sso.connection')`; authentication's own examples write
  `sso.connection_id`, which this package never contributes.
- **The values.** Authentication holds only `null`, a scalar or an array of them, never an object, and fails loudly
  with a `LogicException` naming the namespace and key on anything else. Every value of the projection is already
  plain: a string, a list of strings or `null`. Its three instants (`provider_auth_time`, `provider_session_deadline`
  and `session_not_after`) are strings in `Provenance::INSTANT_FORMAT` (`Y-m-d\TH:i:s.u\Z`), the form the stored
  provenance keeps them in, so the contributor formats nothing.
- **Absent and null.** A session with no stored form (one this package did not establish, an API key, a client
  credentials token, or a binding with no session) makes `fromStored(null)` answer `[]`, so the contributor answers
  `[]`: the `sso` namespace holds no key, `has('sso.connection')` is false, and `get('sso.connection', $default)` gives
  the default. A session with a stored form contributes all twelve keys, `null` where the sign-in did not state the
  fact, so `has()` is true for each and `get()` gives `null` for an unstated one: absent means "not established through
  this package", and `null` means "established through it, without that fact".
- **Failures propagate.** A stored form this version did not write is an `UnexpectedValueException` from `fromStored()`,
  never an empty contribution, and a database error is never read as no stored form. Authentication reads a
  `provider_context` value it cannot read back as a provider context (one edited by hand, say) as none, so such a
  session contributes no key. An application with another adapter that passes a provider context of its own tells the
  two apart before projecting (by the provenance's connection, say), since `fromStored()` refuses any other form.
  Authentication lets a contributor's exception reach the caller, since a policy is never judged on part of a context.
  The contributor never calls `Auth::context()`, which is a `LogicException` while the context is being built.
- **Resolved per build.** Authentication resolves the contributor from the container serving each build (the request's
  own under Octane), so it may depend on request-scoped services and keeps nothing between builds. A re-authentication
  or a confirming `link` never changes the stored form, so it never changes the keys either.

## Event context and correlation

The context names (SSO-9.6) and authentication's, as PR #127 has them with the two keys PR #128 added:

| This package            | Meaning                                      | Authentication (PR #127, PR #128)                           |
|-------------------------|----------------------------------------------|-------------------------------------------------------------|
| `identity_morph_class`  | The identity's type                          | `identity_type`                                             |
| `identity_id`           | The identity's id                            | `identity_id`                                               |
| `principal_morph_class` | The principal's type                         | `principal_type`                                            |
| `principal_id`          | The principal's id                           | `principal_id`                                              |
| `tenant_id`             | The active tenant, the one acted in          | `tenant_id` (with `tenant_type`)                            |
| `connection_tenant_id`  | The tenant that owns the connection          | none                                                        |
| `session_id`            | The session                                  | `session_id`                                                |
| `method`                | The sign-in method                           | `method`                                                    |
| `ip`, `user_agent`      | The client                                   | `ip`, `user_agent`                                          |
| `connection_id`         | The connection                               | `connection_id` (PR #128), on a redemption's own events     |
| `request_reference`     | The authorisation request's public reference | `request_reference` (PR #128), on a redemption's own events |

The concepts are the same, and `tenant_id` means the active tenant in both, so one audit mapping reads it from either
package; only the identity's and principal's types are spelled differently, and the connection's tenant is
`connection_tenant_id`, which authentication has no key for. Correlate one sign-in by
`connection_id` and `request_reference`: `ResultVerified` at completion and `HandoffRedeemed` at redemption both carry
them, so a sign-in is counted once. AUTH-9.4 asks authentication's redemption events to carry the connection and the
reference too, and PR #128 does: the adapter passes the reference as `ExternalResult::$requestReference` beside the
connection id, and authentication's `ExternalResultRedeemed`, and a refused redemption's `AuthenticationFailed` and
`ExternalResultUnlinked`, carry `connection_id` and `request_reference`. Authentication's session events
(`SessionCreated`, `SignedIn`, `SessionPending`, `Reauthenticated`) carry neither, and correlate with
`ExternalResultRedeemed` by `session_id`. So `ResultVerified`, `HandoffRedeemed` and `ExternalResultRedeemed` of one
sign-in share `connection_id` and `request_reference`, and an audit mapping counts the sign-in once across both
packages.

## What `laravel-authentication` does not carry

PR #127 leaves three facts out of authentication's own records and contracts, and PR #128 adds none of them; PR #129
gives the first two a place, inside the opaque provider context. The adapter covers each from what this package already
answers, the session provenance and the redemption result, never by asking a provider, a link or a policy again:

- **No protocol and no link provenance.** `authentication_provenance` has neither as a field. The adapter keeps
  `$redemption->provenance` (a `Sessions\Provenance`, captured under the redemption's locks with the connection's
  protocol and the link's provenance as admitted) in its stored form with the session, as the provider context (or,
  without PR #129, in its own row; see [Keeping the stored form](#keeping-the-stored-form)), and reads them there:
  `sso.protocol` and `sso.link_provenance` come from it, and so does `LinkConfirmation`'s answer on whether the current
  session came through a verified domain link.
- **One deadline.** `provider_session_expires_at` holds one instant. The adapter passes the effective cap,
  `$redemption->sessionNotAfter`, as `ExternalResult::$sessionNotAfter`, so authentication caps the session by it; the
  provider's raw deadline, kept even when `ProviderSessionDeadline` ignored it, is
  `Provenance::$providerSessionDeadline` in the stored form (`sso.provider_session_deadline`).
- **No `NameID` format in `find()`.** `ExternalIdentityLinks::find()` takes the connection, issuer and subject only, so
  it cannot tell two SAML links apart by format (SSO-6.9). The adapter never looks a link up there: it answers from the
  redemption admitted in this request, whose `linkedIdentity` and `linkId` the package resolved under its locks with
  the format, and passes `$redemption->linkId` on the `ExternalResult`, so authentication refuses any other answer as
  `link_mismatch`.

## Acceptance scenarios

An adapter ships only when each holds, on SQLite, MySQL and PostgreSQL, with the races on the two real engines.

### Transaction checks

- [ ] `sso.storage.connection` and `authentication.storage.connection` name one Laravel connection; a boot check of the
  adapter's refuses a mismatch.
- [ ] Every `admit()` runs inside the adapter's transaction on that connection; calling it outside one is a
  `LogicException` before the code is touched.
- [ ] A sign-in whose session write throws leaves the code unspent, no reservation activated, no completed sign-in
  acknowledged and no event reported.
- [ ] A database error or serialisation failure is retried only as the whole transaction.

### Sign-in checks

- [ ] A linked `sign_in` writes one session with the provenance of the table above, in the redemption's transaction,
  and its provider context is exactly the capture's `toArray()`; one whose raw context class is outside the stored
  domain still signs in, with that class `null`.
- [ ] A pending sign-in commits with the redemption; its provenance is unchanged when it becomes active, and on refresh
  and switch.
- [ ] No credential leaves before the commit; every response carries `Cache-Control: no-store`.
- [ ] A package refusal spends the code and reports one `FlowFailed`; an authentication refusal rolls back, spends
  nothing and reports no `HandoffRedeemed`.
- [ ] An unlinked handoff is refused and rolled back.
- [ ] Authentication's link contract answers exactly the admitted link, and `null` for any other connection, issuer or
  subject; a result whose `linkId` is not the link it answers is `link_mismatch` and rolls back.
- [ ] The session's provenance names the enforcement version the redemption judged under its locks, also when the rule
  changed between completion and redemption.

### Re-authentication checks

- [ ] `renewAuthentication()` writes nothing and is recorded once; `reauthenticateExternally()` is called once, after
  `admit()`, for the recorded session.
- [ ] The session's `auth_time` is `max(current, provider_time)`; a provider time older than the session's leaves it.
- [ ] Refresh tokens, deadlines, sign-in provenance, MFA presence, `amr`, the last step-up time and earlier evidence are
  unchanged unless this authentication's own evidence was accepted.
- [ ] A session established through another link, or through none, is `session_ineligible` and renews nothing; a
  result naming another link than the session's is `link_mismatch` at authentication and rolls back.
- [ ] A failed access-token result rolls back the redemption and reports no `ReauthenticationCompleted`.

### Link checks

- [ ] A `link` is redeemed through standalone `redeem()` with the authenticated caller, and writes no session.
- [ ] Removing a link revokes its sessions in the removal's transaction; with `authentication.revocation.link_removed`
  off, the link is still removed.
- [ ] A link removed and made again does not renew or admit a session bound to the old one.
- [ ] A person whose only session came through a verified domain link is `independent_authentication_required` when
  confirming it; a password or passkey session confirms.

### Revocation checks

- [ ] An enforcement change revokes non-compliant sessions in its transaction, in the enforcing tenant and every
  inheriting tenant, whatever any setting says; an exempt identity's session stays.
- [ ] A principal change calls `widened()` first; the sessions through each suspended verified domain link are revoked
  in that transaction, whatever any setting says, and a second call revokes nothing more.
- [ ] Disabling or deleting a connection revokes its sessions unless its switch is off.
- [ ] A revocation that throws rolls the change back: no new version, no event.
- [ ] An enforcement change racing a redemption either sees the new rule or revokes the session the redemption wrote.
- [ ] Turning a rule off revokes nothing.
- [ ] On PostgreSQL at `REPEATABLE READ`, a sign-in racing a revocation of its link or connection fails to serialise
  for the later of the two, and the whole transaction retried sees the other.

### Provisioning checks

- [ ] One synchronous listener provisions; a queued one fails loudly and provisions nothing.
- [ ] A refused helper rolls back the identity, its membership and the link together.
- [ ] A completion that fails after the listener committed leaves the identity, membership and link, and the next
  sign-in resolves through the link.
- [ ] Authentication's `ExternalResultUnlinked` provisions nothing.

### Evidence checks

- [ ] With the default `EvidencePolicy`, no evidence reaches authentication or `laravel-mfa`.
- [ ] With an `EvidencePolicy` accepting `mfa` and MFA's default `CombinationPolicy`, a sign-in records `first_factor`
  through `external_provider` and MFA is not present.
- [ ] Only with the `CombinationPolicy` rebound to trust the provider does accepted `mfa` count as MFA.
- [ ] A `reauthenticate` records `first_factor_reauthentication` with MFA's `reauthenticate` purpose; a `link` records
  no proof.

### Context checks

- [ ] The contributor is registered once, under `sso`, in a service provider's `boot()`; `Auth::context()` builds
  without a `LogicException` for a session established through the package, so every key and value is one
  authentication holds.
- [ ] A session established through the package contributes exactly the documented `sso.*` keys, each value as
  `fromStored()` answers it, its instants `Provenance::INSTANT_FORMAT` strings; any other session contributes none, and
  no key carries a subject, issuer, email, attribute or token.
- [ ] A re-authentication passes no provider context and leaves every `sso.*` key as it was.
- [ ] On PostgreSQL at `REPEATABLE READ`, two re-authentications racing for one session fail the later to serialise at
  its issuance guard, and the whole transaction retried renews from what the other committed.
- [ ] A stored provenance the package cannot restore fails the context's build, never contributes `[]`.
- [ ] An audit record of one sign-in correlates `ResultVerified`, `HandoffRedeemed` and authentication's
  `ExternalResultRedeemed` by `connection_id` and `request_reference`, and counts one sign-in.
- [ ] An audit mapping reads the active tenant from `tenant_id` in both packages' contexts, and the connection's tenant
  from this package's `connection_tenant_id`.
- [ ] Every event of a call the adapter makes for a request carries that request's IP address and user agent, from the
  `Http\ClientContext` the adapter passed; an event of a job or a command carries neither.

## Requirements this guide maps

| AUTH                | Requirement                              | This package                                                                                          | Section                                                                                    |
|---------------------|------------------------------------------|-------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| AUTH-2.12           | Tenant authentication policy, revocation | `Enforcement`, `EnforcementExemption`, `EnforcementInheritance`, `SessionRevocation` (SSO-4, SSO-9.3) | [Enforcement](#enforcement-in-the-tenant-authentication-policy), [Revocation](#revocation) |
| AUTH-3.1            | Email normalisation                      | `LinkEmailMatcher` (SSO-8.8)                                                                          | [Linking](#linking-by-a-verified-domain-and-confirmation)                                  |
| AUTH-3.6, AUTH-3.12 | Further factors, `laravel-mfa`'s seams   | `EvidencePolicy` (SSO-8.7)                                                                            | [Evidence](#evidence-and-laravel-mfa)                                                      |
| AUTH-3.7            | Methods by application                   | `ApplicationPolicy` (SSO-5.1, SSO-9.2)                                                                | [Contracts](#contracts)                                                                    |
| AUTH-3.9            | External-provider seam, links            | `VerifiedResult`, `Linker`, `LinkStorage`, provisioning (SSO-8.1 to SSO-8.6, SSO-9.1)                 | [Links](#links), [Provisioning](#provisioning)                                             |
| AUTH-3.10           | Handoff codes                            | the package's own codes (SSO-9.2, reconciled)                                                         | [Handoff codes](#handoff-codes-are-this-packages)                                          |
| AUTH-3.11, AUTH-8.2 | Freshness, re-authentication             | `Freshness`, `ReauthenticationSessions` (SSO-2.12, SSO-9.4, SSO-9.5)                                  | [Freshness](#freshness), [Re-authentication](#reauthenticate-one-renewal)                  |
| AUTH-5.7            | One kind, one validation                 | codes, references and verifiers never interchangeable (SSO-9.2)                                       | [Handoff codes](#handoff-codes-are-this-packages)                                          |
| AUTH-6.1            | Session records                          | the provenance a session keeps (SSO-9.10)                                                             | [Provenance](#session-provenance-and-the-authentication-context)                           |
| AUTH-6.9            | Pending sessions                         | nothing: a redemption may lead to one                                                                 | [Sign-in](#sign-in)                                                                        |
| AUTH-7.6            | Secrets in responses                     | `no-store` and redaction (SSO-9.8)                                                                    | [Redeeming by purpose](#redeeming-by-purpose)                                              |
| AUTH-8.1            | Sign-in helper                           | `admit()` then the external sign-in (SSO-9.1, SSO-9.9)                                                | [Sign-in](#sign-in)                                                                        |
| AUTH-9.x            | Events and their context                 | the package's events (SSO-9.6, SSO-10)                                                                | [Event context](#event-context-and-correlation)                                            |
| AUTH-10.x           | Operational rules                        | the same rules here (SSO-11)                                                                          | [The transaction rule](#the-transaction-rule)                                              |
| AUTH-11.8           | Authentication context                   | the `sso` namespace (SSO-9.7)                                                                         | [Provenance](#session-provenance-and-the-authentication-context)                           |
