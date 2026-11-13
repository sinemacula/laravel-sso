# Enforcement

A tenant can require that every session active in it is established through one of its own enabled connections: an
SSO-only tenant. The package stores that rule per tenant, answers it through a contract your sign-in code (or
`laravel-iam`) asks on every sign-in, switch and refresh, and, when the rule changes, asks your application to revoke
the sessions that no longer comply, inside the same transaction. Your administration screens change the rule through
`SineMacula\Laravel\Sso\Enforcement\EnforcementService`; who may do so is your application's authorisation, so check it
before you call the service.

<!-- snippet: tests/Integration/Examples/Enforcement/EnforcementExampleTest.php#enforcement-service -->
```php
$enforcement = app(EnforcementService::class);
```

> [!IMPORTANT]
> Enforcement is off until you switch the feature on: set `SSO_ENFORCEMENT=true` (`sso.features.enforcement`). While
> it is off, every tenant's rule answers that nothing is required, and every change is refused with
> `feature_disabled`.

Before you turn a tenant's rule on, decide what should happen to the sessions it already has.

> [!WARNING]
> **The default session revocation does nothing.** The package keeps no sessions, so on its own it cannot revoke one:
> its default, `Revocation\NoSessionRevocation`, succeeds without revoking anything. If your application does not use
> `laravel-authentication`, bind your own `Contracts\SessionRevocation` (see [Revoking sessions](#revoking-sessions)),
> or accept that turning enforcement on leaves every existing session as it was: only sessions established afterwards
> are judged by the new rule. Under `laravel-iam` there is nothing to bind: it binds the contract to
> `laravel-authentication`'s revocation, which an enforcement change then always runs.

## Turning it on

Give the tenant, the switch, the connections that satisfy the rule and, as an `Identities\Caller`, the administrator
making the change, on the session the [freshness contract](freshness.md#the-caller) judges. Here `$tenant` and `$user`
are your own models; the example asserts that the change was made, where your screen would answer each result in the
table below:

<!-- snippet: tests/Integration/Examples/Enforcement/EnforcementExampleTest.php#enforcement-update -->
```php
$result = $enforcement->update(
    $tenant->id,
    true,
    [$connectionId],
    $client,
    new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId()),
);

self::assertSame(EnforcementStatus::UPDATED, $result->status);

$version = $result->enforcement?->version; // a new lower-case ULID on every change
```

`$client` is the `Http\ClientContext` of the request the call is made for, which your controller builds with
`ClientContext::fromRequest($request)`; work with no request (a console command, a queued job) passes
`new ClientContext(null, null)`. Every call that counts an attempt or reports an event takes one, never reading the
request itself, and each event it reports carries the client's IP address and user agent.

The ids you give are the tenant's connections that satisfy the rule: a session established through any of them that
is still enabled complies. Turning the rule on asks the freshness contract with `sso.enforcement.update` (see
[Freshness](freshness.md)), and needs at least one of the connections given to be enabled and to have completed a
sign-in, so a connection that was never tried cannot lock the tenant out. Turning it off (`false`) needs no completed
sign-in and revokes nothing.

| Result                                                            | Why                                                                                               |
|-------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `updated`                                                         | The rule was stored with a new version; any revocation it needed ran in the same transaction      |
| `unchanged`                                                       | The rule already was this: the same switch and the same connections, in any order                 |
| `refused`, reason `feature_disabled`                              | `sso.features.enforcement` is off                                                                 |
| `refused`, reason `completed_sign_in_required`                    | None of the connections given is enabled with a completed sign-in                                 |
| `refused`, reason `freshness_required`                            | The caller did not authenticate recently enough                                                   |
| `invalid`, `connection_ids.<n>` `invalid_type` / `invalid_format` | The id at position `<n>` is not a string of 1 to 26 bytes                                         |
| `invalid`, `connection_ids` `required`                            | No connection was given while turning it on                                                       |
| `invalid`, `connection_ids` `too_many`                            | More than 50 distinct connections were given                                                      |
| `invalid`, `connection_ids.<n>` `unknown`                         | The tenant has no connection with the id at position `<n>`; another tenant's is answered the same |

A refused or invalid change writes nothing, revokes nothing and reports nothing; an `unchanged` one asks nothing
either. Duplicate ids are dropped silently. Each change is reported once it commits as `EnforcementChanged` (see
[Events](events.md)), carrying the new `version` and the `previousVersion` it replaced.

## Reading the rule

Read back after the change above, made at the example's frozen instant:

<!-- snippet: tests/Integration/Examples/Enforcement/EnforcementExampleTest.php#enforcement-get -->
```php
$summary = $enforcement->get($tenant->id);

self::assertTrue($summary->enabled);
self::assertSame([$connectionId], $summary->connectionIds); // the ids stored, in id order
self::assertSame($version, $summary->version); // null while the tenant never had a rule
self::assertSame('2026-11-01T09:30:00Z', $summary->changedAt?->toIso8601ZuluString()); // CarbonImmutable in UTC, or null
```

A tenant that never had a rule reads as off, with no connection, no version and no `changedAt`.

The ids are those stored: one whose connection was since disabled or deleted is still listed here, but no longer
satisfies the rule.

## Asking whether a session complies

Your sign-in code asks `Contracts\Enforcement` for the tenant a session is active in and the application. Here the
example application's tenant authentication policy judges a row of its own `sessions` table, an Eloquent `UserSession`
whose `tenant_id` is the tenant the session is active in and whose `sso_connection_id` is the connection it was
established through (`null` for a session established without SSO); it answers whether the session may stay:

<!-- snippet: tests/Integration/Examples/Enforcement/TenantAuthenticationPolicy.php#enforcement-policy -->
```php
$policy = app(Enforcement::class)->policy($session->tenant_id, 'web');

// Recheck the session once the version moves on
$session->update(['enforcement_version' => $policy->version]);

// A session established without SSO records no connection, which
// satisfies no rule
if ($policy->isRequired() && !$policy->isSatisfiedBy($session->sso_connection_id ?? '')) {
    return $this->isExempt($policy, $session, $client); // refused, unless the identity is exempt (below)
}

return true;
```

It reads the stored rule on the write connection on every call and caches nothing, so a change applies from the next
question. Record `version` against each session and recheck a session whose recorded version is no longer the
current one. It changes with the rule and whenever one of its satisfying connections is disabled, deleted or enabled
again, so it is not the rule's own version that `get()` and `EnforcementChanged` report. A database error is thrown,
never answered as "not required". If every satisfying connection has since been disabled, the rule is still required
and nobody complies until an administrator names an enabled connection or turns it off.

Under `laravel-iam` you do not call it yourself: it is folded into `laravel-authentication`'s tenant authentication
policy, asked at sign-in, at the choice of principal, on every switch and on refresh. Bearer requests do not recheck
that policy's version, so a change reaches existing sessions only through the synchronous revocation below. See
[Integrating with `laravel-iam`](integrating-with-laravel-iam.md#enforcement-in-the-tenant-authentication-policy).

### Admitting a session while the rule changes

`policy()` takes no lock: it answers the rule as it is, but the rule can change before the session it admitted is
written, and that session would then escape the change's revocation. The package's own admissions close that gap. A
handoff redemption and a completion lock the tenant's rule first (the enforcing tenant's row, inserted empty when the
tenant has none), then the connections in id order, then their own row, and judge the rule from what they locked. A
change to the rule waits for them, and its revocation then sees the session your redemption wrote in its transaction;
or they wait for the change, and see it. Write the session inside the redemption's transaction (see
[Redeeming a handoff](redeeming-a-handoff.md#transactions)) for this to hold. On PostgreSQL under `REPEATABLE READ`, a
redemption or completion that waited can get a serialisation failure instead: it is thrown, and the whole transaction
is retried or the person starts again.

If you bind your own `Contracts\Enforcement`, the package asks it as you bound it and locks nothing of its own
enforcement. A current read in your contract does not close the gap above: your contract must itself serialise an
admission against changes to its rule until the session commits (for example by locking the row your rule is stored
in, in the same transaction, with the same lock your changes take first), and your revocation must find sessions with
current reads or writes, never from a snapshot.

### Inherited rules

By default each tenant's own rule applies to it alone. If your tenants form a tree and a child should follow an
ancestor's rule, bind `Contracts\EnforcementInheritance`: it answers, for a tenant and an application, the tenant whose
rule applies. The policy then names it as `enforcingTenantId`, and only that tenant's connections satisfy it.

The package asks it inside a redemption's or a completion's transaction, before it takes the enforcing tenant's lock
and again once it holds it; an answer that changed in between refuses the admission (`connection_unavailable`) rather
than lock another tenant's rule out of order. Answer it in a way that is safe inside the caller's transaction: from
state that does not change under it (a tenant's place in the tree rarely does), or read it with a current read rather
than from the transaction's snapshot.

Here your `Tenant` model names, in `enforcement_root_id`, the root whose rule a tenant follows (none for a root, whose
own rule applies). `TenantTreeInheritance`, a `final readonly` class that implements `Contracts\EnforcementInheritance`,
answers from it:

<!-- snippet: tests/Integration/Examples/Enforcement/TenantTreeInheritance.php#enforcement-inheritance-tenant -->
```php
/**
 * The tenant whose rule applies to sessions active in the tenant: the root
 * of its branch, on every application.
 *
 * @param  string  $tenantId
 * @param  string  $application
 * @return string
 */
#[\Override]
public function enforcingTenant(string $tenantId, string $application): string
{
    unset($application);

    // A tenant's place in the tree rarely changes, so a plain read is safe
    // inside the caller's transaction
    $tenant = Tenant::query()->findOrFail($tenantId);

    return $tenant->enforcement_root_id ?? $tenant->id;
}
```

Bind it in a service provider's `register()`:

<!-- snippet: tests/Integration/Examples/Enforcement/AppServiceProvider.php#enforcement-inheritance-binding -->
```php
$this->app->singleton(EnforcementInheritance::class, TenantTreeInheritance::class);
```

## Exemptions

A break-glass administrator may need to sign in while the identity provider is down. Bind
`Contracts\EnforcementExemption` to say who is exempt (the default exempts nobody), and when a session would be refused,
ask through the gate, which reports each exemption it grants as `ExemptionUsed`. The tenant authentication policy above
asks `Enforcement\ExemptionGate` for the session's user, named as an `Identities\IdentityReference`, and refuses the
session unless the answer is `exempt`:

<!-- snippet: tests/Integration/Examples/Enforcement/TenantAuthenticationPolicy.php#enforcement-exemption -->
```php
$identity = new IdentityReference($session->user_type, $session->user_id);

$outcome = app(ExemptionGate::class)->admit($policy, 'web', $identity, $client, $session->id);

return $outcome->isExempt();
```

A policy that requires nothing needs no exemption: the gate answers `not_exempt` without asking. An exception from
your contract is thrown, never read as exempt.

Only your gate asks the exemption contract. The package's own admission, at completion and again at redemption, never
does: a sign-in through a connection the rule does not list is refused there as `enforcement_unsatisfied`, exempt
identity or not. An exemption admits a session your application establishes some other way (a password or a passkey
your sign-in accepts while the rule is on), asked from your tenant authentication policy or wherever you refuse a
non-compliant session; it never turns a sign-in through an unlisted connection into an accepted one. Keeping the
exemption at one gate keeps one place that grants it and reports it, so every exemption used is in your
`ExemptionUsed` trail.

## Revoking sessions

When a rule is turned on, or its connections change while it is on, the package calls `Contracts\SessionRevocation` with
`RevocationScope::tenant($policy)`, synchronously, inside the transaction that writes the change. Revoke the sessions
active in the tenant (or in a tenant that inherits its rule) that were not established through one of
`$scope->policy->connectionIds`, unless your exemption contract exempts their identity. The same contract is later
called with `RevocationScope::connection()` when a connection is disabled or deleted, and with
`RevocationScope::identityInConnection()` when a link is removed. Turning a rule off calls nothing (see
[below](#turning-a-rule-off-revokes-nothing)).

Here `RevokeSessions`, a `final readonly` class that implements `Contracts\SessionRevocation`, marks revoked the rows of
the application's own `sessions` table, the one `UserSession` above reads, with the reason the scope gives.
`Database\StorageConnection::name()` names the Laravel connection the package writes through (`sso.storage.connection`).
The class imports `Illuminate\Database\Query\Builder`, `Illuminate\Support\Facades\DB` and, from
`SineMacula\Laravel\Sso`, `Database\StorageConnection`, `Revocation\Enums\RevocationScopeKind` and
`Revocation\RevocationScope`, and your service provider binds it as `Contracts\SessionRevocation`. Its body:

<!-- snippet: tests/Integration/Examples/Enforcement/RevokeSessions.php#revoke-sessions -->
```php
/**
 * Revoke the sessions of the scope, inside the package's transaction.
 *
 * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
 * @return void
 */
#[\Override]
public function revoke(RevocationScope $scope): void
{
    // On the package's storage connection, to commit with the change
    $sessions = DB::connection(StorageConnection::name())->table('sessions')->whereNull('revoked_at');

    $revoked = match ($scope->kind) {
        RevocationScopeKind::TENANT => $sessions
            // The scope names only the enforcing tenant: include every
            // tenant that inherits its rule
            ->whereIn('tenant_id', $this->tenantsUnderRule($scope->tenantId))
            // A session with no SSO connection (a password session) holds
            // NULL, and `NULL NOT IN (...)` is never true, so it must be
            // named: it is exactly what the rule exists to remove
            ->where(static fn (Builder $query): Builder => $query->whereNull('sso_connection_id')
                ->orWhereNotIn('sso_connection_id', $scope->policy->connectionIds ?? [])),
        // Here `$scope->tenantId` is the connection's tenant, not the
        // tenant a session is active in now, which a switch changes:
        // connection ids are unique, so never narrow by `tenant_id`
        RevocationScopeKind::CONNECTION => $sessions->where('sso_connection_id', $scope->connectionId),
        // A removed link and a widened scope name the link
        // (`$scope->linkId`); with no link column, revoke the identity's
        // sessions through the connection (`sso_connection_id` and
        // `user_id`), which is broader and never narrower
        default => $sessions->where('sso_link_id', $scope->linkId),
    };

    // The sessions of identities your exemption contract exempts may stay
    $revoked->update(['revoked_at' => now(), 'revoked_reason' => $scope->reason->value]);
}

/**
 * The enforcing tenant and every tenant that inherits its rule: the reverse
 * of your `EnforcementInheritance`, answered by your tenant model.
 *
 * @param  string  $enforcingTenantId
 * @return array<array-key, mixed>
 */
private function tenantsUnderRule(string $enforcingTenantId): array
{
    return Tenant::query()->whereKey($enforcingTenantId)
        ->orWhere('enforcement_root_id', $enforcingTenantId)
        ->pluck('id')
        ->all();
}
```

The tenant scope carries only `$scope->tenantId`, the enforcing tenant: resolving the tenants that inherit its rule is
yours, and leaving them out leaves their sessions in place. A connection's or a link's scope carries the connection's
tenant, which need not be the tenant a session established through it is active in now: a session that switched its
active tenant still began through the connection, so match it by the connection or the link alone, never by the tenant
it is active in. A session established without SSO usually records no connection; match it with `whereNull()`
alongside `whereNotIn()`, since SQL never counts `NULL` as outside a list.

Write through the same Laravel connection the package uses, so your writes commit or roll back with the change; a write
through another connection, even to the same database, is not atomic with it. Find the sessions with an update or delete
(a current read), never by reading them first inside the change's transaction: a session committed by a redemption the
change waited for is newer than that transaction's snapshot. Signal failure by throwing: the change is rolled back (no
new version, no event) and the exception reaches your caller as a server error. Never return as if you revoked what you
did not.

Under `laravel-iam` the contract is bound to `laravel-authentication`'s session revocation, which runs inside the
package's transaction, so you bind nothing. An enforcement change and a widened scope always revoke; a disabled or
deleted connection and a removed link revoke unless `laravel-authentication`'s own switch for them is off. See
[Integrating with `laravel-iam`](integrating-with-laravel-iam.md#revocation).

### Turning a rule off revokes nothing

Turning a rule off calls nothing, deliberately. A rule turned off requires nothing, so no session falls out of
compliance: every session that met the rule meets no rule just as well, and a session the rule would have refused was
revoked when the rule went on or its connections changed. Calling the contract anyway would hand it a policy whose
`connectionIds` is empty, and a revocation written as above, revoking every session not established through one of them,
would then end every session of the tenant, the very ones the rule had just admitted. The rule's new version is still
written and `EnforcementChanged` still reports the change, so a session that recorded the old version can be told apart;
nothing needs ending.
