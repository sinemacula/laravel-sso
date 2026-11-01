# Enforcement

A tenant can require that every session active in it is established through one of its own enabled connections: an
SSO-only tenant. The package stores that rule per tenant, answers it through a contract your sign-in code (or
`laravel-iam`) asks on every sign-in, switch and refresh, and, when the rule changes, asks your application to revoke
the sessions that no longer comply, inside the same transaction. Your administration screens change the rule through
`SineMacula\Laravel\Sso\Enforcement\EnforcementService`; who may do so is your application's authorisation, so check it
before you call the service.

```php
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;

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
> `laravel-authentication`'s revocation (AUTH-2.12), which an enforcement change then always runs.

## Turning it on

```php
use SineMacula\Laravel\Sso\Administration\ActingIdentity;

$result = $enforcement->update(
    $tenant->id,
    true,
    [$connectionId],
    new ActingIdentity($user->getMorphClass(), (string) $user->getKey()),
);

if ($result->isSucceeded()) {
    $version = $result->enforcement->version; // a new lower-case ULID on every change
}
```

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

```php
$summary = $enforcement->get($tenant->id);

$summary->enabled;        // bool
$summary->connectionIds;  // the ids stored, in id order
$summary->version;        // null while the tenant never had a rule
$summary->changedAt;      // CarbonImmutable in UTC, or null
```

The ids are those stored: one whose connection was since disabled or deleted is still listed here, but no longer
satisfies the rule.

## Asking whether a session complies

Your sign-in code asks `Contracts\Enforcement` for the tenant a session is active in and the application:

```php
use SineMacula\Laravel\Sso\Contracts\Enforcement;

$policy = app(Enforcement::class)->policy($activeTenantId, 'web');

if ($policy->isRequired() && !$policy->isSatisfiedBy($session->ssoConnectionId)) {
    // refuse the session, unless the identity is exempt (below)
}

$session->enforcementVersion = $policy->version; // recheck the session once the version moves on
```

It reads the stored rule on the write connection on every call and caches nothing, so a change applies from the next
question. Record `version` against each session and recheck a session whose recorded version is no longer the
current one. A database error is thrown, never answered as "not required". If every satisfying connection has since
been disabled, the rule is still required and nobody complies until an administrator names an enabled connection or
turns it off.

Under `laravel-iam` you do not call it yourself: it is folded into `laravel-authentication`'s tenant authentication
policy (AUTH-2.12), asked at sign-in, at the choice of principal, on every switch and on refresh.

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

```php
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

$this->app->singleton(EnforcementInheritance::class, fn () => new class implements EnforcementInheritance {
    public function enforcingTenant(string $tenantId, string $application): string
    {
        return Tenant::query()->findOrFail($tenantId)->enforcementRoot()->id;
    }
});
```

## Exemptions

A break-glass administrator may need to sign in while the identity provider is down. Bind
`Contracts\EnforcementExemption` to say who is exempt (the default exempts nobody), and when a session would be refused,
ask through the gate, which reports each exemption it grants as `ExemptionUsed`:

```php
use SineMacula\Laravel\Sso\Enforcement\ExemptionGate;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

$outcome = app(ExemptionGate::class)->admit($policy, 'web', new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $sessionId);

if (!$outcome->isExempt()) {
    // refuse the session
}
```

A policy that requires nothing needs no exemption: the gate answers `not_exempt` without asking. An exception from
your contract is thrown, never read as exempt.

## Revoking sessions

When a rule is turned on, or its connections change while it is on, the package calls `Contracts\SessionRevocation`
with `RevocationScope::tenant($policy)`, synchronously, inside the transaction that writes the change. Revoke the
sessions active in the tenant (or in a tenant that inherits its rule) that were not established through one of
`$scope->policy->connectionIds`, unless your exemption contract exempts their identity. Turning a rule off calls
nothing. The same contract is later called with `RevocationScope::connection()` when a connection is disabled or
deleted, and with `RevocationScope::identityInConnection()` when a link is removed.

```php
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

final class RevokeSessions implements SessionRevocation
{
    public function revoke(RevocationScope $scope): void
    {
        // The same Laravel connection as `sso.storage.connection`, so the revocation commits with the change
        $sessions = DB::connection(config('sso.storage.connection'))->table('sessions');

        match ($scope->kind) {
            RevocationScopeKind::TENANT => $sessions
                // The scope names only the enforcing tenant: include every tenant that inherits its rule
                ->whereIn('tenant_id', $this->tenantsUnderRule($scope->tenantId))
                // A session with no SSO connection (a password session) holds NULL, and `NULL NOT IN (...)` is never
                // true, so it must be named: it is exactly what the rule exists to remove
                ->where(fn (Builder $query) => $query->whereNull('sso_connection_id')
                    ->orWhereNotIn('sso_connection_id', $scope->policy->connectionIds)),
            RevocationScopeKind::CONNECTION => $sessions->where('tenant_id', $scope->tenantId)
                ->where('sso_connection_id', $scope->connectionId),
            default => $sessions->where('tenant_id', $scope->tenantId)
                ->where('sso_connection_id', $scope->connectionId)
                ->where('user_id', $scope->identity?->id),
        };

        // You may leave out the sessions of identities your exemption contract exempts

        $sessions->update(['revoked_at' => now(), 'revoked_reason' => $scope->reason->value]);
    }

    /**
     * The enforcing tenant and every tenant that inherits its rule: the
     * reverse of your `EnforcementInheritance`, answered by your tenant model.
     *
     * @return list<string>
     */
    private function tenantsUnderRule(string $enforcingTenantId): array
    {
        return Tenant::query()->whereKey($enforcingTenantId)
            ->orWhere('enforcement_root_id', $enforcingTenantId)
            ->pluck('id')
            ->all();
    }
}
```

The tenant scope carries only `$scope->tenantId`, the enforcing tenant: resolving the tenants that inherit its rule is
yours, and leaving them out leaves their sessions in place. A session established without SSO usually records no
connection; match it with `whereNull()` alongside `whereNotIn()`, since SQL never counts `NULL` as outside a list.

Write through the same Laravel connection the package uses, so your writes commit or roll back with the change; a
write through another connection, even to the same database, is not atomic with it. Find the sessions with an update
or delete (a current read), never by reading them first inside the change's transaction: a session committed by a
redemption the change waited for is newer than that transaction's snapshot. Signal failure by throwing: the
change is rolled back (no new version, no event) and the exception reaches your caller as a server error. Never return
as if you revoked what you did not.

Under `laravel-iam` the contract is bound to `laravel-authentication`'s session revocation (AUTH-2.12, AUTH-6.4,
AUTH-6.5), which runs inside the package's transaction, so you bind nothing.
