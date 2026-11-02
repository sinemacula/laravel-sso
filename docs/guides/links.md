# Links

A link associates a connection's issuer and subject with one of your identities, so a later sign-in through that
connection resolves to the identity. The package stores links itself, in `sso_links`, keyed by the connection the link
was made through, the issuer and the subject (for SAML, the `NameID` with its format), and nothing else: a name, an
email or any other mapped attribute never selects an identity.

## Using the link store

By default nothing is linked: the `Linker` contract is bound to `NoLinks`, so every `sign_in` result is unlinked. Bind
the package's link store to use the links it stores:

```php
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Links\LinkStore;

public function register(): void
{
    $this->app->scoped(Linker::class, LinkStore::class);
}
```

Under `laravel-iam` this binding is made for you, and the same store answers `laravel-authentication`'s link contract.

A result resolves only through a link of the connection it completed through. A tenant that enters another identity
provider's issuer in its own connection reaches none of that provider's links. The subject is matched byte for byte:
`Subject`, `subject` and `subject` followed by a space are three subjects, whatever your database's collation. A
reserved link, held for linking by a verified domain, resolves nothing, and neither does a suspended one; neither counts
as an unlinked subject, so neither can be provisioned, reserved or handed off as unlinked.

Each link records when it was created and when it last resolved a sign-in, to the minute.

## How many links an identity may hold

One subject is linked to one identity at most in a connection; that is not configurable. How many links one identity
may hold in one connection is: by default one. Bind your own `LinkLimit` to allow more:

```php
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

final readonly class TwoLinksPerConnection implements LinkLimit
{
    public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
    {
        return 2;
    }
}

$this->app->singleton(LinkLimit::class, TwoLinksPerConnection::class);
```

The limit is asked while the connection is locked, and counts the identity's active and suspended links and its
reserved ones that have not expired. An answer below one is a misconfiguration and throws a `LogicException`. An
identity may hold links through the connections of several tenants; each link stands alone.

Links are made by the flows: a redeemed `link` flow, [provisioning](provisioning.md), or a [verified
domain](linking-by-domain.md). A creation that is refused
answers `subject_already_linked` (the subject is linked already, to this identity or another; the answer never says
which) or `link_limit_reached`, with nothing written.

## The link purpose

A `link` flow attaches a subject to an identity your application has already authenticated: an account screen's "connect
your identity provider" button, say. It is the only way besides a verified domain that a result ever attaches to an
existing identity (SSO-8.5). It creates no session.

```php
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

$identity = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

$start = app(AuthorizationRequestService::class)->start('web', Purpose::LINK, $connectionId, null, $identity);
```

The flow then goes as any other does, and its handoff code is redeemed at an endpoint of your own that gives the caller
it has authenticated:

```php
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

$caller = new IdentityReference($request->user()->getMorphClass(), (string) $request->user()->getKey());

$result = app(HandoffRedemption::class)->redeem(
    Purpose::LINK,
    'web',
    (string) $request->input('connection'),
    (string) $request->input('code'),
    (string) $request->input('verifier'),
    $caller,
);
```

A `link` writes no session, so it may use this standalone path, which commits before it answers. When your endpoint
writes something of its own that must commit with the link, call `admit()` inside your transaction instead
([Redeeming a Handoff](redeeming-a-handoff.md)). Never sign anyone in from a `link` result, whichever you call:
`$result->linkedIdentity` is only the identity the link now belongs to.

What is asked, and when:

| Step       | Asked                                                                                                                                                                                                        | Refusal                                                                                                                                                        |
|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Start      | Freshness, `sso.link.create`                                                                                                                                                                                 | `freshness_required`                                                                                                                                           |
| Completion | Eligibility; a live reservation of the subject; another identity holding the subject, active or suspended                                                                                                    | `link_ineligible`, `link_reserved`, `subject_already_linked`                                                                                                   |
| Redemption | The caller is the bound identity; freshness; eligibility; independent authentication, when the identity holds a verified domain link; a live reservation; another identity holding it; the link's continuity | `identity_mismatch`, `freshness_required`, `link_ineligible`, `independent_authentication_required`, `link_reserved`, `subject_already_linked`, `link_changed` |

Redemption asks again because holding the code and its verifier proves only that the client started the flow. It does
not prove who is calling now: you must pass the caller your application has authenticated, and no caller, or one that
differs from the bound identity in a single byte of its type or id, is `identity_mismatch`. Freshness and eligibility
are asked again before anything is written, even when the subject is already linked to that same identity.

What the link is at redemption then decides, compared with the link observed at completion:

| At completion                | At redemption                                    | Result                                              |
|------------------------------|--------------------------------------------------|-----------------------------------------------------|
| Unlinked                     | Still unlinked, or its reservation has expired   | The link is created, with the origin `link_purpose` |
| Unlinked                     | Linked to the bound identity                     | Success, with no second link                        |
| Linked to the bound identity | The same link, by its id, active or suspended    | Success                                             |
| Linked to the bound identity | Removed, or removed and made again with a new id | `link_changed`, even for the same identity          |
| Anything                     | Linked to another identity, active or suspended  | `subject_already_linked`, which names nobody        |
| Anything                     | Held by a live reservation                       | `link_reserved`                                     |

Creating the link can still be refused by the store: `link_limit_reached` when the identity holds as many links as it
may, or `subject_already_linked` when the unique index refuses it, each with nothing written. Every refusal after the
code was consumed spends the code, and the client starts again.

An explicit link never takes over a live reservation, even for the identity it matched. A reservation belongs to the
sign-in flow that holds it: the `link` is busy until that flow's handoff is redeemed or expires. An expired reservation
is logically absent, and the link replaces its row.

> [!IMPORTANT]
> A `link` asks the freshness contract (`sso.link.create`, with `sso.freshness.max_age_seconds.link_create`) and the
> eligibility contract, and both defaults refuse. Bind your own of each first. Bind the package's `LinkStore` as your
> `Linker` too: a `link` writes to the links table, so an alternative linker must answer from that same table, with a
> link's id, or the links it makes will never resolve.

## Confirming a suspended link

A link made through a [verified domain](linking-by-domain.md) keeps that provenance. Whenever its identity turns out to
hold a principal outside the connection's tenant, it is suspended (SSO-8.8): the suspension is stored, the connection's
links version is raised, `LinkSuspended` is reported, and the link resolves nothing. A sign-in or a reauthentication
through it is `link_suspended`, and the subject can be neither reserved nor provisioned.

Your `PrincipalScope` answering `unknown` suspends the link the same way, so answer it only for a set of principals you
truly cannot vouch for. A store you cannot reach for the moment should throw: the exception propagates, refuses nothing
and suspends nothing.

The suspension is latched. Removing the outside principal later never restores the link. Only the person can, through
the `link` purpose, with the rules above: the caller is the identity holding the link, with fresh authentication,
eligible, and [authenticated independently of it](#confirming-it-is-the-person). Admitting the code is the confirmation.
It makes the link active with the `link_purpose` provenance, clears the suspension for good, raises the links version
and reports `LinkConfirmed`. Having left its domain provenance behind, the link is no longer judged by the identity's
principals at all.

The same happens for a link on a verified domain that is not suspended. A link with any other provenance has nothing to
confirm: it passes, changes nothing and reports only the redemption. A suspension held by another identity is refused as
`subject_already_linked`, and that link stays suspended.

Suspension blocks new admissions and reauthentication; it does not, by itself, end a session. The change that widens a
person's scope does that: your principal mutation calls `Linking\ScopeWidening`, which also revokes the sessions
established through the affected domain links, through your `SessionRevocation` binding, in that same transaction. A
suspension a resolution finds revokes nothing until then. Confirming a link does not bring a revoked session back, and
it creates none: the person signs in again.

### Confirming it is the person

The identity provider behind a verified domain link was not the person's choice. It can sign them in, and it can renew
their freshness, so it could answer a `link` of them with the same subject. That is not the person confirming anything,
and it would clear the very provenance that holds the provider to the rule above.

So while an identity holds a link of verified domain provenance, active or suspended, in any connection, every `link` of
it needs `Contracts\LinkConfirmation` to answer `independent`, or it is `independent_authentication_required`. That covers
adding a second subject as well as confirming: a new subject would stand with no such provenance. The default refuses
everyone, so bind your own before anyone can confirm. A `link` of an identity holding no such link never asks it.

```php
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

final readonly class PasswordSessionsConfirm implements LinkConfirmation
{
    public function __construct(private Sessions $sessions) {}

    public function judge(IdentityReference $identity, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        // Under the guard your session writers take, through the redeemer's commit
        $session = $this->sessions->currentLocked($identity);

        // Neither established through one of these links, nor renewed through one
        return $session !== null && $session->wasAuthenticatedApartFrom($domainLinkIds)
            ? LinkConfirmationVerdict::INDEPENDENT
            : LinkConfirmationVerdict::DEPENDENT;
    }
}

$this->app->scoped(LinkConfirmation::class, PasswordSessionsConfirm::class);
```

> [!IMPORTANT]
> Freshness that came from an SSO sign-in does not count here, even when your `Freshness` binding answers `fresh` for it.
> Someone whose only credential is the identity provider therefore cannot confirm the link: give them another credential
> first, or remove the link, which ends its sessions, and have them link again once they hold one.

## Deciding who may link

`Contracts\LinkEligibility` decides whether an identity may link through a connection, for example only as a member of
the connection's tenant. Its default, `RefusingLinkEligibility`, refuses everyone.

```php
use App\Models\Membership;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;

final readonly class MembersMayLink implements LinkEligibility
{
    public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
    {
        $member = Membership::query()
            ->useWritePdo()
            ->where('identity_id', $identity->id)
            ->where('tenant_id', $connection->getTenantId())
            ->lockForUpdate()
            ->first();

        return $member !== null ? LinkEligibilityVerdict::ELIGIBLE : LinkEligibilityVerdict::INELIGIBLE;
    }
}

$this->app->singleton(LinkEligibility::class, MembersMayLink::class);
```

It is asked at completion, under the connection's lock, and again in the redemption's transaction, after the package's
locks. Read from the write connection, keep nothing between calls and let an error propagate: an exception rolls the
redemption back as a server error and leaves the code unspent, and it is never a refusal.

The package's locks do not hold your writers back unless they take part. Your answer is protected through the
redemption's commit in one of two ways. Either a guard your writers also take keeps it true, by writing through the
package's storage connection inside this transaction, as the lock above does for a membership that exists (a row being
absent needs a guard row of its own), or you accept that a change committed just after the answer does not undo the
link, and handle that when the change is made. Take your guards after the package's locks in every path, or your writers
will deadlock against a redemption.

## Listing and removing links

`SineMacula\Laravel\Sso\Links\LinkService` lists an identity's links and removes one, for your account and
administration screens. Who may list or remove whose links is your application's authorisation, so check it first.

```php
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkService;

$links  = app(LinkService::class);
$caller = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

$mine = $links->list('me', $caller);                                     // list<LinkSummary>, oldest first
$some = $links->list(new IdentityReference(User::class, '42'));          // another identity's, for administrators

$result = $links->remove('me', $linkId, $caller, new ActingIdentity($user->getMorphClass(), (string) $user->getKey()));
```

The identity is an `IdentityReference`, or `'me'` for the caller you pass. `'me'` without a caller, or any other
string, throws an `InvalidArgumentException`.

Each `LinkSummary` holds the link's id, its connection with the connection's tenant and protocol, the issuer, the
`NameID` format, its state (`active`, `reserved` or `suspended`), whether a verified domain made it and has not been
confirmed since, and when it was created and last used. It never holds the subject. `json_encode()` gives it with
snake_case keys.

> [!IMPORTANT]
> Removing a link asks the freshness contract (`sso.link.remove`, with `sso.freshness.max_age_seconds.link_remove`),
> and the default contract refuses every operation. Bind your own first (see [Freshness](freshness.md)).

A removal answers a `LinkResult`:

| Result                                 | Meaning                                                                         |
|----------------------------------------|---------------------------------------------------------------------------------|
| `isRemoved()`, `link`                  | The link was deleted and the identity's sessions through its connection revoked |
| `refused`, reason `link_not_found`     | The identity has no link with that id; another identity's link answers the same |
| `refused`, reason `freshness_required` | The caller did not authenticate recently enough                                 |

Removing an identity's last link is allowed; whether the identity can still sign in is your application's concern.

## Revoking sessions

When a link is removed, the package calls the `SessionRevocation` contract inside the transaction that deletes the
link, with `RevocationScope::identityInConnection()`: the identity's sessions established through the link's
connection, with the reason `link_removed`. If your binding throws, the link is not removed, nothing is reported, and
the exception propagates. Write through the same database connection the package uses, so the revocation commits or
rolls back with the removal.

The default revocation does nothing: without `laravel-authentication`, bind your own, or accept that a removed link
leaves existing sessions untouched.

## Events

| Event           | When                                                                                                |
|-----------------|-----------------------------------------------------------------------------------------------------|
| `LinkCreated`   | A link was made; `origin` says how (`link_purpose`, `provisioning`, `verified_domain`, `migration`) |
| `LinkRemoved`   | A link was removed and the identity's sessions through the connection revoked                       |
| `LinkActivated` | A reservation became an active link, with what you need to notify the person on their own channels  |
| `LinkConfirmed` | A `link` cleared a link's verified domain provenance and any suspension                             |
| `LinkSuspended` | A link on a verified domain was found outside its tenant, and stored as suspended                   |

Each is dispatched after the transaction commits, never when it rolls back, and names the connection, its tenant and
protocol, the identity, and the acting identity you passed; a link made or confirmed by a flow also names the
application, the purpose and the request's public reference. None carries the subject or an email address. A refused
creation or removal reports nothing of its own, and a refused `link` reports one `FlowFailed`, whose context names the
identity the flow was started for, never the identity holding the subject.
