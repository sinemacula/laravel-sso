# Links

A link associates a connection's issuer and subject with one of your identities, so a later sign-in through that
connection resolves to the identity. The package stores links itself, in `sso_links`, keyed by the connection the link
was made through, the issuer and the subject (for SAML, the `NameID` with its format), and nothing else: a name, an
email or any other mapped attribute never selects an identity.

## Using the link store

By default nothing is linked: the `Linker` contract is bound to `NoLinks`, so every `sign_in` result is unlinked. Bind
the package's link store in a service provider's `register()` to use the links it stores:

<!-- snippet: tests/Integration/Examples/Links/AppServiceProvider.php#links-linker-binding -->
```php
$this->app->scoped(Linker::class, LinkStore::class);
```

Under `laravel-iam` this binding is made for you, and the same store answers `laravel-authentication`'s link contract:
`laravel-authentication` stores no links, and its contract answers exactly the link the package admitted (see
[Integrating with `laravel-iam`](integrating-with-laravel-iam.md#links)).

A result resolves only through a link of the connection it completed through. A tenant that enters another identity
provider's issuer in its own connection reaches none of that provider's links. The subject is matched byte for byte:
`Subject`, `subject` and `subject` followed by a space are three subjects, whatever your database's collation. A
reserved link, held for linking by a verified domain, resolves nothing, and neither does a suspended one; neither counts
as an unlinked subject, so neither can be provisioned, reserved or handed off as unlinked.

Each link records when it was created and when it last resolved a sign-in, to the minute.

## How many links an identity may hold

One subject is linked to one identity at most in a connection; that is not configurable. How many links one identity
may hold in one connection is: by default one. Implement `Contracts\LinkLimit` to allow more; here
`TwoLinksPerConnection` allows two:

<!-- snippet: tests/Integration/Examples/Links/TwoLinksPerConnection.php#links-limit -->
```php
/**
 * The most links the identity may hold in the connection.
 *
 * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
 * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
 * @return int
 */
#[\Override]
public function maxLinks(IdentityReference $identity, SsoConnection $connection): int
{
    // The same for every identity and connection
    unset($identity, $connection);

    return 2;
}
```

Bind it in a service provider's `register()`:

<!-- snippet: tests/Integration/Examples/Links/AppServiceProvider.php#links-limit-binding -->
```php
$this->app->singleton(LinkLimit::class, TwoLinksPerConnection::class);
```

The limit is asked while the connection is locked, and counts the identity's active and suspended links and its
reserved ones that have not expired. An answer below one is a misconfiguration and throws a `LogicException`. An
identity may hold links through the connections of several tenants; each link stands alone.

Links are made by the flows: a redeemed `link` flow, [provisioning](provisioning.md), or a
[verified domain](linking-by-domain.md). A creation that is refused answers `subject_already_linked` (the subject is
linked already, to this identity or another; the answer never says which) or `link_limit_reached`, with nothing
written.

## The link purpose

A `link` flow attaches a subject to an identity your application has already authenticated: an account screen's "connect
your identity provider" button, say. It is the only way besides a verified domain that a result ever attaches to an
existing identity. It creates no session. Start it for the user your application has authenticated, here `$user`, as
an `Identities\Caller` with the session they are on: the [freshness contract](freshness.md#the-caller) judges that
session, and the flow is bound to the identity alone:

<!-- snippet: tests/Integration/Examples/Links/LinksExampleTest.php#links-start -->
```php
// The signed-in user, on the session freshness judges
$caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId());

$start = app(AuthorizationRequestService::class)->start('web', Purpose::LINK, $connectionId, $client, null, $caller);
```

`$client` is the `Http\ClientContext` of the request the call is made for, which your controller builds with
`ClientContext::fromRequest($request)`; work with no request (a console command, a queued job) passes
`new ClientContext(null, null)`. Every call that counts an attempt or reports an event takes one, never reading the
request itself, and each event it reports carries the client's IP address and user agent.

The flow then goes as any other does, and its handoff code is redeemed at an endpoint of your own that gives the caller
it has authenticated, `$user` again on their session, never an identity the request names. Its identity must be the
one the flow was started for, byte for byte; the caller as you give it, with its session, is the one freshness and the
link confirmation judge:

<!-- snippet: tests/Integration/Examples/Links/LinksExampleTest.php#links-redeem -->
```php
// The signed-in user, on the session freshness and confirmation judge
$caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId());

$result = app(HandoffRedemption::class)->redeem(
    Purpose::LINK,
    'web',
    $request->string('connection')->toString(),
    $request->string('code')->toString(),
    $request->string('verifier')->toString(),
    ClientContext::fromRequest($request),
    $caller,
);
```

A `link` writes no session, so it may use this standalone path, which commits before it answers. A transaction the
database rolls back as a deadlock, a lock wait timeout or a serialisation failure is tried again, at most three times in
all, and the attempt is counted against the rate limit once. When your endpoint writes something of its own that must
commit with the link, call `admit()` inside your transaction instead ([Redeeming a Handoff](redeeming-a-handoff.md)).
Never sign anyone in from a `link` result, whichever you call: `$result->linkedIdentity` is only the identity the link
now belongs to.

What is asked, and when:

| Step       | Asked                                                                                                                                                                                                                                                     | Refusal                                                                                                                                                                                   |
|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Start      | Freshness, `sso.link.create`                                                                                                                                                                                                                              | `freshness_required`                                                                                                                                                                      |
| Completion | Eligibility; a live reservation of the subject; another identity holding the subject, active or suspended; a link whose scope cannot be judged                                                                                                            | `link_ineligible`, `link_reserved`, `subject_already_linked`, `principal_scope_unknown`                                                                                                   |
| Redemption | The caller is the bound identity; freshness; eligibility; independent authentication, when the identity holds or held a verified domain link; a live reservation; another identity holding it; a link whose scope cannot be judged; the link's continuity | `identity_mismatch`, `freshness_required`, `link_ineligible`, `independent_authentication_required`, `link_reserved`, `subject_already_linked`, `principal_scope_unknown`, `link_changed` |

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
> `Linker` too, or a wrapper implementing `Contracts\LinkStorage` that delegates to it: a `link` writes to the links
> table, so a linker without it is refused with a `LogicException` before anything is written, since the links it made
> would never resolve.

## Confirming a suspended link

A link made through a [verified domain](linking-by-domain.md) keeps that provenance. Whenever its identity turns out to
hold a principal outside the connection's tenant, it is suspended: the suspension is stored, the connection's links
version is raised, `LinkSuspended` is reported, the sessions established through it are revoked, and the link resolves
nothing. A sign-in or a reauthentication through it is `link_suspended`, and the subject can be neither
reserved nor provisioned.

Your `PrincipalScope` answering `unknown` refuses that attempt alone, with `principal_scope_unknown`, whatever the
purpose: the link is not suspended and nothing is revoked, since uncertainty asserts no widening, and its next
resolution judges it again. A link already suspended stays suspended. A store you cannot reach for the moment should
throw: the exception propagates, refuses nothing and suspends nothing.

The suspension is latched. Removing the outside principal later never restores the link. Only the person can, through
the `link` purpose, with the rules above: the caller is the identity holding the link, with fresh authentication,
eligible, and [authenticated independently of it](#confirming-it-is-the-person). Admitting the code is the confirmation.
It makes the link active with the `link_purpose` provenance, clears the suspension for good, raises the links version
and reports `LinkConfirmed`. Having left its domain provenance behind, the link is no longer judged by the identity's
principals at all.

The same happens for a link on a verified domain that is not suspended. A link with any other provenance has nothing to
confirm: it passes, changes nothing and reports only the redemption. A suspension held by another identity is refused as
`subject_already_linked`, and that link stays suspended.

Suspension blocks new admissions and reauthentication, and ends the sessions established through the link. The change
that widens a person's scope is the primary place that happens: your principal mutation calls `Linking\ScopeWidening`,
which revokes them through your `SessionRevocation` binding, in that same transaction, and revokes again for a link
already suspended. A resolution that finds a definite outside scope repairs what it missed, revoking through the link in
its own transaction when it latches. Revocation is therefore asked more than once for a link, and must be idempotent.
Confirming a link does not bring a revoked session back, and it creates none: the person signs in again.

### Confirming it is the person

The identity provider behind a verified domain link was not the person's choice. It can sign them in, and it can renew
their freshness, so it could answer a `link` of them with the same subject. That is not the person confirming anything,
and it would clear the very provenance that holds the provider to the rule above.

So once an identity has held an active link of verified domain provenance, in any connection, every `link` of it needs
`Contracts\LinkConfirmation` to answer `independent`, or it is `independent_authentication_required`. That covers adding
a second subject as well as confirming: a new subject would stand with no such provenance. It goes on after the link is
removed or confirmed: the package records on the identity's guard, when a reservation is activated, that the identity
has held one, and never clears it, so removing the link and then linking from the session that survived it is asked
too. The ids given are those of the links held now, which can be none. The default refuses everyone, so bind your own
before anyone can confirm. A `link` of an identity that has never held such a link never asks it.

`judge()` is given the caller the redemption is made for, an `Identities\Caller`: the identity the code is bound to and
the session you passed with it. Judge that session, never the request being served, and answer by how it was
established, not by which links remain: through any link that had verified domain provenance at the time, given,
removed since or confirmed since, it is `dependent`. A caller with no session, and a session you cannot tie to the
caller's identity or guard until the redeemer commits, are `dependent` too. So record, when you admit a session from a
redemption, whether the link it stood on (`$result->linkId`) had that provenance then: an admitted `sign_in` answers it
as `$result->provenance?->linkProvenance`, `LinkOrigin::VERIFIED_DOMAIN` for such a link.

Here `PasswordSessionsConfirm` implements `Contracts\LinkConfirmation`, reading the caller's session, by its id and the
caller's identity, from your own session store (`$this->sessions`, given to its constructor), which recorded that when
the session was admitted:

<!-- snippet: tests/Integration/Examples/Links/PasswordSessionsConfirm.php#links-confirmation -->
```php
/**
 * Whether the caller's session is independent of the links.
 *
 * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
 * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
 * @param  list<string>  $domainLinkIds
 * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
 */
#[\Override]
public function judge(Caller $caller, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
{
    unset($connection);

    // The caller's own session, none without one, locked under your session
    // writers' guard until the redeemer commits
    $session = $this->sessions->lockedFor($caller);

    // Neither established through a link of verified domain provenance,
    // held now or before, as recorded when the session was admitted, nor
    // renewed through one
    $independent = $session !== null
        && !$this->sessions->wasEstablishedOnADomainLink($session)
        && $this->sessions->wasAuthenticatedApartFrom($session, $domainLinkIds);

    return $independent ? LinkConfirmationVerdict::INDEPENDENT : LinkConfirmationVerdict::DEPENDENT;
}
```

Bind it in a service provider's `register()`, scoped, since the session store it is given records the request's
session:

<!-- snippet: tests/Integration/Examples/Links/AppServiceProvider.php#links-confirmation-binding -->
```php
$this->app->scoped(LinkConfirmation::class, PasswordSessionsConfirm::class);
```

> [!IMPORTANT]
> Freshness that came from an SSO sign-in does not count here, even when your `Freshness` binding answers `fresh` for
> it. Someone whose only credential is the identity provider therefore cannot confirm the link until they hold another.
> Removal is not the only way out: application-controlled recovery, or a credential established independently of the
> provider, qualifies. Removing the link does not turn its surviving session into independent authentication, so your
> credential enrolment and recovery must preserve that distinction: enrolling a credential from a session the link
> established proves nothing the provider could not do.

## Deciding who may link

`Contracts\LinkEligibility` decides whether an identity may link through a connection, for example only as a member of
the connection's tenant. Its default, `RefusingLinkEligibility`, refuses everyone. Here `MembersMayLink` lets a member
of the connection's tenant link, reading your own `Membership` model on the package's storage connection
(`Database\StorageConnection::name()`, `null` for your default connection), where its table lives:

<!-- snippet: tests/Integration/Examples/Links/MembersMayLink.php#links-eligibility -->
```php
/**
 * Whether the identity is a member of the connection's tenant.
 *
 * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
 * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
 * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
 */
#[\Override]
public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
{
    // Read on the package's storage connection, so this lock holds until
    // the redemption commits
    $member = Membership::on(StorageConnection::name())
        ->useWritePdo()
        ->where('identity_type', $identity->type)
        ->where('identity_id', $identity->id)
        ->where('tenant_id', $connection->getTenantId())
        ->lockForUpdate()
        ->first();

    return $member !== null ? LinkEligibilityVerdict::ELIGIBLE : LinkEligibilityVerdict::INELIGIBLE;
}
```

Bind it in a service provider's `register()`:

<!-- snippet: tests/Integration/Examples/Links/AppServiceProvider.php#links-eligibility-binding -->
```php
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

<!-- snippet: tests/Integration/Examples/Links/LinksExampleTest.php#links-list-remove -->
```php
$links  = app(LinkService::class);
$caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId());

$mine = $links->list('me', $caller);                            // list<LinkSummary>, oldest first
$some = $links->list(new IdentityReference(User::class, '42')); // another identity's, for administrators

$result = $links->remove('me', $linkId, $client, $caller); // freshness judges the caller, who is named as acting
```

The identity is an `IdentityReference`, or `'me'` for the identity of the caller you pass, an `Identities\Caller` of the
signed-in user and the session they are on. `'me'` without a caller, or any other string, throws an
`InvalidArgumentException`. A removal's caller is also the one the freshness contract judges and the one `LinkRemoved`
names as acting, whether they remove their own link or, as an administrator, another identity's named by its
reference.

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
link, with `RevocationScope::identityInConnection()`: the identity's sessions established through that link, with the
reason `link_removed`. The scope names the connection (`$scope->connectionId`) and the removed link (`$scope->linkId`):
revoke by the link when your sessions record it, or every session of the identity through the connection when they do
not, which is broader and never narrower. If your binding throws, the link is not removed, nothing is reported, and
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
protocol, the identity, and the identity of the caller you passed as the acting identity; a link made or confirmed by a
flow also names the application, the purpose and the request's public reference. None carries the subject or an email
address. A refused creation or removal reports nothing of its own, and a refused `link` reports one `FlowFailed`, whose
context names the identity the flow was started for, never the identity holding the subject.
