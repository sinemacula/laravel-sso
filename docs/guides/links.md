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
reserved link, held for linking by a verified domain, resolves nothing.

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

The limit is asked while the connection is locked, and counts the identity's active links and its reserved ones that
have not expired. An answer below one is a misconfiguration and throws a `LogicException`. An identity may hold links
through the connections of several tenants; each link stands alone.

Links are made by the flows: a redeemed `link` flow, provisioning, or a verified domain. A creation that is refused
answers `subject_already_linked` (the subject is linked already, to this identity or another; the answer never says
which) or `link_limit_reached`, with nothing written.

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
`NameID` format, its state (`active` or `reserved`), whether a verified domain made it, and when it was created and
last used. It never holds the subject. `json_encode()` gives it with snake_case keys.

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

| Event         | When                                                                                                |
|---------------|-----------------------------------------------------------------------------------------------------|
| `LinkCreated` | A link was made; `origin` says how (`link_purpose`, `provisioning`, `verified_domain`, `migration`) |
| `LinkRemoved` | A link was removed and the identity's sessions through the connection revoked                       |

Both are dispatched after the transaction commits, never when it rolls back, and name the connection, its tenant and
protocol, the identity, and the acting identity you passed; a link made by a flow also names the application, the
purpose and the request's public reference. Neither carries the subject. A refused creation or removal reports nothing.
