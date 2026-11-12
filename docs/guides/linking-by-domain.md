# Linking by a Verified Domain

When a tenant moves its existing members onto its identity provider, the first sign-in of each member resolves to no
identity. Linking by a verified domain joins such a result to the member's existing identity by email, without asking
them to sign in twice. It is the one way the package ever attaches a result to an identity by email, and it is hedged
accordingly: it is off by default, per connection, and every condition below must hold at completion and again at
redemption.

> A DNS check proves that someone controls a domain now. It does not prove that the domain's owner never changed. That
> is why the person's membership of the tenant must have been accepted before the domain's current verification: a
> tenant that claims a domain cannot add people and then capture them.

A signature does not establish who holds an address either. Turning this on for a SAML connection states that the
identity provider decides which subject holds each of the domain's addresses and that people cannot set their own. If
that is not true of your provider, leave this off and link through the `link` purpose instead.

## What must hold

| Condition          | What the package checks                                                                                                                                                                                     |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| The feature        | `sso.features.domain_linking` is on, and the connection's linking is on.                                                                                                                                    |
| The issuer         | It is explicitly classified. A shared issuer names its organisation claim and expected value, and the result carries exactly that value.                                                                    |
| The email's source | OIDC: `email` with `email_verified` as boolean `true`, both from the ID token or both from a UserInfo response whose `sub` matched. SAML: the one attribute named by exact `Name` and `NameFormat`.         |
| The domain         | The email's domain, compared as a claim is (lower case, IDNA to ASCII, no trailing dot), is this connection's verified claim, not suspended, last checked within `linking_max_age_seconds` (at most a day). |
| The email match    | Your `LinkEmailMatcher` finds exactly one identity whose email is verified and equal to the linking email.                                                                                                  |
| The principals     | Your `PrincipalScope` answers `within_tenant` on the identity's complete set of principals.                                                                                                                 |
| The membership     | Your `TenantMembership` answers a current membership the person accepted strictly before the domain's current verification.                                                                                 |
| What is held       | The identity holds no link, suspended link or live reservation in this connection, and the subject none.                                                                                                    |

A condition that fails at completion reserves nothing, and the result goes on as unlinked. One that fails at redemption
is `reservation_invalid`, the reservation is deleted and no link is left. Another match never becomes the target.

Discovery's grace period authorises nothing here. A domain whose record has gone keeps routing discovery for a while,
but stops allowing linking at once.

## Turning it on

In a service provider's `register()`, bind the package's link store, `Links\LinkStore`, as `Contracts\Linker`, and your
own `Contracts\LinkEmailMatcher`, `Contracts\PrincipalScope` and `Contracts\TenantMembership`, each of which refuses by
default. Here they are the application's classes reading its users and principals, under the guards
[each contract must provide](#the-concurrency-each-contract-must-provide):

<!-- snippet: tests/Integration/Examples/LinkingByDomain/AppServiceProvider.php#linking-by-domain-bindings -->
```php
$this->app->scoped(Linker::class, LinkStore::class);
$this->app->scoped(LinkEmailMatcher::class, UserEmailMatcher::class);
$this->app->scoped(PrincipalScope::class, UserPrincipalScope::class);
$this->app->scoped(TenantMembership::class, UserTenantMembership::class);
```

Your `Linker` must implement `Contracts\LinkStorage`, so that what linking writes is what it resolves: `LinkStore` does,
and a wrapper of yours may delegate every method to it. Any other is refused before anything is written, with a
`LogicException` naming the problem, and reported at boot while the feature is on. An alternative `HandoffIssuer` must
store the reservation's binding with its code and answer the stored expiry and an opaque reference; one that answers no
reference or a later expiry rolls the completion back.

Then turn the feature on and each connection's linking through `Connections\LinkingPolicyService`, with
`sso.connection.trust` freshness. Here an administrator classifies a shared issuer and gives the value their
organisation holds under its `hd` claim, and an invalid change becomes the application's validation errors:

<!-- snippet: tests/Integration/Examples/LinkingByDomain/LinkingSettings.php#linking-policy-change -->
```php
$result = app(LinkingPolicyService::class)->change($tenantId, $connectionId, [
    'enabled'            => true,
    'issuer_class'       => 'shared', // or single_organization, acknowledged
    'organization_claim' => 'hd',
    'organization_value' => $organization,
], $client, $caller);

if ($result->isInvalid()) {
    // Each violation names a setting and a code, never the value given
    $messages = [];

    foreach ($result->violations as $violation) {
        $messages[$violation->setting][] = $violation->code->value;
    }

    throw ValidationException::withMessages($messages);
}
```

`$client` is the `Http\ClientContext` of the request the call is made for, which your controller builds with
`ClientContext::fromRequest($request)`; work with no request (a console command, a queued job) passes
`new ClientContext(null, null)`. Every call that counts an attempt or reports an event takes one, never reading the
request itself, and each event it reports carries the client's IP address and user agent.

The result is a `ConnectionResult`: `updated`, naming each `linking.*` that changed; `unchanged`; `refused` with
`connection_not_found`, `freshness_required` or `protocol_unavailable`; or `invalid` with every violation. With no
`organization_value`, a shared issuer is `invalid`, with `required` at `organization_value`.

### Classifying the issuer

An issuer shared by many organisations, such as Google's, answers for every organisation that uses it, so a verified
email from it says nothing about this tenant without the provider's organisation claim. There is no default: an unset
classification reserves nothing, and an issuer absent from the package's list is never assumed to be one organisation's.

| Setting                             | Requires                                                        |
|-------------------------------------|-----------------------------------------------------------------|
| `issuer_class: shared`              | `organization_claim` and `organization_value`                   |
| `issuer_class: single_organization` | `acknowledged: true`, recorded with its time                    |
| A known shared issuer               | `shared`, under exactly its claim, with `organization_value`    |
| A SAML connection                   | `saml_attribute`, `saml_attribute_format`, `acknowledged: true` |

The package knows `https://accounts.google.com` and `accounts.google.com`, under `hd`, and `https://slack.com`, under
`https://slack.com/team_id`; each preset with an organisation claim (`google`, `microsoft_entra`,
`microsoft_entra_saml`) knows its own issuers; and `sso.linking.shared_issuers` adds yours. Configuration can add an
issuer but never change or remove a built-in one or one a preset names, whichever claim it gives. The value is compared
exactly: `Example.com` is not `example.com`.

Microsoft Entra's `common` and `organizations` are tenant-independent authorities, not issuers, and are not on the list:
the real issuer of a token they lead to names the tenant. Your connection's issuer is that real issuer, and explicit
classification applies to it; one the `microsoft_entra` preset recognises is `shared`, told apart by `tid`.

An acknowledgement stands for what it was given about. Changing the classification or the SAML attribute without giving
`acknowledged: true` again clears it. So does changing the issuer itself, the OIDC `issuer` or the SAML `idp_entity_id`,
through an update, an import or a migration: linking turns off, and the classification, the organisation and the
acknowledgement are cleared, since they were stated about another issuer. Classify the new one before you turn it on
again.

### SAML attributes

`saml_attribute` and `saml_attribute_format` are compared byte for byte. The attribute must be present once, with
exactly one non-empty string value, in that `NameFormat`; a second attribute of that `Name`, in any format, gives no
linking email, and an assertion with encrypted attributes gives none. There is no fallback to `FriendlyName` or an
email-format `NameID`. An attribute with no `NameFormat` is in
`urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified`, as SAML 2.0 says, so name that format for a provider that
sends none, such as Microsoft Entra ID. A shared issuer's organisation comes from the attribute named by
`organization_claim` under the same rule and the same format.

### What a change does

Each change raises the connection's `linking_version`, deletes its open reservations and reports `ConnectionUpdated`. It
is no protocol trust change: `trust_version` stays, flows in flight are not voided and `ConnectionDisabled` is not
reported. A response validated under the old settings reserves nothing, and a code bound to a deleted reservation is
`reservation_invalid`.

## Matching the email

Your matcher receives a `LinkEmailQuery`: the tenant, the email exactly as the protocol asserted it, and its domain
canonicalised. The package does not touch the local part. Pass the email through your application's normaliser: under
`laravel-iam`, the adapter passes it through `laravel-authentication`'s bindable identifier normaliser. Add no
subaddress or dot removal, Unicode folding or confusable matching: `a+b@example.com` and `a.b@example.com` are other
addresses. Only an email verified in your application counts; one merely present on an account does not.

## The flow

1. An eligible `sign_in` reserves a link in the completion's transaction, under the matched identity's guard, and its
   handoff is bound to the reservation. An email that moved to another identity between the first read and the lock is
   `reservation_invalid`, and the person signs in again. The two expire together, at the earlier of the request's expiry
   and the handoff lifetime from now.
2. A reservation resolves no sign-in. A second `sign_in` of that subject meanwhile is `link_reserved`, and so is a
   `link`.
3. Your redemption calls `HandoffRedemption::admit()` inside your transaction, on the package's storage connection, and
   writes the session in the same transaction. Every condition is checked again for that same identity, and the row
   becomes an active link with verified domain provenance. The standalone `redeem()` refuses every `sign_in` code with a
   `LogicException`.
4. `LinkCreated` and `LinkActivated` then `HandoffRedeemed` reach your listeners after the commit. Tell the person on
   your existing channels. `LinkActivated` carries the identity, the link, the application and the request's public
   reference, and never the email the provider supplied, which is not a notification destination.

The link only establishes who the person is. Your further-factor requirements apply as to any sign-in.

## When the person's scope widens

The link keeps its provenance, even across a [subject migration](managing-connections.md#migrating-subjects), which
revokes its sessions. Whenever the identity holds a principal outside the connection's tenant, the link resolves nothing
until the person [confirms it](links.md#confirming-it-is-the-person) through the `link` purpose, authenticated
independently of it, which clears the provenance for good. The suspension is stored and latched: removing the principal
later does not restore it. Your `PrincipalScope` answering `outside_tenant` latches it, and the resolution also revokes
the sessions established through the link. Answering `unknown` refuses that attempt alone, with
`principal_scope_unknown`: it creates no suspension and revokes nothing, and a link already suspended stays suspended. A
store you cannot reach for the moment should throw instead, which refuses nothing and suspends nothing.

Checks at completion and redemption cannot see a principal added and removed between them, so your principal mutation
has to report it, in its own transaction, on the package's storage connection. Call `Linking\ScopeWidening::widened()`
first, then take your own guard and write the principal:

<!-- snippet: tests/Integration/Examples/LinkingByDomain/GrantPrincipal.php#scope-widening -->
```php
DB::connection(StorageConnection::name())->transaction(function () use ($identity, $tenantId, $client): void {
    $widening = app(ScopeWidening::class);

    // First the identity's guard, held until this commits; the tenant
    // is `null` for a platform principal
    $widening->widened([$identity], $tenantId, $client);

    // Then your principal guard, then the write
    $this->lockPrincipals($identity);
    $this->addPrincipal($identity, $tenantId);
});
```

`widened()` takes the identity's guard, which every reservation, activation and confirmation of that identity takes
first, so none of them can slip past your change: each runs wholly before it and is found, or wholly after it and sees
your principal. It suspends the identity's domain links in every connection of another tenant, deletes its reservations
in them, and revokes the sessions established through those links through your `SessionRevocation`, with
`RevocationScope::identityLink()` and the reason `scope_widened`. It all commits or rolls back with the principal. Bind
`SessionRevocation` with an implementation writing through the same connection; the default revokes nothing. An adapter
whose sessions do not record their link revokes the identity's sessions through the connection instead.

`Exceptions\LinkCandidatesChanged` means your transaction's snapshot was older than a link or a reservation it found
under the lock, which on MySQL's `REPEATABLE READ` happens when your transaction read before it called `widened()` or
redeemed. Retry your whole transaction. The package's standalone `link` redemption reads nothing before it takes the
identity's guard, and restarts itself once if it comes to it. It tries its own transaction again, at most three times
in all, when the database rolls it back as a deadlock, a lock wait timeout or a serialisation failure. A change to
several identities' principals in one transaction, such as moving a subtree of tenants, passes them all to one
`widened()` call, which takes their guards in ascending order of `Linking\IdentityLock::digest()`, then locks the
connections holding any of their links together. Calling it once per identity would lock one identity's connections
before the next identity's guard, which can deadlock against a reservation or a confirmation. The call takes one tenant
and spares its connections for every identity given, so pass together only identities that gain a principal in that same
tenant.

This principal-change transaction is the primary place sessions are revoked. A resolution that finds a definite outside
scope repairs what it missed, revoking through the link in the completion's or the redemption's transaction; asking
twice for one link is safe.

Link suspension blocks new admissions and reauthentication. A suspended link can never be provisioned or reserved over.

## The concurrency each contract must provide

Package locks do not serialise your writers unless they take part. An answer read at completion is read again inside
your redeemer's transaction, and must stay true until that commits. The package's locks always come first, and your
guards after them, in every path, or your writers will deadlock against an admission: the identity's guard, enforcement
guard, connections in ascending id order, the domain claim, the request, the code, the links, then your guards. The
package asks each contract below only once its own locks are held. Its identity guard is taken only by what touches
linking: an ordinary linked sign-in never pays for it.

| Contract            | What it must guarantee through commit                                                                                                                                          |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `LinkEmailMatcher`  | A uniqueness guarantee on the verified email, or a guard every writer of a verified email takes. Locking the rows it returned is not enough: another identity can match later. |
| `PrincipalScope`    | The complete set of principals, `unknown` if it cannot read it all, under a guard every writer of principals takes after calling `ScopeWidening` first, as above.              |
| `TenantMembership`  | A guard every writer that revokes a membership takes. The acceptance time is the person's, never an administrator's creation time.                                             |
| `HandoffIssuer`     | The reservation's binding and the expiry written with the code, in the completion's transaction, on the same Laravel connection.                                               |
| `SessionRevocation` | Writes through the same Laravel connection, so a revocation commits or rolls back with the suspension.                                                                         |

Each reads from the write connection, keeps nothing of one call for the next, never logs the email, and lets an error
propagate: an answer it cannot vouch for refuses.

A retry is only ever of your whole transaction. A committed refusal spends the code; a rollback undoes the consumption
and the activation together.

## What withdraws a reservation

Each runs in the transaction of its change, deletes the reservation and leaves no tombstone: a handoff bound to a
deleted reservation activates nothing, and a later reservation of the subject has another identity.

- The domain's record gone or changed, at once, without the grace period; the domain removed; the domain lapsed.
- The connection disabled or deleted, and any protocol trust change, which also voids the handoff, so its redemption is
  `handoff_unknown`.
- A change to the connection's linking settings.
- The identity's scope widening.
- A refusal of its own handoff, once it is consumed.

A domain verified again counts from its new verification time and its new generation, so a reservation made before it
never activates, and a membership accepted since the new time no longer counts.
