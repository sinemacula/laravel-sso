# Domains

A tenant proves it controls an email domain by publishing a DNS TXT record, and the domain is then verified for one of
its connections. Only a verified domain routes discovery, marks an email as belonging to its connection, or allows
linking by email. Your administration screens claim, verify and remove domains through
`SineMacula\Laravel\Sso\Domains\DomainService`; who may do so is your application's authorisation, so check it before
you call the service.

```php
use SineMacula\Laravel\Sso\Domains\DomainService;

$domains = app(DomainService::class);
```

> [!IMPORTANT]
> Claiming, verifying and removing a domain each ask the freshness contract (`sso.domain.claim`, `sso.domain.verify`,
> `sso.domain.remove`), and the default contract refuses every operation. Bind your own first (see
> [Freshness](freshness.md)).

## Claiming a domain

```php
use SineMacula\Laravel\Sso\Administration\ActingIdentity;

$result = $domains->claim($tenant->id, $connectionId, 'Example.COM', new ActingIdentity($user->getMorphClass(), (string) $user->getKey()));

if ($result->isSucceeded()) {
    $record = $result->domain->recordName;          // _sso-verification.example.com
    $value  = $result->domain->verificationToken(); // 64 lower-case hex characters
}
```

Show the administrator the record name and the token: they publish a TXT record at that name whose value is exactly the
token. The domain is stored normalised (lower case, IDNA ASCII, no trailing dot), so `Bücher.Example.COM.` is
`xn--bcher-kva.example.com`. A claim is exact: claiming `example.com` covers none of its subdomains, which are claimed on
their own.

A claim is refused, with nothing written, when:

| Result                                   | Why                                                                                                                                                            |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `invalid`, violation `required`          | No domain was given                                                                                                                                            |
| `invalid`, violation `invalid_format`    | It is not a host name that could be registered: an IP address, a wildcard, a URL, an email address, a single label, a `.test` or `.internal` name and the like |
| `invalid`, violation `too_long`          | It, or its record name, is longer than a DNS name may be                                                                                                       |
| `invalid`, violation `not_allowed`       | It is a public mailbox provider or one you refuse (`sso.domains.refused`), or under one                                                                        |
| `invalid`, violation `duplicate`         | The connection already holds a live claim of it                                                                                                                |
| `refused`, reason `domain_unavailable`   | It is verified for another connection, of this tenant or any other; the answer never says whose                                                                |
| `refused`, reason `connection_not_found` | The tenant has no such connection                                                                                                                              |
| `refused`, reason `freshness_required`   | The caller did not authenticate recently enough                                                                                                                |

A pending claim expires after `sso.domains.pending_expiry_seconds` (a week by default). Claiming the domain again
afterwards gives it a new token.

## Verifying a domain

```php
$result = $domains->verify($tenant->id, $connectionId, 'example.com', $actor);
```

The package looks the TXT record up and verifies the domain only when one of the records at the name is exactly the
token. On success the result is `verified`, and the domain is verified for this connection from now. Otherwise:

| Reason                    | Meaning                                                                                      |
|---------------------------|----------------------------------------------------------------------------------------------|
| `domain_record_not_found` | No TXT record at the name is the token; check the record and try again                       |
| `domain_lookup_failed`    | The DNS lookup itself failed; nothing is concluded, so try again later                       |
| `domain_claim_expired`    | The claim expired; claim the domain again for a new token                                    |
| `domain_unavailable`      | The domain became verified for another connection first                                      |
| `rate_limited`            | The connection used up its domain checks (`sso.rate_limits.domain_check`); wait `retryAfter` |
| `domain_not_found`        | The connection holds no claim of the domain                                                  |

A domain that is already verified answers `unchanged` with nothing looked up. A lapsed domain can be verified again,
and counts from its new verification time.

## Removing and reading domains

```php
$domains->remove($tenant->id, $connectionId, 'example.com', $actor);  // in any state
$domains->get($tenant->id, $connectionId, 'example.com');             // ?DomainSummary
$domains->list($tenant->id, $connectionId);                           // ?list<DomainSummary>, oldest first
```

Removing a verified domain stops it routing discovery and allowing linking at once, and frees it for another
connection. `get()` answers `null`, and `list()` `null`, for a connection the tenant does not have.

A `DomainSummary` encodes to JSON without the token; read it with `verificationToken()` when you show the record to
publish. Never put it in a log.

## The DNS resolver

Lookups go through `SineMacula\Laravel\Sso\Contracts\DnsResolver`. The default asks the system resolver through
`dns_get_record()`, which has no timeout of its own: a slow resolver holds the request or the scheduled command as long
as the system allows. Bind your own for a bounded deadline, DNSSEC validation or DNS over HTTPS. The default queries the
fully qualified name (with a trailing dot), so a search domain in `resolv.conf` never answers for it; yours must resolve
the name as absolute too. It answers a
`DnsLookup`: `found` with the records, `absent`, or `lookupFailed()` when it cannot tell, and must never answer `absent`
when it could not look the name up.

```php
use SineMacula\Laravel\Sso\Contracts\DnsResolver;

$this->app->scoped(DnsResolver::class, MyDohResolver::class);
```

## Testing

`SineMacula\Laravel\Sso\Testing\FakeDnsResolver` answers each name with what your test gives it and fails loudly on a
name it has no answer for:

```php
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;

$this->app->instance(DnsResolver::class, $dns = new FakeDnsResolver);

$claimed = $domains->claim($tenantId, $connectionId, 'example.com');

$dns->publishes($claimed->domain);              // or ->absent($name), ->failing($name), ->found($name, ...$records)

$domains->verify($tenantId, $connectionId, 'example.com');

$dns->assertLookedUp('_sso-verification.example.com', 1);
```

## Configuration

| Key                               | Default             | Meaning                                                                 |
|-----------------------------------|---------------------|-------------------------------------------------------------------------|
| `domains.table`                   | `sso_domains`       | The table the claims are kept in                                        |
| `domains.record_name`             | `_sso-verification` | The TXT record's name under the domain, for new claims                  |
| `domains.refused`                 | `[]`                | Domains to refuse, added to the public mailbox providers always refused |
| `domains.pending_expiry_seconds`  | `604800`            | How long a claim waits to be verified, an hour to 30 days               |
| `domains.recheck_grace_seconds`   | `259200`            | How long a domain whose record has gone keeps routing discovery         |
| `domains.linking_max_age_seconds` | `86400`             | How recent a successful check must be to allow linking; at most a day   |

Keep the domains verified with the scheduled recheck: see [Domain rechecks](domain-rechecks.md).
