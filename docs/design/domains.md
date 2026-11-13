# Domains

## Purpose

This note records how a tenant claims an email domain for one of its connections and proves it controls it with a DNS
TXT record (SSO-3.1, SSO-3.2): what a claim holds, how a domain is normalised and which are refused, the resolver
contract and its three outcomes, the one verified connection per domain, how the helpers lock and in which order, and
the predicates every reader judges a domain by. The scheduled rechecks and lapses (SSO-3.3) are in `domain-rechecks.md`.

## Invariants

- A claim is a row of `Models\Domain` in `sso.domains.table` (`sso_domains`): its connection, its normalised `domain`,
  its `state` (`Domains\Enums\DomainState`: `pending`, `verified`, `lapsed`), the `record_name` it was claimed with and
  its `verification_token`, and the times `claimed_at`, `pending_expires_at`, `verified_at`,
  `last_successful_check_at`, `linking_suspended_at`, `lapses_at` and `lapsed_at`, with the recheck's
  `recheck_leased_until`. Its connection and domain are fixed once it exists (`LogicException`). The token is hidden
  from serialisation.
- `verified_domain` holds the domain while the claim is verified, and `null` otherwise, under a unique index, so a
  domain is verified for at most one connection at a time across every tenant, whatever the race. Several connections,
  of any tenants, may hold a pending or lapsed claim of the same domain; one connection holds at most one claim of a
  domain (unique `connection_id`, `domain`).
- A domain is normalised by `Domains\DomainName::normalize()`: trimmed, one trailing dot removed, converted by IDNA (UTS
  #46, non-transitional, STD3 rules, bidirectional and contextual checks; the `intl` extension or
  `symfony/polyfill-intl-idn`) to lower-case ASCII. Only a host name that could be registered is accepted: at least two
  labels, each 1 to 63 letters, digits and hyphens with no hyphen at either end, 253 characters at most, a top-level
  label of letters or an IDNA label, and not under a special-use top-level domain (`localhost`, `local`, `test`,
  `invalid`, `example`, `internal`, `arpa`, `onion`, `alt`). An IP address, a wildcard, an underscore, a URL, an
  email address and a single label are refused. Whether a name is a public suffix is not judged: no tenant but its
  registry could publish the record that verifies it.
- Claims are exact: a verified domain covers none of its subdomains, each claimed on its own.
- A domain is refused when it is one of `Domains\DomainSettings::refused()` or under one: the public mailbox providers
  of `DomainSettings::PUBLIC_MAILBOX_PROVIDERS`, always, and those configured in `sso.domains.refused`, which adds and
  never removes. A domain whose record name (`record_name` + `.` + domain) would pass 253 characters is `too_long`.
- The token is 32 bytes from `random_bytes()` (the system CSPRNG), in lower-case hex (`DomainService::TOKEN_BYTES`). The
  TXT record is looked up at the claim's own `record_name` under the domain (`_sso-verification.example.com` by
  default; `sso.domains.record_name` sets it for new claims only). A domain is verified only when one TXT record there
  is exactly the token, byte for byte, compared in constant time; a record that contains it, or differs in case or
  whitespace, is not it.
- `Contracts\DnsResolver::txt($name)` answers a `Domains\DnsLookup`: `found` with every record (each record's
  character-strings joined), `absent`, or `lookup_failed`. `lookup_failed` is never read as `absent` or as a record:
  a verification it answers is `domain_lookup_failed` and writes nothing. The records are attacker-supplied, so a
  lookup holds them in a `\SensitiveParameterValue` behind `records()`, shows them in no dump, encodes as its status
  alone, and refuses to be serialised.
- The default resolver, `Domains\SystemDnsResolver`, is the system resolver through `dns_get_record(DNS_TXT)`, with no
  timeout of its own. It looks the name up as absolute, with a trailing dot, so the resolver's search list and `ndots`
  never answer for another name (a TXT record under a search domain is never read as the claimed domain's); the contract
  requires every implementation to resolve the name as absolute. An answer with no TXT record (PHP's answer for a name
  that does not exist too) is `absent`; a `false` answer or one that warns is `lookup_failed`, logged through the
  sanitising logger with the name and PHP's warning, never a record; it keeps the first 64 records of at most 4096
  bytes. An application that needs a bounded deadline, DNSSEC or DNS over HTTPS binds its own. It is a scoped
  default. `Testing\FakeDnsResolver` is the public test double.
- `Domains\DomainService` (`@api`) is the management helper. Every change is scoped to a tenant through
  `Connections\ConnectionFinder` (another tenant's connection is `connection_not_found`) and goes in one order: find
  the connection, and the claim, on the write connection; validate; for a verification, ask freshness
  (`sso.domain.verify`) when no transaction is open, so a stale caller spends no check, then take one domain check of
  the connection (`AttemptSubject::domainCheck()`, `rate_limited` with `retryAfter`) and look the record up before the
  helper's transaction; then in one transaction on the storage connection, read the connection again locked, read again with
  locking reads what decides the write, ask freshness (`sso.domain.claim`, `sso.domain.verify`, `sso.domain.remove`),
  write, and report through `Administration\DomainEvents`.
- Lock order: the connection's row, then every claim of the one domain (`DomainFinder::claimsOf($domain, true)`, by the
  `domain` index, in id order), or the connection's own claim by (`connection_id`, `domain`). Nothing takes a locking
  read by `verified_domain`, whose MySQL gap locks would deadlock with a verification's update; the unique index on it
  is the last guard, and a verification it refuses (caught in a savepoint) is `domain_unavailable`. A deadlock MySQL's
  gap locks can still cause between claims of neighbouring domains is retried up to three times when the helper's
  transaction is the outermost; inside the application's, it propagates. Everything else that locks domains (the
  recheck, linking, a connection's deletion) keeps this order.
- Discovery reads `DomainFinder::claimsOf($domain)` without a lock, since it writes nothing on the strength of it, and
  routes by the claim `DomainClaims::routing($now)` picks ([discovery.md](discovery.md)).
- Every outcome is a `Domains\DomainResult` (status `Domains\Enums\DomainStatus`): `claimed`, `verified`, `unchanged`
  or `removed` with a `Domains\DomainSummary`; `refused` with `freshness_required`, `connection_not_found`,
  `domain_not_found`, `domain_unavailable`, `domain_claim_expired`, `domain_record_not_found`, `domain_lookup_failed`
  or `rate_limited` (with `retryAfter`); `invalid` (`settings_invalid`) with one `domain` violation: `required`,
  `invalid_format`, `too_long`, `not_allowed` or `duplicate`. `domain_unavailable` never names, or hints at, the
  connection or tenant that holds the domain, and is the same whether that is another tenant or the same one.
- `DomainSummary` reads the token only through `verificationToken()`: held in a `\SensitiveParameterValue`, redacted
  from dumps, left out of `jsonSerialize()`, and the summary refuses to be serialised.
- `Domains\DomainStanding` holds the predicates every reader uses: `isPendingExpired()` (pending, at or past its
  expiry), `routes()` (verified and before `lapses_at`, even before a recheck marks it lapsed: discovery and SSO-8.1),
  `allowsLinking()` (routes, not suspended, last successful check no later than now and within the maximum age,
  capped at 86400 seconds: SSO-8.8) and `lookupName()`.
- `Domains\DomainWithdrawal::linkingWithdrawn()` is the seam called, under the connection's and the domain's locks and
  before the write, whenever a domain stops allowing linking: a removal here, a suspension or a lapse in the recheck.
  It deletes the domain's open link reservations (`Links\ReservationWithdrawal`, `linking.md`).
- `[domains]` (`Domains\DomainsCheck`) checks `record_name`, `refused`, `pending_expiry_seconds` (3600 to 2592000,
  default 604800), `recheck_grace_seconds` (0 to 2592000, default 259200) and `linking_max_age_seconds` (60 to 86400,
  default 86400) while the package is in use, each as `DomainSettings` reads it.

## Success Path

1. The administrator claims `example.com` for the tenant's connection: `claim()` answers `claimed` with the record
   name `_sso-verification.example.com` and the token, and reports `DomainClaimed`.
2. The administrator publishes a TXT record with the token at that name.
3. `verify()` looks it up, finds the token, and marks the domain verified from now (`verified_at` and
   `last_successful_check_at`), clearing the expiry; it reports `DomainVerified`.
4. Discovery and linking read the claim through `DomainStanding`; the recheck keeps it verified.

## Failure / Edge Cases

- A claim expired before it was verified is `domain_claim_expired` on `verify()`; claiming it again reuses the row
  with a new token, claim time and expiry, and reports `DomainClaimed` again.
- A verified domain is `unchanged` on `verify()`, once freshness was asked, with nothing looked up or written.
- A lapsed domain is verified again by `verify()`, and counts from its new verification time.
- A domain verified for another connection between the lookup and the write, a claim removed meanwhile, and a claim
  claimed again with another token meanwhile are each refused in the transaction (`domain_unavailable`,
  `domain_not_found`, `domain_record_not_found`). So is a claim that lapsed after it was read for the lookup (verified
  and lapsed again meanwhile, or lapsed again since): a recheck found no record after the lookup began, and the older
  answer never overrules it (`domain_record_not_found`).
- A claim's check that the domain is verified elsewhere locks every claim of the domain, so a verification that races
  it is serialised with it.
- A removal deletes a claim in any state; a verified domain removed frees it for another connection.
- A database error, a resolver or a limiter that throws propagates (SSO-11.4); an empty tenant id is an
  `InvalidArgumentException`; a malformed setting fails closed naming its key.

## Implementation Anchors

- `src/Domains/DomainService.php`, `DomainFinder.php`, `DomainClaims.php`, `DomainName.php`, `DomainStanding.php`,
  `DomainResult.php`, `DomainSummary.php`, `DomainSettings.php`, `DomainsCheck.php`, `DomainWithdrawal.php`,
  `DnsLookup.php`, `SystemDnsResolver.php`, `Enums/`.
- `src/Contracts/DnsResolver.php`, `src/Testing/FakeDnsResolver.php`, `src/Models/Domain.php`,
  `database/migrations/2026_11_02_000000_create_sso_domains_table.php`.
- `src/Administration/DomainEvents.php`; `src/Events/DomainClaimed.php`, `DomainVerified.php`, `DomainRemoved.php`.

## Authoritative Tests

- `tests/Feature/Domains/DomainClaimTest.php`, `tests/Feature/Domains/DomainVerificationTest.php`,
  `tests/Feature/Domains/DomainSummaryTest.php`, `tests/Feature/Domains/DomainsCheckTest.php`,
  `tests/Feature/Models/DomainTest.php`.
- `tests/Unit/Domains/DomainNameTest.php`, `DnsLookupTest.php`, `SystemDnsResolverTest.php`, `DomainResultTest.php`,
  `Enums/DomainEnumsTest.php`; `tests/Unit/Testing/FakeDnsResolverTest.php`.
- `tests/Integration/Domains/DomainsMigrationTest.php`, `ConcurrentDomainClaimsTest.php` (MySQL and PostgreSQL),
  `DomainEventsAfterCommitTest.php`; `tests/Performance/DomainServiceQueryBudgetTest.php`.

## Change Triggers

- A change to normalisation, to what is refused, to the token, the record name or the exact match.
- A change to the resolver contract, its outcomes, or the default resolver.
- A change to the lock order, to the uniqueness of a verified domain, or to an outcome of a domain helper.
- A change to `DomainStanding`'s predicates, or to where `DomainWithdrawal` is called.
