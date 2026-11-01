# Discovery

## Purpose

This note records how a flow starts from an email address instead of a named connection (SSO-3.4, SSO-3.5): how the
email's domain is resolved to a connection, the fixed order of a discovery start and the refusal each step answers, the
per-domain rate limit (SSO-11.8), why a match and a miss answer in the same shape, status and time, and what the answer
still discloses. Starting through a named connection, the request stored and the fallback a named start shares with
discovery are in `authorization-requests.md`; domain claims and the predicates they are judged by are in `domains.md`
and `domain-rechecks.md`.

## Invariants

### Routing an email

- `Discovery\DomainRouter` (`@internal`) answers `connectionFor($email)`: the usable `Models\Connection` the email's
  domain routes to, or `null`. It never looks up a user, and reads nothing but the domains and the connections, both on
  the write connection (SSO-11.3).
- The domain is the part after the last `@` (`DomainRouter::domainOf()`), normalised by
  `Domains\DomainName::normalize()` (trimmed, one trailing dot removed, IDNA UTS #46 to lower-case ASCII). An email
  with no `@`, an empty domain, and a domain `normalize()` refuses (a single label, an IP address, a wildcard, a
  special-use name) are `null`, never an exception, and read nothing.
- The domain's claims, of every tenant, are read by `Domains\DomainFinder::claimsOf($domain)`, without a lock: nothing
  is written on the strength of them. The routing claim is the one `DomainClaims::routing($now)` picks: the claim for
  which `Domains\DomainStanding::routes()` holds at the clock's now, verified and `lapses_at` unset or after now, so a
  domain whose record went keeps routing through its grace period, with linking suspended, and stops at its end even
  before a recheck marks it lapsed. The unique index on `verified_domain` holds at most one verified claim across every
  tenant, so at most one claim routes a domain. A pending or lapsed claim never routes, whatever its `verified_domain`.
  Claims are exact: a subdomain of a verified domain does not route.
- The connection is read by its id on the write connection and must be usable (`ProtocolManager::isUsable()`: enabled,
  its protocol switched on, its settings complete). A deleted, disabled or incomplete connection is `null`.
- Both sides of the comparison are normalised lower-case ASCII, so no column collation can fold one name into another.
- Every `null` is the same `null`: an unknown domain, a pending, lapsed or past-grace claim and an unusable connection
  cannot be told apart by the caller.

### Starting a flow by email

- `Discovery\DiscoveryService::start($application, $purpose, $email, $codeChallenge, $identity, $sessionId)` (`@api`)
  answers a `Flows\StartResult`. Called inside a transaction open on the storage connection, it is a `LogicException`
  before anything else (`StorageConnection::assertNoTransaction()`), as a named start is: a match calls the driver,
  which may reach the identity provider while the caller's transaction kept the connection's lock (SSO-11.5). Its
  steps run in this order, and each refusal reports exactly one `FlowFailed(Flow::AUTHORIZATION_REQUEST, reason)` and
  writes no request:
  1. the purpose's binding, by the named start's own check (`AuthorizationRequestService::assertBinding()`: `sign_in`
     with no identity and no session, `link` for an identity with no session, `reauthenticate` for an identity on a
     session of 1 to 255 bytes): anything else is an `InvalidArgumentException` with the named start's message, before
     anything is counted, read or reported;
  2. the attempt, counted with `AttemptSubject::authorizationRequest($ip, $domain)`: the IP address of the request
     being served (none when no request is bound) and the email's normalised domain (none when it does not normalise),
     never the email; a full counter is `rate_limited` with its wait;
  3. `Applications\ApplicationGate::admit()`: `application_not_allowed` for an unknown application and for one the
     policy does not allow, alike;
  4. the application must offer discovery (`discoveryEnabled`) while the `discovery` feature is on, else
     `feature_disabled`;
  5. the client's challenge, when given, must have an S256 challenge's form, else `challenge_invalid`;
  6. `DomainRouter::connectionFor()`. A match calls `AuthorizationRequestService::begin()`, which checks the purpose
     (`freshness_required` for a stale `link`, `session_ineligible` for a `reauthenticate` not signed in), asks the
     driver to start, stores the request under the connection's lock and reports `AuthorizationRequestStarted`; its
     refusals are answered as they are (a connection changed while the driver started leads to the fallback, reported
     as `connection_unavailable`). A miss reports `FlowFailed(discovery_no_match)` with the application and the
     purpose (and the identity and session a `link` or `reauthenticate` gave), never the email, its domain or a
     connection, and answers `AuthorizationRequestService::fallback($application, $challengeGiven)`.
- A match and a miss answer the same status (`started`), the same body keys (`reference`, `navigation`, and `verifier`
  exactly when no challenge was given), a reference of the same form (32 base64url characters), a `redirect`
  navigation and the same headers (`Cache-Control: no-store`). Only the URL differs: the identity provider's for a
  match, the application's `discovery.fallback_url` for a miss. A miss's reference names no request and its verifier
  redeems nothing.
- `Discovery\Pacer` (`final`, `@internal`) holds every answer from step 2 on, refusals included, until
  `FlowSettings::discoveryMinimumDurationMilliseconds()` (50 to 2000, default 250) has passed since it started. It
  measures on the monotonic clock (`hrtime(true)`), not the package's `Contracts\Clock`, which a test may freeze, and
  waits with `usleep()` again until the floor is reached; what remains is rounded up to whole microseconds and is never
  negative, so an answer already slower than the floor is not delayed further. `start()` reads the floor before any
  work, so a malformed floor is an `InvalidArgumentException` naming its key before anything is counted; `[flows]`
  refuses it at boot. An exception is not held.
- The floor must exceed the slowest match, a driver's start included; within it, a match's extra work (the connection's
  read, the driver's start, the stored request) is invisible in the answer's time.
- The email and its domain appear in no event and no log. The public reference is the only flow identifier an event
  carries (SSO-9.8); no event carries the protocol state, the nonce, a verifier or a challenge.
- What the answer still discloses: where the navigation leads shows whether a domain routes to an identity provider, as
  any discovery does (SSO-3.5). It never shows whether a person has an account, since no user is read. The guide says
  so.
- An application that offers discovery while the feature is on needs `discovery.fallback_url`: `[applications]`
  refuses its absence at boot (SSO-12.3), and a start for such an application fails closed with the same message.

## Success Path

1. The application calls `start('web', Purpose::SIGN_IN, 'jane@example.com')` from its discovery route; the attempt is
   counted against the IP address and `example.com`, `web` is admitted and offers discovery.
2. `example.com` is verified for a usable connection: the flow starts through it, the request is stored under the
   connection's lock, and `AuthorizationRequestStarted` is reported once that commits.
3. The pacer holds the answer until the floor has passed; the answer is `started` with `{reference, navigation,
   verifier}` and `Cache-Control: no-store`, the navigation leading to the identity provider.

## Failure / Edge Cases

- A domain that routes nowhere answers `started`, leading to the fallback, after exactly one
  `FlowFailed(discovery_no_match)`, storing nothing, in the same time as a match.
- A refusal (rate limited, application not allowed, discovery not offered, a malformed challenge, a match's own
  refusal) answers its reason after the floor too; each reports exactly one `FlowFailed`.
- A misbound purpose is an `InvalidArgumentException`; nothing is counted, read, written or reported, and it is not
  held.
- An email that does not normalise is counted against the IP address alone and answered as a miss; the per-domain
  limit cannot be spread over spellings of one domain, since it counts the normalised form.
- A database error, a misconfiguration and a driver's exception propagate (SSO-11.4), unheld.

## Implementation Anchors

- `src/Discovery/DiscoveryService.php`, `src/Discovery/DomainRouter.php`, `src/Discovery/Pacer.php`.
- `src/Flows/AuthorizationRequestService.php` (`begin()`, `fallback()`, `assertBinding()`, `offersDiscovery()`,
  `isChallenge()`), `src/Flows/RequestEvents.php`, `src/Flows/FlowSettings.php`, `src/Flows/FlowsCheck.php`,
  `src/Domains/DomainFinder.php` (`claimsOf()`), `src/Domains/DomainClaims.php` (`routing()`),
  `src/Domains/DomainName.php`, `src/Domains/DomainStanding.php`, `src/RateLimiting/AttemptSubject.php`.

## Authoritative Tests

- `tests/Feature/Discovery/DomainRouterTest.php`, `tests/Feature/Discovery/DiscoveryServiceTest.php`,
  `tests/Feature/Discovery/DiscoveryEventSequenceTest.php`.
- `tests/Integration/Discovery/DiscoveryTimingTest.php`; `tests/Feature/Flows/FlowsCheckTest.php` for the floor's
  range, `tests/Feature/Config/Checks/ApplicationsCheckTest.php` for the required fallback.
- `tests/Performance/DiscoveryQueryBudgetTest.php`.

## Change Triggers

- A step added to, removed from or moved in a discovery start, or a change to what a step refuses with.
- A change to how a domain is taken from an email, normalised, or judged to route, or to what of a connection makes it
  usable.
- A change to what a match or a miss answers, to what the pacer holds, or to how it measures and waits.
- A change to what is counted against the per-domain limit, or to what an event's context names.
