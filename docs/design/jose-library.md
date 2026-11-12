# JOSE Library

## Purpose

This note records the comparison behind the choice of JOSE library: which library the package uses to verify OIDC ID
tokens against an issuer's JWKS (SSO-7.3, SSO-2.6) and to sign RFC 7523 `private_key_jwt` client assertions, and what
the package's JOSE adapter must add around it. The two candidates were run against the same hostile tokens and the same
time checks, in one process, on PHP 8.3, 8.4 and 8.5. The criteria were: algorithm pinned per key, `none` and HMAC
refused by construction, PS and ES verification and signing, and a clock and leeway given per call rather than held in
static state (SSO-11.2, SSO-11.13, Octane). Being used elsewhere in the suite did not count in either library's favour.
The package uses `web-token/jwt-library` `^4.2.4`, under the rules in the decision below.

## Method

- Candidates:
  - `web-token/jwt-library` 4.2.4, which pulled in `brick/math` 1.0.0, `spomky-labs/pki-framework` 1.6.3, `psr/clock`
    1.0.0 and `symfony/deprecation-contracts` 3.7.1;
  - `firebase/php-jwt` 7.2.1 with `phpseclib/phpseclib` 3.0.57, which pulled in `paragonie/constant_time_encoding`
    3.1.3 and `paragonie/random_compat` 9.99.100.
- Keys: RSA 2048 (two), RSA 1024 and EC P-256, made with OpenSSL. The issuer's JWKS held `k1` (RSA, no `alg`), `k2`
  (RSA, `alg` `RS256`) and `e1` (EC, `alg` `ES256`), each with `use` `sig`.
- The hostile tokens were built by hand (base64url, `openssl_sign`, `hash_hmac`), not by either library. PS256 tokens
  and client assertions were signed by each library and verified by the other, and ES256 assertions were also checked
  with plain OpenSSL (raw `R||S` converted to DER).
- web-token was run two ways. The first passed the whole key set to `JWSVerifier::verifyWithKeySet()`, as the library
  offers it. The second was adapter-style: the key chosen by an exact string match on `kid`, then `verifyWithKey()`.
  The verifier's `AlgorithmManager` held only the allow-list (`RS256`, `PS256`, `ES256`). firebase was run through
  `JWK::parseKeySet()` and `JWT::decode()`, which is the only way it verifies a token.
- Time: the token's `exp` was a fixed instant T. Four calls ran one after another in the same process, each with its
  own clock and leeway. Then two requests were interleaved with PHP fibres in one worker: request A was set up with
  60 s of leeway and suspended, request B ran with 0 s, and A resumed.
- PHP 8.3.32, 8.4.23 and 8.5.8, with `gmp`, `bcmath`, `sodium` and `openssl`. The results were the same on all three
  versions, and no notice or deprecation was raised.

## Results

"Refused" means the call threw or returned `false`. A row marked **risk** is behaviour the adapter has to close.

| Check                                                                                                                  | web-token/jwt-library 4.2.4                                                                                            | firebase/php-jwt 7.2.1 + phpseclib 3.0.57                                                                                                                               |
|------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| RS256 verification                                                                                                     | Verified                                                                                                               | Verified                                                                                                                                                                |
| PS256 verification, own and the other library's signature                                                              | Verified both                                                                                                          | Verified both (through phpseclib)                                                                                                                                       |
| ES256 verification, token signed with plain OpenSSL                                                                    | Verified                                                                                                               | Verified                                                                                                                                                                |
| `alg` `none` or `None`, empty signature                                                                                | Refused: not in the verifier's `AlgorithmManager`                                                                      | Refused: `Algorithm not supported`                                                                                                                                      |
| `none` if it were registered                                                                                           | **risk**: `None::verify()` accepts an empty signature against any key, an RSA key included. Never register it          | Not offered                                                                                                                                                             |
| HS256 signed with the RSA public PEM as the secret                                                                     | Refused: HS256 is not in the allow-list. Still refused with HS256 registered, because HMAC needs a `kty` `oct` key     | Refused when the key's algorithm comes from the JWKS or config (`Incorrect key for this algorithm`). **risk**: accepted when the `Key` is built with the header's `alg` |
| RSA JWK whose `alg` says HS256                                                                                         | Not reached (HS256 not allowed)                                                                                        | Refused: `key must be a string when using hmac`                                                                                                                         |
| `kty` `oct` key planted in the JWKS, HS256 token                                                                       | Refused by the allow-list (accepted only if HS256 is registered)                                                       | **risk**: accepted. `parseKeySet()` turns an `oct` JWK into an HMAC key, and `decode()` has no algorithm allow-list                                                     |
| `kid` with a path (`../../../../etc/passwd`), SQL-like (`k1' OR '1'='1`) or unknown, signed by `k1`                    | Refused by exact-match selection. **risk**: `verifyWithKeySet()` ignores `kid`, tries every key and accepted all three | Refused: `"kid" invalid`. The lookup is an array key, with no file or query behind it                                                                                   |
| `kid` `"0"` against a key with no `kid`                                                                                | **risk**: `JWKSet::has('0')` and `get('0')` reach the kid-less key by its position                                     | **risk**: accepted, since kid-less keys are indexed by position; an integer `0` is accepted too                                                                         |
| `kid` as an array                                                                                                      | Refused by the adapter's string check                                                                                  | Refused with a `TypeError`, outside the library's own exception types                                                                                                   |
| No `kid`                                                                                                               | **risk**: `verifyWithKeySet()` accepted                                                                                | Refused with a key array; a single `Key` ignores `kid` (an unknown `kid` was accepted)                                                                                  |
| JWK `alg` `RS256`, header `PS256`                                                                                      | Refused (`KeyChecker::checkKeyAlgorithm`)                                                                              | Refused (`Incorrect key for this algorithm`)                                                                                                                            |
| JWK without `alg`                                                                                                      | Any allowed algorithm that fits the `kty` (RS256 and PS256 both verified with `k1`)                                    | `parseKeySet()` throws for the whole set unless a default `alg` is given, and the default pins every key without an `alg` to that one algorithm                         |
| ES512 header, P-256 key, ES512 allowed                                                                                 | **risk**: accepted. The curve is not tied to the algorithm                                                             | ES512 not supported                                                                                                                                                     |
| RS256 with a 1024-bit key                                                                                              | **risk**: accepted                                                                                                     | Refused (2048-bit minimum)                                                                                                                                              |
| `crit` naming an unknown header                                                                                        | **risk**: `JWSVerifier` ignores it. `HeaderCheckerManager` refuses it                                                  | **risk**: ignored, token accepted                                                                                                                                       |
| `exp` equal to now, leeway 0 (RFC 7519 section 4.1.4: refuse)                                                          | **risk**: accepted (`now > exp + leeway`)                                                                              | Refused                                                                                                                                                                 |
| `exp` as a numeric string                                                                                              | Refused: `"exp" must be an integer.`                                                                                   | **risk**: accepted (`is_numeric`)                                                                                                                                       |
| `exp` missing                                                                                                          | Refused when `exp` is mandatory                                                                                        | **risk**: accepted (no claim is mandatory)                                                                                                                              |
| `iat` 120 s ahead, `nbf` present, leeway 60                                                                            | Refused                                                                                                                | **risk**: accepted (`iat` is checked only when there is no `nbf`)                                                                                                       |
| Clock and leeway per call                                                                                              | Each checker takes a PSR-20 `ClockInterface` and a leeway in its constructor (`final readonly`)                        | No parameter. Only the statics `JWT::$timestamp` (null means `time()`) and `JWT::$leeway`                                                                               |
| Four calls in a row: (clock, leeway) of (T-10, 0), (T+30, 60), (T+30, 0), (T-10, 0)                                    | Accepted, accepted, refused, accepted                                                                                  | The same, but only by setting the statics and restoring them in `finally` around each `decode()`                                                                        |
| A call that leaves leeway 300 behind, then a call expecting 0                                                          | Not applicable                                                                                                         | **risk**: the second call accepted a token that expired 120 s earlier                                                                                                   |
| Interleaved fibres, A with leeway 60 and B with 0                                                                      | A accepted, B refused: isolated                                                                                        | **risk**: B's restore wiped A's settings. A was refused, having seen leeway 0 and `timestamp` null                                                                      |
| Frozen clock (2020) without setting the statics                                                                        | Not applicable (the clock is injected)                                                                                 | **risk**: `decode()` used `time()` and refused a token that was valid at the injected clock. The library's own time checks cannot be switched off                       |
| RFC 7523 PS256 and ES256 assertion signing (`iss` = `sub` = client id, `aud`, `jti`, `iat`, `exp`, `kid`, `typ` `JWT`) | Signed from a private JWK. firebase/phpseclib verified the PS256 one and OpenSSL the ES256 one                         | Signed from a PEM. web-token verified both, and phpseclib and OpenSSL each verified one                                                                                 |
| PS384, PS512, ES512                                                                                                    | Supported                                                                                                              | Not supported (RS384, RS512 and ES384 are the only stronger ones)                                                                                                       |
| Cost per operation (PHP 8.3, GMP): PS256 verify, RS256 verify, PS256 sign                                              | 0.06, 0.21, 0.58 ms                                                                                                    | 0.56, 0.03, 0.93 ms                                                                                                                                                     |
| PHP 8.3.32, 8.4.23, 8.5.8                                                                                              | Same results, no deprecations                                                                                          | Same results, no deprecations                                                                                                                                           |

## Findings: web-token/jwt-library 4.x

- Algorithms are an allow-list per instance. The `AlgorithmManager` given to `JWSVerifier` is the complete set the
  verifier will run, and the verifier reads `alg` only from the protected header. Built per call from the connection's
  allow-list, it refuses `none` and every HMAC algorithm because they are not in it. HMAC is also refused a second time
  because it needs an `oct` key. `None` must never be registered, since its `verify()` does not look at the key.
- Per-key pinning depends on the JWK. When a JWK carries `alg`, `KeyChecker` refuses any other header algorithm. When it
  does not, the key can be used with every allowed algorithm that fits its `kty`. Both are acceptable under SSO-7.3 (the
  allow-list is the connection's), but a key is pinned only when the issuer publishes `alg`, or when the adapter pins it
  on import.
- `kid` is not used for key selection. `verifyWithKeySet()` tries every key in the set and returns the first that
  verifies. A forged `kid` cannot pass an unsigned token this way, because the signature still has to verify under one
  of the issuer's keys. It does break SSO-7.3's "the key is chosen by `kid`", and the unknown-`kid` refetch depends on
  knowing that a `kid` is unknown. `JWKSet::has()` and `get()` also turn the string `"0"` into a position. The adapter
  therefore selects the key itself, by exact string equality on each key's own `kid`, and calls `verifyWithKey()`.
- The adapter must add the checks the library leaves out: a minimum RSA modulus (1024-bit keys verify), a curve that
  matches the algorithm (a P-256 key verified an ES512 header), and refusing `crit`. `JWSVerifier` ignores `crit`;
  `HeaderCheckerManager` enforces it.
- Time can be injected and holds no state. `ExpirationTimeChecker`, `IssuedAtChecker` and `NotBeforeChecker` are
  `final readonly`, and each takes a PSR-20 clock and a leeway when it is built. The package's `Contracts\Clock` already
  extends `Psr\Clock\ClockInterface`, so it can be passed straight in. Consecutive calls and interleaved fibres each
  kept their own clock and leeway. The library declares no static properties.
- The `exp` boundary is off by one. The library accepts a token at `now == exp + leeway`, where RFC 7519 requires
  refusing it on or after `exp`. Claim types are strict (`int` or `float` only), and claims can be made mandatory.
  SSO-7.4 needs checks the library does not have anyway (`iat` maximum age, `auth_time` against `max_age`, `azp`,
  trusted audiences, `nonce`), so the package makes every time and claim check itself against `Contracts\Clock` and
  `ClockSkew`. That fixes the boundary in one place.
- Signing: `JWSBuilder` signed PS256 and ES256 client assertions from private JWKs, with the header the package chooses
  (`alg`, `kid`, `typ`). The other library and plain OpenSSL both verified them. `JWKFactory` can also build a JWK from
  a PEM.
- PHP, dependencies and maintenance: it requires `php >=8.2`, `brick/math` (`^0.12` to `^1.0`; the package's lock
  already has 1.0.0 through `ramsey/uuid`), `psr/clock` (already required), `symfony/deprecation-contracts` (already in
  Laravel's dependency tree) and `spomky-labs/pki-framework` (the one new package). `ext-openssl` is suggested, and the
  package already requires it. Upstream CI runs PHP 8.2 to 8.5, with 8.5 marked experimental. The library is a read-only
  split of `web-token/jwt-framework`: 4.2.4, 4.1.10, 4.0.8 and 3.4.12 were all released on 2026-10-30 (the 4.2.4 fix is
  in the Symfony bundle, not the library), with 4 open issues and the last push on 2026-10-31. One maintainer does
  nearly all the work, which is the main maintenance risk.

## Findings: firebase/php-jwt 7.x

- Algorithm pinning per key is its strength. A `Key` binds its material to one algorithm, and `decode()` refuses a
  header `alg` that differs from it. `none` is not offered, and RSA keys under 2048 bits are refused (a 7.0 security
  fix). The `exp` boundary is correct.
- No allow-list, and the JWKS decides HMAC. `decode()` takes no list of allowed algorithms. `parseKeySet()` turns a
  `kty` `oct` JWK into an HMAC key, so an `oct` key in a fetched JWKS let an HS256 token verify. Building a `Key` with
  the header's `alg` reopens the public-key-as-HMAC-secret attack. `JWT::$supported_algs` is a public, mutable static.
  The adapter would have to filter `kty` and `alg` before every `Key` it builds.
- JWKS without `alg`: one JWK without an `alg` makes `parseKeySet()` throw for the whole set, and some identity
  providers publish keys without one. The `defaultAlg` workaround pins every such key to a single algorithm, so with an
  allow-list of more than one RSA algorithm the adapter would have to build a `Key` per token.
- Time is static and cannot be switched off. `decode()` always checks `exp`, `nbf` and `iat`, against `JWT::$timestamp`,
  or `time()` when that is null, with `JWT::$leeway`. There is no per-call parameter. The package's clock can be
  honoured only by setting both statics before each `decode()` and restoring them in `finally`. That worked for calls
  made one after another. It is still process-wide state, which SSO-11.2 forbids ("no ... state in singletons or
  statics"). The comparison showed both ways it fails: a value left behind made the next call accept a token that had
  expired 120 s earlier, and an interleaved fibre lost its settings to the other request's restore. Octane serves one
  request per worker at a time today, so a synchronous set-decode-restore does not interleave. The window is still
  shared with any other code in the application that uses this library and sets `JWT::$leeway` for its own reasons, and
  with anything that could suspend inside it. Leaving the statics alone instead adds a second time check on `time()`
  that the package does not control, which breaks SSO-11.13's frozen clock.
- Claim typing is loose, and `crit` is ignored. Numeric strings pass as `exp`, `iat` and `nbf`. `exp` is not required.
  `iat` is skipped when `nbf` is present. `crit` is ignored. The package would check claims itself in any case
  (SSO-7.4).
- Algorithm breadth: there is no PS384, PS512 or ES512. PS256 needs `phpseclib/phpseclib` 3 (the code refers to the
  `phpseclib3` namespace, and phpseclib 4.x, already released, uses `phpseclib4`). It runs in PHP rather than OpenSSL,
  so PS256 verification costs about ten times as much as RS256. That is still under a millisecond.
- `kid` handling: an exact array-key lookup refused paths, SQL-like strings and unknown ids. Keys without a `kid` are
  indexed by position, so a header `kid` of `"0"` or `0` selected one. An array `kid` throws a `TypeError`.
  `CachedKeySet` fetches the JWKS over HTTP from inside the key lookup, outside the package's fetcher (SSO-2.9), so it
  would not be used.
- Signing: `JWT::encode()` signed PS256 and ES256 assertions from PEMs, and they verified everywhere. It always adds
  `typ` `JWT`.
- PHP, dependencies and maintenance: it requires `php ^8.0` and nothing at runtime. With phpseclib 3 it adds phpseclib
  and two `paragonie` packages. The repository is `googleapis/php-jwt`: v7.2.1 came out on 2026-09-28, with regular
  releases through 2026, 5 open issues and wide use. The repository publishes no CI workflow, so the PHP versions it is
  tested on are not visible. phpseclib 3.0.57 came out on 2026-08-26 and is maintained alongside 4.x, with 115 open
  issues.

## Decision

The package uses `web-token/jwt-library`, constrained to `^4.2.4` (the release tested here), behind the package's JOSE
adapter. The deciding question was whether `firebase/php-jwt`'s static leeway could be isolated per request. It
cannot: the only per-call isolation is to set and restore process-wide statics around each `decode()`, which SSO-11.2
rules out. The library's own time checks would otherwise run on `time()`, which breaks SSO-11.13. firebase also lacks
PS384, PS512 and ES512, has no algorithm allow-list, and turns an `oct` key in a fetched JWKS into an HMAC key. Its
real strengths (a `Key` pinned to one algorithm, a 2048-bit RSA minimum, the correct `exp` boundary) are easy to
build into the adapter. firebase's static clock is not something an adapter can remove.

The adapter, not the library, carries these rules:

- Algorithms: a `JWSVerifier` is built per call, with an `AlgorithmManager` holding only the connection's allow-list of
  asymmetric algorithms (RS, PS and ES at 256 bits and above). `None` and HS* are never registered, whatever the
  configuration says, and the configuration check refuses them.
- Key selection: a `kid`, when present, must be a non-empty string, and the key is the one stored JWK whose own `kid` is
  identical to it. An unknown `kid` follows SSO-7.3's refetch-once path and is otherwise refused. `verifyWithKeySet()`,
  `JWKSet::get()` and `JWKSet::has()` are never used. A token with no `kid` is verified only when exactly one stored key
  is admissible for its algorithm (after `alg`, `kty` and curve, strength, `use` and `key_ops`); none is an unknown key
  (the refetch-once path), two or more a refusal. An unknown supplied `kid` never falls back to a key without one.
- Key admission, on import and again at use: public keys only (no `d`). `kty` `RSA` or `EC` (never `oct`). `use` `sig`
  when present. An `alg`, when present, must be in the allow-list. RSA keys of at least 2048 bits. A curve that matches
  the algorithm: P-256 for ES256, P-384 for ES384, P-521 for ES512. The header `alg` must equal the JWK's `alg` when the
  JWK has one, which the library also checks.
- Headers: a token whose protected header carries `crit`, `b64`, `enc` or `zip` is refused.
- Time and claims: the package checks every time and claim itself against `Contracts\Clock` and `ClockSkew::seconds()`.
  `exp` is refused at or after `exp + skew`, and the rest of SSO-7.4 applies, so the library's `exp` boundary never
  decides anything. The adapter keeps no clock, leeway, key or token in a property that outlives the call.
- Client assertions: `JWSBuilder` signs them from the connection's stored private key, with that key's `kid` and `typ`
  `JWT`, under the algorithm the connection's `client_assertion_algorithm` pins: for an RSA key `PS256` (the default) or
  `RS256`, for a P-256 key `ES256` (the default and only one). `PS256` is the default for its stronger padding, and
  `RS256` is an explicit opt-in for a provider that accepts nothing else. The algorithm is pinned: it is never
  negotiated from a response or a discovery document, and an assertion is never retried under another. It is apart from
  the ID token allow-list, which judges what the provider signs. The assertion's header, the published JWK's `alg` and
  the relying party description always agree. Each assertion carries `iss` and `sub` equal to the client id, `aud` equal
  to the token endpoint, a fresh `jti`, and an `exp` a short time after `iat`.
- Tests: the adapter's integration tests carry the hostile cases from this comparison as fixtures: `none`, HMAC with the
  public key, an `oct` key planted in the JWKS, a path, a SQL-like string or `"0"` as `kid`, a mismatched `alg`, ES512
  with a P-256 key, a 1024-bit key, `crit`, and the `exp` boundary. Another test runs two verifications in a row with
  different clocks and skews in one process.

## Implementation Anchors

- The adapter is recorded in `jose-adapter.md`. It is the namespace `Protocols\Oidc\Jose`, and `JoseAdapter` is the one
  class in it that names the library: `verify()` (a `JWSVerifier` built per call over an `AlgorithmManager` of the
  allow-list alone, then `verifyWithKey()` with the one stored key chosen) and `signClientAssertion()` (`JWSBuilder`
  over the key's own algorithm, `CompactSerializer`).
- Everything else the adapter carries is the package's own code: `StrictJson` (duplicate members refused after
  unescaping, nested too, large integers kept as digits only where a time claim reads them), `Base64Url` (canonical
  unpadded only), `CompactToken` (compact only, the size cap, no JWE, `crit`, `b64`, `enc` and `zip` refused, `kid` and
  `typ` typed), `AlgorithmAllowList` (RS, PS and ES at 256 bits and above, never `none` or HMAC), `ProviderKey`
  (admission and the check at use, the stored form, the RFC 7638 thumbprint), `PublicKeyEncoding` (the key read back by
  OpenSSL, so a point off its curve is never admitted), `ProviderKeySet` (the JWKS caps, the duplicate admissible `kid`
  refusal, exact `kid` selection and the missing-`kid` rule, what a replacement adds and removes), `KeySelection`,
  `TimeClaims` (`exp`, `iat` and `nbf` against `Contracts\Clock` and `ClockSkew`, typed, at full precision) and
  `ClientKey` (`PS256` or `RS256` for an RSA key, `ES256` for a P-256 key, the thumbprint as `kid`, the public JWK
  published).
- Time and claim checks read `src/Contracts/Clock.php` and `src/Clock/ClockSkew.php`.
- The JWKS is fetched through the package's fetcher (`src/Contracts/Fetcher.php`), never by the library.
- The hostile tokens of this comparison are `src/Testing/Oidc/HostileIdTokens.php`, signed by hand with OpenSSL
  (`JwsSigner`, `PssSignature`), never by the library.

## Authoritative Tests

- `tests/Unit/Protocols/Oidc/Jose/`: each part of the adapter, every algorithm verifying a hand-signed token, client
  assertions verified without the library, two time checks in a row and two interleaved in fibres each keeping their
  own clock and skew.
- `tests/Unit/Testing/Oidc/HostileIdTokensTest.php`: every hostile token refused at the stage it names.
- `tests/Unit/Architecture/JoseLibraryBoundaryTest.php`: only the adapter names the library, only `JoseAdapter` calls
  it, nothing names `JWKSet`, `verifyWithKeySet()`, `None`, HMAC, the checkers, the loaders, encryption, nested tokens
  or key management, and the adapter registers only the asymmetric algorithms.

## Change Triggers

Update this note when any of the following change:

- The chosen library, its major version, or the constraint the package requires.
- The connection's allowed algorithms, or how a key is admitted from a JWKS.
- How the key is selected by `kid`, or the refetch on an unknown `kid`.
- Where time and claim checks are made, or the clock they read.
- How client assertions are signed, their algorithms, or their claims.
- The PHP versions the package supports.
