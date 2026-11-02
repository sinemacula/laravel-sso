# JOSE Adapter

## Purpose

This note records the package's JOSE adapter: the one namespace that calls `web-token/jwt-library`, how it reads an ID
token, admits and selects a key, verifies a signature and signs a `private_key_jwt` client assertion (SSO-2.4, SSO-7.3,
RFC 7515, RFC 7517, RFC 7523). It holds the conditions `jose-library.md` set on the choice of library. What the driver
then checks of a verified token (its claims, the nonce, `auth_time`, `at_hash`) is `oidc-id-tokens.md`, and when the
JWKS is fetched and written is `oidc-discovery.md`.

## Invariants

- Every call into the library is made by `Protocols\Oidc\Jose\JoseAdapter`, and nothing outside the namespace
  `Protocols\Oidc\Jose` names the library. An architecture test holds this, and forbids `JWKSet`, `verifyWithKeySet()`,
  `None`, every HMAC algorithm, the library's claim and header checkers, its loaders, its encryption, its nested tokens
  and its key management.
- The adapter holds nothing between calls: `JoseAdapter` has no property, and each `verify()` builds its `JWSVerifier`
  and `AlgorithmManager` for the call (SSO-11.2). The library's own statics are never used, and its time checks never
  run, so a time is only ever judged against `Contracts\Clock` and the skew given per call (SSO-11.13).
- A token is read by `CompactToken::parse()`, before the library sees it, under the size cap given: compact only (so a
  JWE or a JSON serialisation is refused), canonical unpadded base64url, a non-empty signature, a header and a payload
  that are each one JSON object read by `StrictJson`. A header with `crit`, `b64`, `enc` or `zip` is refused, as is one
  whose `alg` is not a non-empty string, whose `kid` is present and not a non-empty string, or whose `typ` is present
  and not a string. `jku`, `x5u`, `jwk` and `x5c` are never read.
- `StrictJson` refuses a repeated member after its escapes are read, nested ones too, in an ID token, a JWKS, a
  discovery document, a token response and a UserInfo response. `decodeObject()` keeps an integer too large for PHP's as
  its digits, so a time claim refuses it rather than reading a finite float. Whatever reads a string or a list of a
  provider's document reads `decodeMembers()` or `decodeAsWritten()` instead, where that integer is a float, so a number
  is never taken for its digits; `decodeAsWritten()` also keeps a JSON object a `\stdClass` and a list an array, so an
  object is never read as a list. A JWKS's `keys`, a key's `key_ops` and a discovery document's lists are read that way.
- `AlgorithmAllowList` holds RS, PS and ES algorithms at 256 bits and above, and `of()` refuses anything else, `none`
  and HMAC above all, whatever a connection's settings say. The library is only ever given the allow-list's own names.
- A key is admitted by `ProviderKey::admit()`, on import and again each time it is read: `kty` `RSA` or `EC`, public
  members only, `kid` a non-empty string when present, `use` `sig` when present, `key_ops` including `verify` when
  present, `alg` on the allow-list and one the key fits when present, an RSA modulus of 2048 to 16384 bits with an odd
  public exponent of at least 3, or a point OpenSSL accepts on P-256, P-384 or P-521.
- A JWKS is read by `ProviderKeySet::read()` under its byte and key caps. A key not admitted is left out; two admitted
  keys under one `kid`, or none admitted, refuses the whole JWKS. What is stored is the public members of each key, in
  a fixed order, and is admitted again as it is read, so a key whose algorithm has left the allow-list is never used.
- `ProviderKeySet::select()` chooses the key, never by position and never through the library's key set. It answers a
  `KeySelection`: `found`, the one key whose own `kid` is byte for byte the header's and which fits the algorithm; or,
  for a token with no `kid`, the only key admissible for its algorithm. `unknown`, no such key, which alone may refetch
  the JWKS. `refused`, an algorithm off the allow-list, a key that does not fit it, or two admissible keys for a token
  with no `kid`, which never fetches. An unknown `kid` never falls back to another key. `overtaken` is
  `Metadata\ProviderKeys`' own answer, when a trust change overtook the refetch (`oidc-discovery.md`).
- `JoseAdapter::verify()` checks the key fits the token's algorithm (`ProviderKey::fits()`) and that the library read
  the same protected header, then calls `verifyWithKey()` with that one key under an `AlgorithmManager` of the
  allow-list alone. The two readings differ for an integer too large for PHP's, which `decodeObject()` keeps as digits
  and the library reads as a float: a token signed with such a header member does not verify. Anything the library
  throws is a signature that does not verify.
- `JoseAdapter::signClientAssertion()` signs with the connection's current `client_assertion` key (`ClientKey`), whose
  type pins its algorithm: `PS256` for an RSA key, `ES256` for a P-256 key. Its header is `alg`, `kid` (the key's RFC
  7638 thumbprint, stable for as long as the key is) and `typ` `JWT`. Its claims are `iss` and `sub` the client id,
  `aud` the token endpoint exactly, a fresh 256-bit `jti`, `iat` now and `exp` 60 seconds later. A fresh assertion is
  signed for each attempt, and it is answered as a `Secrets\Secret`. Anything the library throws while it signs becomes
  a `\InvalidArgumentException` with a fixed message and no previous exception, since the library's frames hold the
  private JWK.
- `CompactToken` and `ClientKey` hold what they carry in a `\SensitiveParameterValue`: a dump shows no token, claim,
  signature or private member, and each refuses to be serialised (SSO-7.6).

## Success Path

1. `IdTokenValidator` reads the token response's ID token with `CompactToken::parse()`.
2. `Metadata\ProviderKeys` reads the stored JWKS with `ProviderKeySet::fromStored()` and asks it to select the key,
   refetching once when the key is unknown.
3. `JoseAdapter::verify()` checks the signature with that key under the connection's allow-list.
4. The package's own rules judge the claims (`TimeClaims`, `oidc-id-tokens.md`).

For a client assertion, `TokenExchange` reads the current key's private half from `Keys\KeyRing` for the one attempt,
and `JoseAdapter::signClientAssertion()` signs it with the package's clock and the connection's token endpoint.

## Failure / Edge Cases

- A token `parse()` refuses is never verified and never fetches. An algorithm off the allow-list is refused before any
  key is looked for, so `none` and HMAC never reach the library, an `oct` key planted in a JWKS is never admitted, and a
  public key is never taken for an HMAC secret.
- A `kid` holding a path, a SQL-like string or `"0"` is only ever compared as a string, so it finds no key.
- A key that fits no algorithm the token could use (ES512 with a P-256 key, an RSA key for an ES algorithm, a key whose
  own `alg` differs) is refused at selection, with no refetch.
- A 1024-bit key is not admitted, so a token signed by it is unknown, and a JWKS of nothing else is refused.
- A client assertion key of any other type is a misconfiguration, an `InvalidArgumentException`: the package generates
  only these. A system with no randomness is a server error (SSO-11.4).

## Implementation Anchors

- `src/Protocols/Oidc/Jose/JoseAdapter.php`, the one caller of the library.
- `src/Protocols/Oidc/Jose/CompactToken.php`, `StrictJson.php`, `Base64Url.php`: reading a token.
- `src/Protocols/Oidc/Jose/AlgorithmAllowList.php`, `ProviderKey.php`, `PublicKeyEncoding.php`, `ProviderKeySet.php`,
  `KeySelection.php`, `Enums/KeySelectionOutcome.php`: algorithms, and admitting and choosing a key.
- `src/Protocols/Oidc/Jose/TimeClaims.php`: `exp`, `iat` and `nbf`, against the clock and skew given.
- `src/Protocols/Oidc/Jose/ClientKey.php`: a connection's own key as a JWK, its algorithm and its `kid`.
- `src/Testing/Oidc/HostileIdTokens.php`: the hostile tokens, signed by hand with OpenSSL, never by the library.

## Authoritative Tests

- `tests/Unit/Protocols/Oidc/Jose/`: each part of the adapter, every algorithm verifying a hand-signed token, client
  assertions verified without the library, and two time checks in a row and two interleaved in fibres each keeping their
  own clock and skew.
- `tests/Unit/Architecture/JoseLibraryBoundaryTest.php`: only the adapter names the library, only `JoseAdapter` calls
  it, nothing names what is forbidden, and the adapter registers only the asymmetric algorithms.
- `tests/Unit/Testing/Oidc/HostileIdTokensTest.php`: every hostile token refused at the stage it names.
- `tests/Feature/Completion/OidcAdversarialCallbackTest.php`: every hostile token through the public callback path, with
  the reason a completion must end with.

## Change Triggers

- The library, or a call the adapter makes into it.
- What a token may hold in its header, or how it is read.
- How a key is admitted, stored or selected, or the algorithms an allow-list may hold.
- How a client assertion is signed, or its header or claims.
- A new outcome of a key's selection.
