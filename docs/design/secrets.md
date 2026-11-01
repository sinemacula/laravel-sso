# Secrets

## Purpose

This note describes how the package keeps the secrets it stores (client secrets and private keys) encrypted at rest,
what a read of one returns instead of the secret, how a secret in memory is kept out of logs, exceptions, events,
queues and caches, and the rule that every secret, verifier, code and digest is compared in constant time (SSO-2.5,
SSO-11.9).

## Invariants

- Every secret the package stores goes through one contract, `Contracts\SecretEncrypter`: `encrypt()` before it is
  written, `decrypt()` when a flow needs it. Nothing else encrypts or decrypts one, and nothing stores one in
  plaintext.
- The default is `Secrets\LaravelSecretEncrypter`, Laravel's encrypter (its `encrypter` binding, served as a
  `StringEncrypter`) under `app.key`. Laravel's encrypter decrypts under `app.key` and then each of
  `app.previous_keys`, so a secret encrypted before a rotation decrypts while its key is listed as a previous one, and
  rotating the key needs no migration of what is stored. The package has no key setting of its own.
- The binding is a scoped default (`scopedIf`): one the application or another package made before the provider
  registers is kept, and a new instance is built for each request or job, so a rotated key is read by the next one
  once Laravel's encrypter is rebuilt.
- A ciphertext no current or previous key decrypts is a server error: the `RuntimeException` (Laravel's
  `DecryptException`) propagates, and is never read as a refusal, an unknown connection or a missing secret.
- An exception from the encrypter never carries the plaintext: Laravel's messages name the failure only, and the
  contract's `encrypt()` marks its argument `#[\SensitiveParameter]`, so a trace shows it redacted.
- Once set, a secret is never read back by a helper. A read of a client secret is a `Secrets\MaskedSecret`, whose only
  field is `isSet`; a read of a key pair or certificate is a `Secrets\MaskedKey`: `isSet`, the certificate (PEM), the
  public key (PEM) and the fingerprint, the lower-case hex SHA-256 of the certificate's DER when there is one and of
  the public key's DER (SubjectPublicKeyInfo) otherwise. A `MaskedKey` never holds a private key: a PEM containing
  `PRIVATE KEY` is refused with an `InvalidArgumentException`, as is anything that is not exactly one PEM block of the
  expected type, and the refusal never echoes the PEM.
- A decrypted secret in memory is a `Secrets\Secret`. It is held in a `\SensitiveParameterValue` and leaves only through
  `reveal()`, for the code that must send or use it. A dump shows `[redacted]`, even one that lists private properties
  (Symfony's VarDumper, behind Laravel's `dump()` and error pages), as does `json_encode()`; serialising or
  unserialising it throws a `LogicException`, so it cannot reach a queue, a cache or a session; and it has no
  `__toString()`, so a cast or an interpolation into a message fails loudly instead of writing it out. An empty secret
  is refused.
- No secret, decrypted or encrypted, is put in an event, a log line or an exception message. Events carry the shared
  context only (see `event-model.md`); a masked type is what an event or a response may carry.
- Every comparison of a secret, verifier, code or digest goes through `Secrets\ConstantTime`: `equals()` for two
  values, `matchesDigest()` for a value against a stored lower-case hex digest under a cryptographic hash PHP supports
  (SHA-256 by default). Neither `===`, `==` nor `strcmp()` compares one. Only the known value's length can show through
  `hash_equals()`, which is why a digest, of a fixed length, is the form a value of any length is compared in. A lookup
  through a unique database index (the single-use store) is not a comparison in PHP and is exempt.
- An application's own encrypter (a key management service, say) must: encrypt every secret it is given and return
  what its own `decrypt()` turns back into the same secret; throw a `RuntimeException` rather than return a wrong or
  empty secret when it cannot decrypt; never log, report or put in an exception the plaintext it is given or returns;
  hold nothing of one request or job for the next (it is resolved per scope); and keep decrypting what it encrypted
  before any rotation of its own keys, or a stored secret becomes a server error.

## Success Path

- A connection's client secret is set: the package encrypts it with the bound encrypter and stores the ciphertext.
- A flow needs the secret: the package decrypts it, holds it as a `Secret` for the one call that sends it, and lets it
  go; a comparison with it uses `Secret::equals()` or `ConstantTime`.
- An application reads the connection: the secret is a `MaskedSecret` (`{"set": true}`), the key a `MaskedKey` with
  its certificate, public key and fingerprint.
- `APP_KEY` is rotated with the old key in `APP_PREVIOUS_KEYS`: stored secrets still decrypt, new ones are encrypted
  under the new key, and re-encrypting the old ones is optional.
- `php artisan sso:check` reports `[secrets]` while the package is in use: the bound encrypter resolves and, when it is
  the default, encrypts and decrypts a fixed probe under `app.key`.

## Failure / Edge Cases

- No `app.key`: the default cannot be built, and the check reports
  ``The default secret encrypter cannot encrypt and decrypt with `app.key`; set APP_KEY, or bind your own
  SecretEncrypter.``, as it does for a default whose round trip throws or gives back something else. Any other failure
  to resolve the bound encrypter is reported with the container's own message.
- An application's own encrypter is only resolved by the check, never called, so the check makes no network request
  and touches no key.
- A previous key removed from `app.previous_keys` while a secret encrypted under it is still stored: decrypting it is a
  server error. Remove a previous key only once every secret has been re-encrypted under the current one.
- A tampered or truncated ciphertext: Laravel's `DecryptException`, a server error.
- A malformed or private-key PEM given for a `MaskedKey`: `InvalidArgumentException`, with OpenSSL's warning silenced
  and its error queue cleared, so neither reaches a log or a later call.
- A digest algorithm that is not a cryptographic hash PHP supports (an unknown name, a checksum such as `crc32b`):
  `InvalidArgumentException`, a caller's mistake.

## Implementation Anchors

- `src/Contracts/SecretEncrypter.php`; `src/Secrets/LaravelSecretEncrypter.php`.
- `src/Secrets/Secret.php`, `src/Secrets/MaskedSecret.php`, `src/Secrets/MaskedKey.php`.
- `src/Secrets/ConstantTime.php`.
- `src/Secrets/SecretsCheck.php`; `src/SsoServiceProvider.php`: the `scopedIf` binding and `CONFIGURATION_CHECKS`.

## Authoritative Tests

- `tests/Unit/Secrets/SecretTest.php`
- `tests/Unit/Secrets/MaskedSecretTest.php`
- `tests/Unit/Secrets/MaskedKeyTest.php`
- `tests/Unit/Secrets/ConstantTimeTest.php`
- `tests/Feature/Secrets/LaravelSecretEncrypterTest.php`
- `tests/Feature/Secrets/SecretEncrypterBindingTest.php`
- `tests/Feature/Secrets/SecretsCheckTest.php`
- `tests/Integration/Secrets/KeyRotationTest.php`

## Change Triggers

- Any new stored secret, or a new place one is decrypted, sent or compared.
- Any helper that returns a stored secret or key, or an event, log line or exception that could carry one.
- Any change to the encrypter binding, to what the check exercises, or to how previous keys are honoured.
- Any comparison of a secret, verifier, code or digest that does not go through `ConstantTime`.
