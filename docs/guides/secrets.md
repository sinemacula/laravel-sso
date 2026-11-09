# Secrets

The package stores four kinds of secret, each encrypted at rest through
`SineMacula\Laravel\Sso\Contracts\SecretEncrypter`:

- a connection's client secret (OIDC);
- the private keys a connection signs and decrypts with (SAML, and OIDC's `private_key_jwt`);
- the PKCE verifier the package uses with the identity provider, held on each authorisation request until the flow
  completes or expires (never the client's own verifier, of which only the S256 challenge is kept);
- the verified result each handoff code carries until it is redeemed or expires, since it holds personal data.

The first two are long-lived and never returned once set; the last two live no longer than an authorisation request
(`sso.authorization_requests.ttl_seconds`, 600 seconds by default) and a handoff code (each application's
`handoff_ttl_seconds`, at most 300 seconds). None of them reaches a log, an exception or an event.

## The default encrypter

By default the package encrypts with Laravel's encrypter under your `APP_KEY`; it has no key setting of its own. While
a protocol is on, the boot check and `php artisan sso:check` confirm, under `[secrets]`, that the encrypter can encrypt
and decrypt with `app.key`. Without an `APP_KEY` they report:

```text
The default secret encrypter cannot encrypt and decrypt with `app.key`; set APP_KEY, or bind your own SecretEncrypter.
```

A stored ciphertext that no key can decrypt (a key that was removed too soon, a value changed in the database) is a
server error, a `RuntimeException`, never a failed sign-in.

## Rotating APP_KEY

Laravel decrypts with `APP_KEY` and then with each key in `APP_PREVIOUS_KEYS`, so rotation needs no migration of the
stored secrets:

1. Generate a new key, and move the current one to `APP_PREVIOUS_KEYS` (comma-separated when there are several):

   ```dotenv
   APP_KEY=base64:new-key…
   APP_PREVIOUS_KEYS=base64:old-key…
   ```

2. Deploy and restart every worker (`php artisan octane:reload`, `php artisan queue:restart`), so each one builds
   Laravel's encrypter with the new keys. Stored secrets still decrypt under the old key; anything encrypted from now
   on uses the new one.
3. Optionally re-encrypt the stored client secrets and private keys under the new key (setting a secret again encrypts
   it under the current key). The verifiers and handoff results need nothing: each expires within its lifetime.
4. Remove the old key from `APP_PREVIOUS_KEYS` only once no secret is stored under it, and no sooner than the longest
   authorisation request or handoff code lifetime after the deploy; a secret still stored under it then fails to
   decrypt, and a flow or a code still in flight fails.

## Binding a key management service

To keep the secrets under a key management service rather than `APP_KEY`, bind your own implementation of
`SecretEncrypter` in your service provider's `register()`. One bound in a provider that registers before the
package's is kept; one bound later, as your application's providers are, replaces the default as any later binding
does:

<!-- snippet: tests/Integration/Examples/Secrets/AppServiceProvider.php#kms-encrypter-binding -->
```php
// One encrypter per request or job: nothing of one is kept for the next
$this->app->scoped(SecretEncrypter::class, KmsSecretEncrypter::class);
```

Here `KmsSecretEncrypter`, a `final readonly` class implementing `SecretEncrypter`, takes your key management
service's client (`KmsClient $kms`) in its constructor, and keeps every secret under the service's `sso-secrets` key:

<!-- snippet: tests/Integration/Examples/Secrets/KmsSecretEncrypter.php#kms-secret-encrypter -->
```php
/**
 * The secret, encrypted under the service's key.
 *
 * @param  string  $secret
 * @return string
 *
 * @throws \RuntimeException
 */
#[\Override]
public function encrypt(#[\SensitiveParameter] string $secret): string
{
    return $this->kms->encrypt('sso-secrets', $secret);
}

/**
 * The secret the ciphertext holds, decrypted by the service under the
 * version of its key that encrypted it.
 *
 * @param  string  $ciphertext
 * @return string
 *
 * @throws \RuntimeException
 */
#[\Override]
public function decrypt(string $ciphertext): string
{
    return $this->kms->decrypt($ciphertext);
}
```

Your encrypter must:

- give back from `decrypt()` exactly the secret `encrypt()` was given, and keep decrypting what it encrypted after any
  rotation of its own keys;
- throw a `RuntimeException` when it cannot encrypt or decrypt, never return an empty or wrong value;
- never log, report or put in an exception message the secret it is given or returns (mark the parameter
  `#[\SensitiveParameter]`, as above);
- hold nothing of one request or job for the next: bind it `scoped`, or as a singleton only if it keeps no state.

The configuration check only resolves your encrypter; it never calls it, so a check makes no request to your key
management service. Switching an existing installation to another encrypter means re-encrypting the client secrets and
private keys stored: the new encrypter cannot decrypt what the old one encrypted. The flows and handoff codes in flight
at the switch fail, and the person signs in again.

## What a read returns

No helper returns a secret once it is set. What it returns instead:

| Stored                      | Returned               | JSON fields                                       |
|-----------------------------|------------------------|---------------------------------------------------|
| A client secret             | `Secrets\MaskedSecret` | `set`                                             |
| A key pair or a certificate | `Secrets\MaskedKey`    | `set`, `certificate`, `public_key`, `fingerprint` |

`MaskedKey` carries the certificate and the public key as PEM, and the fingerprint as the lower-case hex SHA-256 of the
certificate's DER (the same value `openssl x509 -noout -fingerprint -sha256` prints, without the colons), or of the
public key's DER when there is no certificate. Give the certificate or the public key to your identity provider, and
compare fingerprints to check which one it has. A `MaskedKey` never holds a private key: a PEM with one in it is
refused.

To replace a lost client secret, set a new one; the old one cannot be read back.

## Secrets in your own code

When the package hands your code a decrypted secret, it is a `Secrets\Secret`. Call `reveal()` only where the secret
must be sent or used. A dump of it, or `json_encode()`, shows `[redacted]`; it cannot be serialised (so it cannot be put
on a queue or in a cache) and cannot be cast to a string. Compare it with `$secret->equals($given)`, which runs in
constant time.

For your own comparisons of secrets, codes, verifiers and digests, use `Secrets\ConstantTime`. A stored digest is
lower-case hex, as `hash()` writes it, and SHA-256 unless you name another algorithm:

<!-- snippet: tests/Integration/Examples/Secrets/compare.php#constant-time -->
```php
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

$secretMatches = ConstantTime::equals($known, $given);
$sha256Matches = ConstantTime::matchesDigest($storedSha256Hex, $presented);
$sha512Matches = ConstantTime::matchesDigest($storedSha512Hex, $presented, 'sha512');
```

`matchesDigest()` refuses, with an `InvalidArgumentException`, an algorithm that is not a cryptographic hash PHP
supports.
