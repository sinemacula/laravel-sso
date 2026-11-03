# Logging

The package logs what goes wrong in a sign-in (an identity provider's error, a refused response, a failed request to
the provider) so you can diagnose it, and nothing that would let someone who reads your logs sign in as somebody else.
Every log call it makes goes through one logger, `SineMacula\Laravel\Sso\Logging\SanitizingLogger`, which:

- writes to the channel you choose, or to your default channel;
- sanitises the message and every string in the context: control characters and Unicode direction controls removed,
  whitespace collapsed, secrets replaced with `[redacted]`, and the text cut to at most 512 characters (ending in `…`
  when cut);
- redacts the context: the value under any redacted key is `[redacted]`, an exception is reduced to its class,
  sanitised message and code (no trace), and any other object is written as `[object <class>]`, never dumped.

A request is identified in the logs only by its public reference (`request_reference`), with the failure reason as a
code, so you can match a log line to the failure redirect and event the same request produced.

## Settings

| Key                             | Default | Env                             |
|---------------------------------|---------|---------------------------------|
| `logging.channel`               | `null`  | `SSO_LOG_CHANNEL`               |
| `logging.max_diagnostic_length` | `512`   | `SSO_LOG_MAX_DIAGNOSTIC_LENGTH` |
| `logging.redacted_keys`         | `[]`    |                                 |

Each is read on every log call. A malformed value makes every package log call throw an `InvalidArgumentException`
naming its key, rather than log something unsanitised, and stops the boot outside the console; `php artisan sso:check`
reports it under `[logging]`.

## Choosing a channel

By default the package logs to Laravel's default channel (`LOG_CHANNEL`). To keep its lines apart, name any channel
your `config/logging.php` configures:

```dotenv
SSO_LOG_CHANNEL=sso
```

Here, in `config/logging.php`, the `sso` channel is a daily file under your storage directory:

<!-- snippet: tests/Integration/Examples/Logging/config/logging.php#logging-channel -->

```php
'channels' => [
    'sso' => [
        'driver' => 'daily',
        'path'   => storage_path('logs/sso.log'),
        'level'  => env('LOG_LEVEL', 'info'),
        'days'   => 30,
    ],
],
```

An empty value is the default channel. A name `logging.channels` does not configure is reported by the boot check and
`sso:check`:

```text
`sso.logging.channel` names the channel [sso], which is not configured in `logging.channels`.
```

The channel is resolved on every call, so a change is picked up by the next log line without a restart.

## How much diagnostic text to keep

An identity provider's error description or status message, and every other string the package logs, is cut to
`logging.max_diagnostic_length` characters: a whole number from `64` to `4096` (default `512`). Anything else fails
with `sso.logging.max_diagnostic_length must be an integer from 64 to 4096.` Raise it if your providers' messages are
cut before the useful part; the text is redacted before it is cut, so a longer cap keeps more diagnostic text, never a
secret.

## What is redacted

Whatever key it is logged under, the sanitiser replaces with `[redacted]`:

- a JWT (an ID token, a client assertion, a JWT access token) or a JWE;
- the credential after `Bearer` or `Basic`;
- a PEM block (a certificate or key);
- a SAML `Assertion`, `EncryptedAssertion`, `SignatureValue` or `X509Certificate` element, whole;
- the whole value after a redacted key in `key=value` (a query string or form), `key="value"` (an XML attribute),
  `key => value` and `[key] => value` (a PHP array dump), `key: value` (YAML, a JavaScript object), `"key": value`
  (JSON, escaped JSON and an object or array included), `<key>value</key>` (an XML element, child elements
  included) or `<key value="…"/>`, whatever punctuation, quotes or brackets it holds;
- the whole value of an `Authorization`, `Proxy-Authorization`, `Cookie` or `Set-Cookie` header written as
  `Name: value`, to the end of the text;
- any run of 40 or more base64 or base64url characters, which is how a SAML response, a code, a verifier or a key
  looks when nothing names it;
- any percent- or HTML-entity-encoded run of text (an encoded URL or body) that, decoded, carries any of the above,
  whole.

The base64 rule also redacts long identifiers and URL paths, and the encoded rule a whole encoded URL: a log line may
show `[redacted]` where a long path, an id or a URL was. That is deliberate: the package removes too much rather than
too little.

The redacted keys are compared without regard to case, separators or percent-encoding (`Client-Secret`,
`CLIENT_SECRET`, `clientSecret`, `client.secret` and `client%5Fsecret` are one key), and a key matches when any run
of its words does: a form's `user[password]`, a dotted `credentials.password`, a path's `user/password` and a
header's `X-Client-Secret` all match, and so does `private key=…` in text. `error_code` and `token_type` do not.
Built in:

`password`, `secret`, `client_secret`, `token`, `access_token`, `refresh_token`, `id_token`, `code`, `handoff_code`,
`verifier`, `code_verifier`, `state`, `relay_state`, `nonce`, `assertion`, `saml_response`, `saml_request`,
`private_key`, `authorization`, `cookie`, `set_cookie`, `client_assertion` and `signature`.

## Adding redacted keys

If your own adapters pass the package something else that must never be logged (a key management service's token, a
tenant's API key), add its key name in your published `config/sso.php`. Added keys join the built-in ones; none can be
removed:

<!-- snippet: tests/Integration/Examples/Logging/config/sso.php#logging-settings -->

```php
'logging' => [
    'channel'               => env('SSO_LOG_CHANNEL'),
    'max_diagnostic_length' => env('SSO_LOG_MAX_DIAGNOSTIC_LENGTH', 512),
    'redacted_keys'         => ['x-api-key', 'kms_token'],
],
```

The value must be a list of names, each holding at least one letter or digit; anything else fails with
`` `sso.logging.redacted_keys` must be a list of key names, each holding a letter or a digit. ``

## Logging from your own adapters

An adapter you bind for the package (an encrypter, a resolver, a store) can log through the same logger, so its lines
get the same treatment and land on the same channel. Here `KmsSecretEncrypter`, a `final readonly` class that implements
`Contracts\SecretEncrypter`, takes your key management service's client (`KmsClient`, which throws `KmsException`) and
`Logging\SanitizingLogger` in its constructor, and logs a refusal of the service through the logger before it throws:

<!-- snippet: tests/Integration/Examples/Logging/KmsSecretEncrypter.php#logging-adapter-decrypt -->

```php
/**
 * The secret the key management service decrypts from the ciphertext; a
 * refusal is logged through the package's logger and thrown as a
 * `RuntimeException`, which the package treats as a server error.
 *
 * @param  string  $ciphertext
 * @return string
 *
 * @throws \RuntimeException
 */
#[\Override]
public function decrypt(string $ciphertext): string
{
    try {
        return $this->kms->decrypt($ciphertext);
    } catch (KmsException $exception) {
        $this->logger->error('KMS decrypt failed.', ['exception' => $exception]);

        throw new \RuntimeException('The secret could not be decrypted.', 0, $exception);
    }
}
```

Its `encrypt()` does the same. The exception reaches the channel as its class, sanitised message and code, never its
trace: with `x-api-key` added to the redacted keys above, a refusal whose message names the API key the call carried
reaches it as `Decrypt on alias/sso was refused for x-api-key=[redacted]`.

Redaction is a backstop, not a licence: log the public reference and a reason, never a secret on purpose.
