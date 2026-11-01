# Logging

## Purpose

This note describes how the package keeps secrets out of its logs: the one logger every package log call goes through,
the sanitiser an identity provider's diagnostics pass through (length capped, control characters removed, secrets
redacted), the redaction applied to every log call's context, and the harness flow tests use to prove that no
verifier, handoff code, protocol state, assertion or provider token is ever logged (SSO-5.7, SSO-9.8, SSO-11.9).

## Invariants

- Every log call the package makes goes through `Logging\SanitizingLogger`, a PSR-3 logger. Nothing in the package
  outside `Logging` names the log manager, a logger, the `Log` facade or the `logger()` and `info()` helpers, and a part
  of the package that takes a `Psr\Log\LoggerInterface` (the fetcher, say) is given this logger by a contextual binding
  (`SsoServiceProvider::LOGGING_CLASSES`). `LoggerInterface` is never bound for the whole application, so the
  application's own logging is left alone. The logger sanitises the message, redacts the context and writes both to the
  channel `sso.logging.channel` names, or to Laravel's default channel when it names none. The channel is resolved on
  each call, never kept, so the logger holds nothing of one request or job for the next (SSO-11.2). A level PSR-3 does
  not define is refused with PSR-3's `InvalidArgumentException`.
- A message, and every string in a context, is sanitised by `Logging\DiagnosticSanitizer`. In order:
  - invalid UTF-8 is scrubbed (each bad byte becomes `?`);
  - tabs and line breaks become spaces, and every other C0 control, DEL, every C1 control and the Unicode
    bidirectional controls (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) are removed, so a diagnostic
    cannot forge a log line, colour a terminal or reorder what a reader sees;
  - whitespace, Unicode separators included, is collapsed to single spaces and trimmed;
  - secrets are replaced with `[redacted]` (below);
  - the text is cut to `sso.logging.max_diagnostic_length` characters (64 to 4096, 512 by default), counted in
    characters rather than bytes; cut text keeps one character fewer and ends in `…`, so it is exactly the cap.

  Whitespace is collapsed before redaction rather than after, so every pattern sees the same text on every pass and
  an unusual space (a no-break space after `Bearer`) cannot hide a secret from it; a replacement never leaves two
  spaces together, so collapsing again afterwards would change nothing. Sanitising is idempotent:
  `sanitize(sanitize($x)) === sanitize($x)`.
- What the sanitiser redacts, in order:
  - a PEM block, from its `-----BEGIN …-----` line to its `-----END …-----` line, or to the end when cut short;
  - a SAML `Assertion`, `EncryptedAssertion`, `SignatureValue` or `X509Certificate` element, with any namespace
    prefix, whole: self-closing, closed, or cut short (to the end of the text);
  - a JWS or JWT (`eyJ…` and two more dot-separated parts) or a JWE (four more);
  - the credential after `Bearer` or `Basic`, in any case;
  - the value of a JSON member (`"key": value`, a string, number or boolean, in plain or escaped JSON), a simple XML
    element (`<key>value</key>`), a quoted pair or XML attribute (`key="value"`, `key='value'`) and an unquoted pair
    (`key=value`, as in a query string or form) whose key, without any namespace prefix, normalises to a redacted
    key; the key is kept;
  - any run of 40 or more base64 or base64url characters (`A-Z`, `a-z`, `0-9`, `+`, `/`, `-`, `_`, with any `=`
    padding), which catches assertions, codes, verifiers, tokens and keys under no recognisable name.
- Redaction errs towards removing too much. A key is redacted only when its whole name normalises to a redacted key
  (`error_code` is not `code`), but a long identifier or URL path of 40 or more base64 characters is redacted along
  with the secrets, and a public reference must therefore stay shorter than that (a ULID or UUID is).
- A context is redacted by `Logging\Redactor`, recursively:
  - a value under a redacted key is `[redacted]`, whatever it is, an array, an object or an exception included;
  - any other string is sanitised as above, so a secret under an innocent key is still caught by its shape;
  - an integer, float, boolean or `null` is kept, and a backed enum (a `FailureReason`) is its value;
  - a `Throwable` is `['class' => …, 'message' => …, 'code' => …]`, the message (and a string code) sanitised, with
    no trace, file, line or previous exception;
  - any other object is `[object <class>]`: objects are never dumped, cast, JSON-encoded or serialised, so nothing a
    value object keeps private (a fetch request's form, a result's body, a decrypted `Secret`) can reach a log, and a
    `Stringable` is never turned into a string;
  - a resource is named by its type;
  - arrays are followed to a depth of 8, the context itself the first; a deeper array is `[truncated]`.
- Keys are compared normalised: lower case, with everything but `a` to `z` and `0` to `9` removed, so
  `Client-Secret`, `CLIENT_SECRET`, `clientSecret` and `client.secret` are one key. The built-in keys
  (`Redactor::REDACTED_KEYS`) are: `password`, `secret`, `client_secret`, `clientsecret`, `token`, `access_token`,
  `refresh_token`, `id_token`, `code`, `handoff_code`, `verifier`, `code_verifier`, `state`, `relay_state`,
  `relaystate`, `nonce`, `assertion`, `saml_response`, `samlresponse`, `saml_request`, `samlrequest`, `private_key`,
  `privatekey`, `authorization`, `cookie`, `set_cookie`, `client_assertion` and `signature`.
  `sso.logging.redacted_keys` adds keys; nothing removes a built-in one.
- The public reference is the only flow identifier a log carries (SSO-9.8). Package code logs it under a key that is
  not redacted (`request_reference`, as events carry it), with the reason as a `FailureReason`, and never logs a
  verifier, code, state, nonce, assertion or token, even redacted, on purpose: redaction is the backstop, not the
  design.
- Every setting is read on each call through `Logging\LoggingSettings`, and a malformed one fails closed with an
  `InvalidArgumentException` naming its key, so a log call never goes out unsanitised, uncapped or under fewer
  redacted keys than configured. A sanitiser pattern that cannot run over the text (a PCRE limit on a huge body)
  redacts the text whole rather than passing it through.

## Success Path

- A flow fails at the provider: it logs, through `SanitizingLogger`, the provider's error code and sanitised
  description with the request's public reference and the `FailureReason`. The channel receives the message with any
  token, code or assertion replaced by `[redacted]`, at most 512 characters long, with no control characters.
- A flow logs a fetch's failure detail (the host that did not resolve, the TLS error): the detail is sanitised, and
  the request or result object, if passed, appears only as `[object <class>]`.
- An exception is logged in the context as Laravel does (`'exception' => $e`): the channel receives its class,
  sanitised message and code, never its trace.
- `php artisan sso:check` reports `[logging]` while the package is in use: the channel is the default or one
  `logging.channels` configures, the diagnostic length is an integer from 64 to 4096, and the added keys are a list
  of names each holding a letter or a digit.
- A flow test captures the package's logs with `Tests\Concerns\CapturesLogs` (a channel backed by Monolog's
  `TestHandler`, which `sso.logging.channel` is pointed at), runs the flow, and asserts with
  `assertNothingLoggedContains()` that none of its verifiers, codes, state, assertions or tokens appear in any
  record's message or context, and with `assertLoggedContains()` that its public reference and reason do.
  `tests/Integration/Logging/NothingSecretIsLoggedTest.php` is the template each flow's test follows.

## Failure / Edge Cases

- `sso.logging.channel` that is not a string or `null`: `InvalidArgumentException` on each log call, and the check
  reports it. An empty string is the default channel, as an unset `SSO_LOG_CHANNEL=` gives one. A name
  `logging.channels` does not configure is reported by the check, naming the channel; at run time Laravel's own
  handling of an unknown channel applies (it reports the problem and writes to its emergency logger).
- `sso.logging.max_diagnostic_length` outside 64 to 4096, or not an integer or the digit string `env()` gives for
  one: `InvalidArgumentException` on each log call; the check reports it.
- `sso.logging.redacted_keys` that is not a list, or holds anything that is not a string with a letter or digit (an
  empty name would match every key with none): `InvalidArgumentException` on each log call; the check reports it.
- Text that only looks like a secret is kept: `error_code=E1`, `token_type`, `StatusCode`, `AssertionConsumerService`,
  a run of 39 characters.
- `Basic` or `Bearer` in prose (`basic setup failed`) takes the next word for a credential and redacts it.
- A pair with nothing after the `=` and then a space (`code= state`) takes the next word as its value and redacts it:
  more is removed, never less.
- A secret shorter than 40 characters that is under no key, outside every recognised form, is not caught by the
  sanitiser. Package code never logs one; the redacted keys catch the ones it passes in a context.
- A header written as `Name: value` is not a pair: only its credential after `Bearer` or `Basic` is redacted.
  Package code never logs transport headers (SSO-5.7); a header map in a context is redacted by its keys.
- Laravel's shared log context (`Log::shareContext()`, `Context`) is added by Laravel after redaction and is the
  application's own.

## Implementation Anchors

- `src/Logging/SanitizingLogger.php`.
- `src/Logging/DiagnosticSanitizer.php`.
- `src/Logging/Redactor.php`: `REDACTED_KEYS`, `MAX_DEPTH`.
- `src/Logging/LoggingSettings.php`: `normalizeKey()`.
- `src/Logging/LoggingCheck.php`; `src/SsoServiceProvider.php`: `CONFIGURATION_CHECKS`, `LOGGING_CLASSES`.
- `tests/Concerns/CapturesLogs.php`: the capture harness.

## Authoritative Tests

- `tests/Unit/Logging/DiagnosticSanitizerTest.php`
- `tests/Unit/Logging/RedactorTest.php`
- `tests/Feature/Logging/LoggingSettingsTest.php`
- `tests/Feature/Logging/SanitizingLoggerTest.php`
- `tests/Feature/Logging/LoggingCheckTest.php`
- `tests/Integration/Logging/NothingSecretIsLoggedTest.php`
- `tests/Unit/SsoServiceProviderTest.php`, `tests/Feature/SsoServiceProviderTest.php`: the contextual binding
- `tests/Unit/Architecture/NamespaceDependenciesTest.php`: only `Logging` writes to the logs directly

## Change Triggers

- Any new log call, or a new part of the package that takes a `LoggerInterface`: it goes through `SanitizingLogger`,
  and the class joins `SsoServiceProvider::LOGGING_CLASSES`.
- Any new secret, verifier, code, state or token the package holds: its key joins `Redactor::REDACTED_KEYS` if it
  could be logged under a key no built-in one covers, and the flow's test captures its logs and asserts it is absent.
- Any new form a provider's diagnostic may carry a secret in (a new XML element, a new header): a pattern in
  `DiagnosticSanitizer`, with its test.
- Any change to the cap, the depth, the replacement text or the order of the sanitiser's steps: the idempotence test
  must still hold.
