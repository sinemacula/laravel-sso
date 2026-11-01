# Completion Responses

## Purpose

This note records how the way a completion ended becomes the response the application's controller returns at the
assertion consumer service and the OIDC callback (SSO-5.6, SSO-5.7, SSO-12.1): the status of each outcome after each
HTTP method, where the handoff code, the failure code and the public reference go on the redirect URI, the headers
every response carries, the body, and why the builder catches nothing (SSO-11.4). The package has no route or
controller: it answers a value the application returns.

## Invariants

- `Responses\CompletionResponses::from(CompletionResult $result, string $method)` builds a
  `Responses\CompletionResponse` from a `Completion\CompletionResult` and the method the completion arrived by. It is
  the only way the package turns a result into a response; it reads nothing from the request but the method, and never
  chooses or alters a target (SSO-5.5).
- `CompletionResponse` (`final readonly`) holds the `status`, the `headers` (every header but `Location`), the plain
  text `body`, and the `Location` of a redirect, read through `location()`. It is Laravel's `Responsable`:
  `toResponse()` answers an `Illuminate\Http\Response` with exactly that status, those headers, that `Location` and
  that body.
- Status, by outcome:

  | Outcome        | After `POST` | After `GET` | After any other method (`HEAD` included) | `Location`                         |
  |----------------|--------------|-------------|------------------------------------------|------------------------------------|
  | `completed`    | `303`        | `302`       | `303`                                    | redirect URI, `code`, `reference`  |
  | `failed`       | `303`        | `302`       | `303`                                    | redirect URI, `error`, `reference` |
  | `reinitiated`  | `303`        | `302`       | `303`                                    | the start URL, exactly as given    |
  | `rejected`     | `400`        | `400`       | `400`                                    | none                               |
  | `rate_limited` | `429`        | `429`       | `429`                                    | none, `Retry-After: {retryAfter}`  |

  The method is compared case-insensitively. A `307` or a `308` would make the browser post the assertion or the form
  again to the redirect URI, so neither is ever answered: `CompletionResponse::redirect()` accepts only `302` and
  `303`, and throws `InvalidArgumentException` for anything else.
- The `Location` of a completed or failed one is the application's redirect URI, otherwise unchanged (no path, trailing
  slash or normalisation added; a private-use scheme such as `com.example.app:/sso` is kept), with the parameters
  appended as the application's `delivery` says:
  - `fragment`: `#` and the parameters. The configured redirect URI never has a fragment
    (`Config\UrlSetting::redirect()` refuses one at boot), so the fragment is the package's alone.
  - `query`: `?` and the parameters, or `&` when the URI already has a query.
- The parameters are `code` (the issued handoff's code, revealed only here) or `error` (the failure reason's value),
  then `reference` (the request's public reference), in that order, written by `http_build_query()` with RFC 3986
  encoding. A code and a reference are base64url and a reason is lower case with `_`, so the encoding changes none of
  them. A failed one carries the code and nothing else: never a reason in prose, the identity provider's error
  description or an assertion (SSO-5.7).
- Every response, the `400` and the `429` included, is sent with `HEADERS`, in this order: `Cache-Control: no-store`,
  `Referrer-Policy: no-referrer` and `Content-Type: text/plain; charset=UTF-8`; the `429` adds `Retry-After`. The
  completed one carries the handoff code (SSO-9.8); the others carry the same headers so no response is cached and no
  redirect leaks the URL in a `Referer`. Symfony writes `Cache-Control: no-store` as `no-store, private`, which only
  narrows it, and adds a `Date` header.
- The body is a message read through `Localization\Messages` in the translator's current locale (SSO-12.6):
  `completion.redirecting` for a redirect, `completion.invalid` for a `400` and a `429`, the same whatever the reason.
- The `Location` is held in a `\SensitiveParameterValue`. The debug view (`__debugInfo()`) and `json_encode()` show
  the status, the headers, the body and the `Location` with the value of every `code` parameter, in the query or the
  fragment, replaced by `[redacted]`; an export or an array cast sees only the wrapper. The response refuses to be
  serialised or unserialised (`LogicException`), since the `Location` carries the code.
- `CompletionResponses` keeps only the `Messages` it was given, and is not bound: the container builds it with the
  application's translator wherever it is resolved, so nothing of one request or job outlives it (SSO-11.2).

## Success Path

1. The application's controller calls the completion helper (`completion.md`), which answers a `CompletionResult`.
2. It resolves `CompletionResponses` and calls `from($result, $request->getMethod())`.
3. For a completed or failed one, the builder appends the code or the failure code and the reference to the redirect
   URI in the fragment or the query, picks `303` or `302` by method, and reads `completion.redirecting`.
4. The controller returns the `CompletionResponse`; Laravel calls `toResponse()` and sends the status, the headers,
   the `Location` and the body.

## Failure / Edge Cases

- No trusted redirect target (an unknown connection, a response that matches no authorisation request): `rejected`, a
  `400` with no `Location`. The response never says which.
- A full limit: a `429` with `Retry-After` of at least one second (`rateLimited()` throws `InvalidArgumentException`
  below that) and no `Location`.
- An unsolicited SAML response: `reinitiated`, a redirect to the connection's start URL exactly as given; it carries no
  code.
- The builder catches nothing. A database error never becomes a `CompletionResult`, because the completion propagates
  it as a server error (SSO-11.4), so it never reaches the builder and is never turned into a failure redirect; and an
  error the builder meets itself (a translator that cannot read its lines, or the `LogicException` of a message with no
  English line) propagates as thrown.
- A redirect URI whose query is empty (`https://app.example.com/sso?`) has a query: the parameters follow `&`.

## Implementation Anchors

- `src/Responses/CompletionResponse.php`: `HEADERS`, the statuses, `redirect()`, `rejected()`, `rateLimited()`,
  `location()`, `toResponse()`, the redacted debug view.
- `src/Responses/CompletionResponses.php`: `from()`, the status by method, the `Location` by delivery.
- `src/Completion/CompletionResult.php`, `src/Handoffs/IssuedHandoff.php`, `src/Applications/Enums/HandoffDelivery.php`,
  `src/Localization/Messages.php`, `lang/en/messages.php`.

## Authoritative Tests

- `tests/Unit/Responses/CompletionResponseTest.php`: every status after `POST`, `GET` and `HEAD`, never `307` or `308`
  over every outcome and method, every `Location` by delivery and URI form, every failure reason, the `400` and the
  `429` exactly, the headers as whole arrays, the debug view without the code, the refused serialisation, and an
  error that propagates.
- `tests/Feature/Responses/CompletionResponsesTest.php`: the application's translator (an override applies, an
  untranslated locale reads English), `toResponse()` with exactly the status and headers, and a route returning the
  response.

## Change Triggers

- A new completion outcome, or a change to an outcome's status, target or parameters.
- A change to the headers, to the body's message, or to where the code or the reference goes.
- Anything that would catch an error between the completion and the response.
