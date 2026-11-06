<h1 align="center">Laravel SSO</h1>

<div align="center">

[![Latest Stable Version](https://img.shields.io/packagist/v/sinemacula/laravel-sso.svg)](https://packagist.org/packages/sinemacula/laravel-sso)
[![PHP Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-sso/php.svg)](https://packagist.org/packages/sinemacula/laravel-sso)
[![Laravel Version](https://img.shields.io/packagist/dependency-v/sinemacula/laravel-sso/laravel/framework.svg?label=laravel)](https://packagist.org/packages/sinemacula/laravel-sso)
[![Build Status](https://github.com/sinemacula/laravel-sso/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-sso/actions/workflows/tests.yml)
[![Quality Gates](https://github.com/sinemacula/laravel-sso/actions/workflows/quality-gates.yml/badge.svg?branch=master)](https://github.com/sinemacula/laravel-sso/actions/workflows/quality-gates.yml)
[![Maintainability](https://qlty.sh/gh/sinemacula/projects/laravel-sso/maintainability.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-sso)
[![Code Coverage](https://qlty.sh/gh/sinemacula/projects/laravel-sso/coverage.svg)](https://qlty.sh/gh/sinemacula/projects/laravel-sso)
[![Total Downloads](https://img.shields.io/packagist/dt/sinemacula/laravel-sso.svg)](https://packagist.org/packages/sinemacula/laravel-sso)
[![License](https://img.shields.io/github/license/sinemacula/laravel-sso.svg)](LICENSE)

</div>

Tenant single sign-on for Laravel, over SAML 2.0 and OpenID Connect. Each tenant signs its people in through its own
identity provider, and the package hands the application a verified, single-use handoff to sign them in with.

Works on its own, or alongside the rest of the Sine Macula identity and access packages. It ships no routes,
controllers or views: the application's own endpoints call one helper each, and the package never issues the
application's tokens or creates its sessions.

> [!NOTE]
> The package is under active development and has no release yet. The features below describe its intended scope.

## Core Concept

| Concept             | What it is                                                                                         |
|---------------------|----------------------------------------------------------------------------------------------------|
| **Connection**      | One tenant's trust in one identity provider, over SAML 2.0 or OpenID Connect.                      |
| **Verified domain** | An email domain a tenant has proven it controls, which routes discovery to its connection.         |
| **Verified result** | The issuer, subject and connection of a completed sign-in, produced only after every check.        |
| **Link**            | The stored association from a connection's issuer and subject to an identity.                      |
| **Handoff code**    | A single-use, short-lived code the package issues, stores and redeems, bound to the client's flow. |

A flow has three steps, each one helper call from a route of your own: **start** (an authorisation request, answered
with where to send the browser), **complete** (at the assertion consumer service or the callback, answered with a
redirect carrying a handoff code) and **redeem** (the code and the client's verifier, inside your transaction, answered
with the identity to sign in).

## Features

- **SAML 2.0 and OpenID Connect** connections per tenant, with metadata and discovery import, scheduled refresh,
  presets for Google Workspace, Microsoft Entra ID, Okta and Auth0, key and certificate rotation, and secrets encrypted
  at rest.
- **Hardened validation**: schema-checked SAML with signature-wrapping defences, replay protection and optional
  encrypted assertions; ID tokens with pinned algorithms, exact key selection and PKCE.
- **Verified domains and discovery**: DNS TXT verification with scheduled rechecks, and routing an email address to
  its tenant's identity provider without revealing whether the person has an account.
- **SSO-only enforcement** per tenant, with break-glass exemptions and a synchronous revocation hook.
- **Linking** by issuer and subject, through an explicit link flow, just-in-time provisioning, or a verified domain
  for moving a tenant's existing members.
- **A verified handoff**: a single-use code the package issues, stores and redeems, bound to the client that started
  the flow and to the endpoint's purpose, admitted inside your own transaction.
- **Re-authentication** at the identity provider for a session, and the provider's authentication context offered to
  your further-factor policy, never accepted by default.
- **Session provenance**: how a session began (its connection, tenant, protocol, accepted evidence, link and provider
  deadline), captured inside the redemption and projected into stable `sso.*` authentication context keys.
- **IdP-initiated sign-in** by re-initiation, never by consuming an unsolicited assertion.
- **Events** for every flow, failure and administrative change, with one shared context and never a secret.
- **Operations**: pruning, domain rechecks, metadata refresh and key expiry warnings on the schedule, safe on several
  servers, with read-replica and Octane safety.
- **Testing helpers**: fake SAML and OpenID providers, a fake DNS resolver and fetcher, fake freshness and a frozen
  clock, so your flows run in tests without a network.
- **Localisable messages**: the pages a completion shows translate through your `lang` files, and every other answer
  is a code your application words.
- **Extension points**: every policy is a contract with a default that fails closed, which `laravel-iam` binds to
  `laravel-authentication` and `laravel-mfa`.

## Installation

The SAML library installs its XML schemas through a Composer plugin, so allow it first:

```bash
composer config allow-plugins.simplesamlphp/composer-xmlprovider-installer true
composer require sinemacula/laravel-sso
```

## Configuration

Publish the config and the migrations, and migrate:

```bash
php artisan vendor:publish --tag=sso-config
php artisan vendor:publish --tag=sso-migrations
php artisan migrate
```

Every feature is off until you turn it on, but for the scheduled refresh of what connections fetch from their identity
providers, which has nothing to do until a protocol is on. Turn on a protocol, set the base URL every endpoint is built
from (with Laravel's `/api` prefix when your routes live in `routes/api.php`), and register the applications people sign
into:

```dotenv
SSO_OIDC=true
SSO_SAML2=true
SSO_BASE_URL=https://api.example.com/api
```

<!-- snippet: tests/Integration/Examples/Readme/config/sso.php#readme-applications -->
```php
// config/sso.php
'applications' => [
    'web' => [
        'redirect_uri'     => 'https://app.example.com/auth/sso/complete',
        'external_sign_in' => true,
    ],
],
```

Check it, and register the package's scheduled work on the application builder in `bootstrap/app.php`, importing
`Illuminate\Console\Scheduling\Schedule` and `SineMacula\Laravel\Sso\Operations\OperationsSchedule`; metadata refreshes
need a queue worker:

```bash
php artisan sso:check
```

<!-- snippet: tests/Integration/Examples/Readme/bootstrap/app.php#readme-schedule -->
```php
// bootstrap/app.php
->withSchedule(function (Schedule $schedule): void {
    app(OperationsSchedule::class)->register($schedule);
})
```

See [Installation](docs/guides/installation.md) for the extensions, the SAML library's limits and the contracts to
bind, and [Configuration](docs/guides/configuration.md) for every option.

## Usage

Start a flow from a route of your own, with the purpose fixed by the endpoint:

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoStartController.php#route-start-sign-in -->
```php
/** @var array{application: string, connection?: string, email?: string, code_challenge?: ?string} $input */
$input = Validator::validate($request->all(), [
    'application'    => ['required', 'string'],
    'connection'     => ['required_without:email', 'string'],
    'email'          => ['required_without:connection', 'string', 'max:320'],
    'code_challenge' => ['nullable', 'string'],
]);

$challenge = $input['code_challenge'] ?? null;

// The purpose is this endpoint's: a `purpose` in the body is never read
$result = isset($input['email'])
    ? $this->discovery->start($input['application'], Purpose::SIGN_IN, $input['email'], ClientContext::fromRequest($request), $challenge)
    : $this->requests->start($input['application'], Purpose::SIGN_IN, $input['connection'] ?? '', ClientContext::fromRequest($request), $challenge);
```

Complete it where the identity provider sends the browser back:

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoCompletionController.php#route-assertion -->
```php
$result = $this->completions->complete(
    CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
    $connection,
    CompletionRequest::fromRequest($request),
    ClientContext::fromRequest($request),
);

return $this->responses->from($result, $request->getMethod());
```

Redeem the handoff inside your own transaction, write the session in it, and send a credential only after it commits:

<!-- snippet: tests/Integration/Examples/Routes/Controllers/SsoSessionController.php#route-sign-in -->
```php
/** @var array{application: string, connection: string, code: string, verifier: string} $input */
$input = Validator::validate($request->all(), [
    'application' => ['required', 'string'],
    'connection'  => ['required', 'string'],
    'code'        => ['required', 'string'],
    'verifier'    => ['required', 'string'],
]);

$client = ClientContext::fromRequest($request);

// The code is consumed and the session written in one transaction, on
// the package's storage connection
[$result, $sessionId] = DB::connection(StorageConnection::name())->transaction(function () use ($input, $client): array {
    $result = $this->redemptions->admit(Purpose::SIGN_IN, $input['application'], $input['connection'], $input['code'], $input['verifier'], $client);

    // Active, or pending your own further factor; an unlinked handoff
    // signs nobody in
    $sessionId = $result->isRedeemed() && $result->linkedIdentity !== null ? $this->signIns->start($result) : null;

    return [$result, $sessionId];
});

// Only now, after the commit, does a credential leave
return $sessionId === null
    ? self::refusal($result)
    : response()->json($this->signIns->credential($sessionId), 200, Answers::NO_STORE);
```

[An example application](docs/guides/example-application.md) lays out every route, with its middleware, its
authorisation and the client's part, from code the test suite runs.

### Guides

| Guide                                                                         | Covers                                                                     |
|-------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| [Installation](docs/guides/installation.md)                                   | Composer, extensions, migrations, the SAML library's limits, the schedule  |
| [Configuration](docs/guides/configuration.md)                                 | Every configuration key, endpoints, applications and the boot check        |
| [An example application](docs/guides/example-application.md)                  | One coherent route layout, middleware, authorisation and the client's part |
| [Setting up an identity provider](docs/guides/identity-provider-setup.md)     | Registration fields, with Microsoft Entra ID, Okta and Google Workspace    |
| [Opt-in features and their risks](docs/guides/opt-in-features.md)             | Every flow and opt-in, what turning it on means, and what it costs         |
| [Starting a flow](docs/guides/starting-a-flow.md)                             | The start helper, purposes and the client's duties                         |
| [Completing a flow](docs/guides/completing-a-flow.md)                         | The completion helper, unlinked sign-ins and the responses it answers      |
| [Redeeming a handoff](docs/guides/redeeming-a-handoff.md)                     | `admit()` and `redeem()`, what a redemption checks, transactions           |
| [Links](docs/guides/links.md)                                                 | The link store, the `link` purpose, confirmation, listing and removal      |
| [Domains](docs/guides/domains.md) and [discovery](docs/guides/discovery.md)   | Verifying a domain, and routing an email address to its connection         |
| [Enforcement](docs/guides/enforcement.md)                                     | SSO-only tenants, exemptions and revoking sessions                         |
| [Events](docs/guides/events.md)                                               | Every event, its context and the failure reasons                           |
| [Operations](docs/guides/operations.md)                                       | The schedule, several servers, queues, pruning and key expiry warnings     |
| [Re-authenticating](docs/guides/reauthenticating.md)                          | The `reauthenticate` purpose and the sessions contract it needs            |
| [Session provenance](docs/guides/session-provenance.md)                       | What a session keeps from its sign-in, and the `sso.*` context keys        |
| [Testing](docs/guides/testing.md)                                             | The fake identity providers, DNS resolver, fetcher, freshness and clock    |
| [Integrating with `laravel-iam`](docs/guides/integrating-with-laravel-iam.md) | Every seam, the transaction rule and the adapter's obligations             |

Every guide, by task, is in the [guides index](docs/guides/README.md). The security and lifecycle contracts behind
them, for maintainers and reviewers, are in [docs/design](docs/design/README.md).

## Requirements

- PHP ^8.3, with the `bcmath`, `curl`, `dom`, `hash`, `libxml`, `mbstring`, `openssl` and `zlib` extensions
- Laravel ^12.40 || ^13.3

## Testing

```bash
composer test               # all suites in parallel (Paratest)
composer test:coverage      # all suites with clover coverage
composer test:unit          # unit suite only
composer test:feature       # feature suite only
composer test:integration   # integration suite only
composer test:performance   # performance budget suite (serial)
composer test:mutation      # scoped mutation gate
composer test:mutation:full # full mutation suite (no thresholds)
composer bench              # PHPBench hot-path benchmarks
composer check              # static analysis + style
composer format             # format the codebase
composer smells             # advisory code smells (duplication, complexity)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of notable changes.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on branching, commits, code
quality, and pull requests.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for the
disclosure policy and contact details.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
