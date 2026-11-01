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
identity provider, and the package hands the application a verified result to sign them in with.

Works on its own, or alongside the rest of the Sine Macula identity and access packages. It ships no routes,
controllers or views: the application's own endpoints call one helper each, and the package never issues the
application's tokens or creates its sessions.

> [!NOTE]
> The package is under active development and has no release yet. The features below describe its intended scope.

## Core Concept

| Concept             | What it is                                                                                  |
|---------------------|---------------------------------------------------------------------------------------------|
| **Connection**      | One tenant's trust in one identity provider, over SAML 2.0 or OpenID Connect.               |
| **Verified domain** | An email domain a tenant has proven it controls, which routes discovery to its connection.  |
| **Verified result** | The issuer, subject and connection of a completed sign-in, produced only after every check. |
| **Link**            | The stored association from a connection's issuer and subject to an identity.               |
| **Handoff code**    | A single-use, short-lived code that carries a verified result back to the application.      |

## Features

- **SAML 2.0 and OpenID Connect** connections per tenant, with metadata import, certificate and key rotation, and
  secrets encrypted at rest.
- **Verified domains and discovery**: DNS TXT verification, and routing an email address to its tenant's identity
  provider without revealing whether the person has an account.
- **SSO-only enforcement** per tenant, with exemptions and a synchronous revocation hook.
- **Linking** by issuer and subject, by an explicit link flow, or by a verified domain, and an event to provision new
  identities just in time.
- **A verified handoff** bound to the client that started the flow, for the application or `laravel-authentication` to
  redeem.
- **Events** for every flow, failure and administrative change, never carrying a secret.

## Installation

```bash
composer require sinemacula/laravel-sso
```

## Configuration

Publish the config:

```bash
php artisan vendor:publish --tag=sso-config
```

## Requirements

- PHP ^8.3, with the `curl`, `dom`, `hash`, `libxml`, `mbstring`, `openssl` and `zlib` extensions
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
