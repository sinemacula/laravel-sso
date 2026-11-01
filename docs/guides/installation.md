# Installation

The SAML library the package uses installs its XML schemas through a Composer plugin, so allow it first:

```bash
composer config allow-plugins.simplesamlphp/composer-xmlprovider-installer true
composer require sinemacula/laravel-sso
```

The package needs PHP 8.3 or later with the `bcmath`, `curl`, `dom`, `hash`, `libxml`, `mbstring`, `openssl` and
`zlib` extensions; Composer requires them, and the boot check names any that is missing (see
[Checking the configuration](configuration.md#checking-the-configuration)).

The SAML library (`simplesamlphp/saml2` 6.2 with `simplesamlphp/xml-security` 2.3) sets two limits until the package
can move to its next major version, which needs PHP 8.5:

- **Guzzle stays at 7.** The package requires `guzzlehttp/guzzle` `^7.9`, because the SAML library's dependencies do
  not yet allow `guzzlehttp/psr7` 3, which Guzzle 8 needs.
- **No AES-256-GCM.** The library cannot decrypt an assertion encrypted with AES-256-GCM, so the package neither
  accepts nor advertises it: an encrypted assertion must use AES-128-GCM or AES-192-GCM (or AES-CBC, only where a
  connection opts in). Configure the identity provider accordingly.

Publish the config and the migrations (every `sso_` table, created on the storage connection: the default connection
unless `sso.storage.connection` names another, see [Storage](configuration.md#storage)), then migrate:

```bash
php artisan vendor:publish --tag=sso-config
php artisan vendor:publish --tag=sso-migrations
php artisan migrate
```

The package never runs a migration itself: they are published and run by the application's migration user, and at run
time the package needs only `SELECT`, `INSERT`, `UPDATE` and `DELETE`. Each migration refuses to run over an existing
table of the same name, before changing anything, with a `TableAlreadyExistsException` that names the configuration
key renaming its table (`connections.table`, `single_use.table`, and so on).

To override the package's consumer-facing messages, publish its translations to `lang/vendor/sso`:

```bash
php artisan vendor:publish --tag=sso-lang
```

Every feature is off until you turn it on. Turn on a protocol, set the base URL the package builds its endpoints
from, and register the applications people sign into (see [Configuration](configuration.md)), then check:

```bash
php artisan sso:check
```
