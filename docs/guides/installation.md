# Installation

```bash
composer require sinemacula/laravel-sso
```

The package needs PHP 8.3 or later with the `curl`, `dom`, `hash`, `libxml`, `mbstring`, `openssl` and `zlib`
extensions; Composer requires them, and the boot check names any that is missing (see
[Checking the configuration](configuration.md#checking-the-configuration)).

Publish the config and the migrations (the `sso_single_use_keys` and `sso_rate_limits` tables, created on the storage
connection: the default connection unless `sso.storage.connection` names another, see
[Storage](configuration.md#storage)), then migrate:

```bash
php artisan vendor:publish --tag=sso-config
php artisan vendor:publish --tag=sso-migrations
php artisan migrate
```

The package never runs a migration itself: they are published and run by the application's migration user, and at run
time the package needs only `SELECT`, `INSERT`, `UPDATE` and `DELETE`. Each migration refuses to run over an existing
table of the same name, before changing anything, with a `TableAlreadyExistsException` that names the configuration
key renaming its table (`single_use.table`, `rate_limits.table`).

To override the package's consumer-facing messages, publish its translations to `lang/vendor/sso`:

```bash
php artisan vendor:publish --tag=sso-lang
```

Every feature is off until you turn it on. Turn on a protocol, set the base URL the package builds its endpoints
from, and register the applications people sign into (see [Configuration](configuration.md)), then check:

```bash
php artisan sso:check
```
