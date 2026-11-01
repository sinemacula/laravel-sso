# Configuration

## Purpose

This note records how the package is switched on and checked: the feature switches, the configuration checked at boot
for what is enabled and reported by `sso:check`, the application and endpoint settings, and how each part of the
package registers its settings and its check without editing another's (SSO-12.2, SSO-12.3).

## Invariants

- Every feature is off until the application turns it on in `sso.features` (`saml2`, `oidc`, `discovery`,
  `enforcement`, `encrypted_assertions`, `metadata_refresh`, `idp_initiated`, `domain_linking`). A protocol is the
  package in use; every other feature needs a protocol, and the SAML-only ones need `saml2` (`Config\Enums\Feature`).
  A feature that is on lets an application or a connection opt into it, never opts in for them, and no setting turns
  off a security check of a feature that is on.
- `Config\Features::enabled()` is the answer a flow acts on, and a malformed switch fails it closed with an
  `InvalidArgumentException`. `requested()` and `isInUse()` are the answers the checks act on: a malformed switch counts
  as on there, so what it would enable is checked as well as the switch.
- Settings are read when used, through the shared readers: `Config\IntegerSetting` (an integer or the digit string
  `env()` gives, within a range), `Config\BooleanSetting` (a boolean, `1`/`0`, `true`/`false`) and `Config\UrlSetting`
  (a web URL, or an application's redirect URI). Each fails closed naming the key and what it must be, never the
  configured value.
- Each part of the package that has settings has a `Contracts\ConfigurationCheck`, registered under a subject in
  `SsoServiceProvider::CONFIGURATION_CHECKS`. A check says whether it applies (what it covers is enabled; the
  package's infrastructure applies while the package is in use; `[features]` always applies) and returns closures,
  each throwing on one problem. A check must not throw from `applies()`, and reads configuration only.
- `Config\ConfigurationChecker` resolves each check from the container when the configuration is checked, never
  before; skips one that does not apply; runs every closure of one that does; and reports a check that cannot be built
  or is not a check as a problem of its subject.
- At boot, outside the console, the checker runs once the application has booted and any problem stops the boot with
  an `Exceptions\InvalidConfigurationException` listing every problem as `[subject] message` (SSO-12.3). Octane
  workers are not console processes, so they are checked as they boot.
- In the console the checker runs as each command in `SsoServiceProvider::WORKER_COMMANDS` starts (`queue:work`,
  `queue:listen`, `horizon`, `horizon:supervisor`, `horizon:work`, `schedule:run`, `schedule:work`, `schedule:test`,
  `octane:start` and the Octane server commands), on Artisan's `CommandStarting` event, and a problem fails the command
  with the same exception before it takes a job, runs a scheduled task or starts a server. The command is matched by
  the name Artisan resolved, so an alias or abbreviation is checked as the command. Every other command runs whatever
  the configuration, so a misconfigured application can still run `sso:check`, its migrations, `vendor:publish`, the
  `config:*`, `cache:*` and `optimize*` commands, `package:discover`, `list`, `help`, `about` and `tinker`.
- `sso:check` runs the same checks and prints `[subject] OK`, `[subject] not enabled` or one line per problem, exiting
  `1` on a problem. It opens no database connection and prints no secret.
- An application (`sso.applications.<name>`) has exactly one redirect URI, compared later as an exact string:
  `https`, `http` on `127.0.0.1` or `[::1]`, or a private-use scheme with a dot (RFC 8252). It may set
  `external_sign_in` (off unless set), `delivery` (`fragment` or `query`), `discovery` (`enabled`, and the
  `fallback_url` required while it is on with the `discovery` feature), `unlinked_handoffs` (off unless set) and
  `handoff_ttl_seconds` (1 to 300, default 60). Any other key is refused. No request input selects among these values.
  Each application is judged by `Applications\Application::fromSettings()`, which the flows use too, and the exact URI
  is answered by the `Contracts\RedirectUriResolver` contract, defaulting to this setting (see `applications.md`).
- The endpoints (`sso.endpoints`) are built from a configured base URL (a web URL with no query) and a path pattern per
  endpoint holding `{connection}` once, never from the request's host or headers (SSO-5.5), each read by
  `Endpoints\EndpointSettings`, the one way the default `Contracts\EndpointResolver` and the check read them.
- The PHP extensions the package needs (`curl`, `dom`, `hash`, `libxml`, `mbstring`, `openssl`, `zlib`, and
  `idn_to_ascii()` from `ext-intl` or `symfony/polyfill-intl-idn`) are required by Composer and checked by
  `[extensions]` while the package is in use, naming each missing one with what it is needed for.

## Success Path

- An application with every feature off boots with only `[features]` checked; `sso:check` reports the rest as not
  enabled.
- An application that turns a protocol on configures `sso.endpoints.base_url` and its applications, and boots once
  `[features]`, `[extensions]`, `[storage]`, `[endpoints]`, `[applications]` and every check of the package's
  infrastructure pass.
- A part of the package that adds settings adds its section to `config/sso.php`, its check class implementing
  `ConfigurationCheck` under its own namespace, and its entry in `CONFIGURATION_CHECKS`; it reads its settings through
  the shared readers, so the check and the code that uses a setting judge it the same way.

## Failure / Edge Cases

- A misspelt switch or application setting is refused rather than left at its default.
- A feature on without the protocol it needs is a problem, including over a malformed protocol switch.
- A malformed switch fails a flow closed (`enabled()`), and is reported by `[features]` at boot.
- A check class that does not exist is reported under its subject, so a registry entry left behind fails the boot
  rather than being skipped.
- A long-running or scheduled process started from the console is checked as it starts rather than skipped: a queue
  worker, Horizon or the scheduler in a misconfigured application exits with the exception, and the process each
  spawns (a `queue:work` under `queue:listen`, a supervisor or worker under `horizon`, a `schedule:run` under
  `schedule:work`) is checked again as it starts. An application command the scheduler runs is checked through
  `schedule:run`, which fails before running it.
- The boot check reads configuration only and touches no database, so it adds no query to a request (the performance
  suite's query budget for registering and booting the package stays at zero).

## Implementation Anchors

- `src/Config/Enums/Feature.php`, `src/Config/Features.php`, `src/Config/BooleanSetting.php`,
  `src/Config/IntegerSetting.php`, `src/Config/UrlSetting.php`.
- `src/Contracts/ConfigurationCheck.php`, `src/Config/ConfigurationChecker.php`,
  `src/Exceptions/InvalidConfigurationException.php`, `src/Exceptions/MissingExtensionException.php`.
- `src/Config/Checks/FeaturesCheck.php`, `ExtensionsCheck.php`, `StorageCheck.php`, `EndpointsCheck.php`,
  `ApplicationsCheck.php`.
- The checks of later parts, each beside the settings it reads: `src/Freshness/FreshnessCheck.php` (`[freshness]`),
  `src/Keys/KeysCheck.php` (`[keys]`), `src/Connections/MappingCheck.php` (`[mapping]`),
  `src/Domains/DomainsCheck.php` (`[domains]`), `src/Flows/FlowsCheck.php` (`[flows]`).
- `src/Console/CheckConfigurationCommand.php`; `src/SsoServiceProvider.php`: `CONFIGURATION_CHECKS`,
  `WORKER_COMMANDS`, `checkConfiguration()`, `checkConfigurationBeforeWork()`; `config/sso.php`.

## Authoritative Tests

- `tests/Unit/Config/ConfigurationCheckerTest.php`, `tests/Unit/Config/BooleanSettingTest.php`,
  `tests/Unit/Config/IntegerSettingTest.php`, `tests/Unit/Config/UrlSettingTest.php`,
  `tests/Unit/Config/Enums/FeatureTest.php`.
- `tests/Feature/Config/FeaturesTest.php` and every test under `tests/Feature/Config/Checks/`.
- `tests/Feature/Console/CheckConfigurationCommandTest.php`.
- `tests/Feature/SsoServiceProviderTest.php` `testBootingOutsideTheConsoleFailsOnAProblem`,
  `testBootingInTheConsoleLeavesTheCheckToTheCommand`, `testAWorkerCommandFailsToStartOnAProblem`,
  `testAWorkerCommandStartsWithAWellConfiguredPackage`, `testARecoveryCommandStartsOnAProblem`;
  `tests/Integration/Config/BootCheckTest.php`.

## Change Triggers

- A new setting, section or feature switch; a new check, or a change to when one applies.
- A change to where the boot check runs, to the commands checked as they start, or to what `sso:check` prints or
  exits with.
- A change to the application or endpoint settings, or to what a redirect URI may be.
