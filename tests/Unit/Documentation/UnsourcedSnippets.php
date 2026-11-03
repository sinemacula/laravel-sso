<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

/**
 * Every PHP code block of a guide or the README that no snippet marker holds to
 * an executed example (SSO-12.5), by its document and its place among that
 * document's PHP blocks, with the reason it is not taken from one.
 * `ExampleSnippetsTest` fails on a PHP block that is neither marked nor listed
 * here, and on a listed block that is marked or gone, so this list is exactly
 * the documentation's code that no test runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnsourcedSnippets
{
    /** @var string A configuration array or a published file's contents, which the configuration guide and the configuration tests hold. */
    public const string CONFIGURATION = 'configuration';

    /** @var string The application's own bootstrap, route registration or schedule, around a call the guide names. */
    public const string WIRING = 'wiring';

    /** @var string A container binding in the application's service provider. */
    public const string BINDING = 'binding';

    /** @var string A sketch of a contract or a controller the application writes against its own models. */
    public const string IMPLEMENTATION = 'implementation';

    /** @var string A call of a sibling package's API, which this package does not install. */
    public const string SIBLING = 'sibling';

    /** @var string A call of the package's API not yet taken from an executed example. */
    public const string CALL = 'call';

    /** @var array<string, array<int, string>> Each document's unmarked PHP blocks, by their place among its PHP blocks (from 1), with their reason. */
    public const array FENCES = [
        'README.md'                           => [1 => self::CONFIGURATION, 2 => self::WIRING],
        'docs/guides/clock.md'                => [1 => self::CALL, 2 => self::BINDING, 3 => self::CALL],
        'docs/guides/completing-a-flow.md'    => [1 => self::CALL, 2 => self::WIRING, 3 => self::IMPLEMENTATION, 4 => self::CONFIGURATION],
        'docs/guides/completion-responses.md' => [1 => self::WIRING, 2 => self::IMPLEMENTATION],
        'docs/guides/configuration.md'        => [1 => self::BINDING, 2 => self::CONFIGURATION, 3 => self::BINDING],
        'docs/guides/connections.md'          => [1 => self::CONFIGURATION, 2 => self::BINDING, 3 => self::CALL, 4 => self::CALL],
        'docs/guides/discovery.md'            => [1 => self::CALL, 2 => self::CONFIGURATION, 3 => self::CALL],
        'docs/guides/domain-rechecks.md'      => [1 => self::WIRING, 2 => self::CALL, 3 => self::CALL],
        'docs/guides/domains.md'              => [1 => self::CALL, 2 => self::CALL, 3 => self::CALL, 4 => self::CALL, 5 => self::BINDING, 6 => self::CALL],
        'docs/guides/enforcement.md'          => [
            1 => self::CALL, 2 => self::CALL, 3 => self::CALL, 4 => self::CALL, 5 => self::BINDING, 6 => self::CALL, 7 => self::IMPLEMENTATION,
        ],
        'docs/guides/events.md'                       => [1 => self::CALL, 2 => self::SIBLING, 3 => self::SIBLING, 4 => self::CALL, 5 => self::CALL],
        'docs/guides/evidence.md'                     => [1 => self::BINDING, 2 => self::CALL, 3 => self::CALL, 4 => self::CALL],
        'docs/guides/freshness.md'                    => [1 => self::CONFIGURATION, 2 => self::IMPLEMENTATION, 3 => self::BINDING, 4 => self::CALL],
        'docs/guides/installation.md'                 => [1 => self::WIRING],
        'docs/guides/integrating-with-laravel-iam.md' => [1 => self::SIBLING, 2 => self::CALL, 3 => self::CALL],
        'docs/guides/keys.md'                         => [1 => self::CALL, 2 => self::CALL, 3 => self::CALL, 4 => self::CALL, 5 => self::CALL, 6 => self::CALL],
        'docs/guides/linking-by-domain.md'            => [1 => self::BINDING, 2 => self::CALL, 3 => self::CALL],
        'docs/guides/links.md'                        => [
            1 => self::BINDING, 2 => self::IMPLEMENTATION, 3 => self::CALL, 4 => self::CALL, 5 => self::IMPLEMENTATION, 6 => self::IMPLEMENTATION,
            7 => self::CALL,
        ],
        'docs/guides/localization.md'         => [1 => self::CALL, 2 => self::CONFIGURATION, 3 => self::CONFIGURATION],
        'docs/guides/logging.md'              => [1 => self::CONFIGURATION, 2 => self::CONFIGURATION, 3 => self::IMPLEMENTATION],
        'docs/guides/managing-connections.md' => [
            1 => self::CALL, 2 => self::CALL, 3 => self::CALL, 4 => self::CALL, 5 => self::CALL, 6 => self::CALL, 7 => self::CALL, 8 => self::CALL,
        ],
        'docs/guides/oidc-callback.md'       => [1 => self::WIRING, 2 => self::IMPLEMENTATION, 3 => self::CALL],
        'docs/guides/oidc-claims.md'         => [1 => self::CONFIGURATION, 2 => self::CALL, 3 => self::CALL],
        'docs/guides/oidc-connections.md'    => [1 => self::CALL, 2 => self::CALL],
        'docs/guides/oidc-id-tokens.md'      => [1 => self::CONFIGURATION, 2 => self::CONFIGURATION, 3 => self::CONFIGURATION],
        'docs/guides/oidc-sign-in.md'        => [1 => self::CALL, 2 => self::CALL],
        'docs/guides/operations.md'          => [1 => self::WIRING, 2 => self::CALL],
        'docs/guides/outbound-requests.md'   => [1 => self::CONFIGURATION, 2 => self::BINDING, 3 => self::BINDING, 4 => self::CALL],
        'docs/guides/provisioning.md'        => [1 => self::IMPLEMENTATION, 2 => self::CALL],
        'docs/guides/rate-limits.md'         => [1 => self::CONFIGURATION, 2 => self::WIRING, 3 => self::CALL, 4 => self::CALL],
        'docs/guides/reauthenticating.md'    => [1 => self::CALL, 2 => self::CALL, 3 => self::BINDING, 4 => self::IMPLEMENTATION, 5 => self::CALL],
        'docs/guides/redeeming-a-handoff.md' => [1 => self::CALL, 2 => self::IMPLEMENTATION, 3 => self::CALL, 4 => self::CALL],
        'docs/guides/saml-connections.md'    => [1 => self::CALL, 2 => self::CALL, 3 => self::CALL, 4 => self::CALL],
        'docs/guides/saml-metadata.md'       => [
            1 => self::CALL, 2 => self::CALL, 3 => self::CALL, 4 => self::CALL, 5 => self::WIRING, 6 => self::CONFIGURATION, 7 => self::CALL,
        ],
        'docs/guides/secrets.md'                   => [1 => self::BINDING, 2 => self::IMPLEMENTATION, 3 => self::CALL],
        'docs/guides/service-provider-metadata.md' => [1 => self::CALL, 2 => self::CALL, 3 => self::CALL],
        'docs/guides/single-use-store.md'          => [1 => self::CALL, 2 => self::WIRING, 3 => self::BINDING],
        'docs/guides/starting-a-flow.md'           => [1 => self::CALL, 2 => self::CALL, 3 => self::CALL],
    ];
}
