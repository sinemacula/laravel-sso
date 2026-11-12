<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Enums;

/**
 * A feature switch under `sso.features`, keyed by its value.
 *
 * Turning a feature on allows an application or connection to opt in; it never
 * opts in itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Feature: string
{
    // Connections over SAML 2.0
    case SAML2 = 'saml2';

    // Connections over OpenID Connect
    case OIDC = 'oidc';

    // Choosing a connection from an email domain
    case DISCOVERY = 'discovery';

    // Tenants that require sign-in through their own connections
    case ENFORCEMENT = 'enforcement';

    // SAML connections that require encrypted assertions
    case ENCRYPTED_ASSERTIONS = 'encrypted_assertions';

    // Scheduled metadata refresh; off never stops the stale limit
    case METADATA_REFRESH = 'metadata_refresh';

    // Re-initiation of an unsolicited SAML response
    case IDP_INITIATED = 'idp_initiated';

    // Linking an unlinked sign-in to an identity by a verified domain
    case DOMAIN_LINKING = 'domain_linking';

    /**
     * The configuration key of the feature's switch.
     *
     * @return string
     */
    public function key(): string
    {
        return 'sso.features.' . $this->value;
    }

    /**
     * Whether the feature is a protocol.
     *
     * @return bool
     */
    public function isProtocol(): bool
    {
        return $this === self::SAML2 || $this === self::OIDC;
    }

    /**
     * Only the scheduled refresh is on by default, so fetched resources keep
     * refreshing before their stale limit.
     *
     * @return bool
     */
    public function isOnByDefault(): bool
    {
        return $this === self::METADATA_REFRESH;
    }

    /**
     * The protocols of which one must be on; none for the scheduled refresh,
     * which is merely idle without one.
     *
     * @return list<self>
     */
    public function needs(): array
    {
        return match ($this) {
            self::SAML2, self::OIDC, self::METADATA_REFRESH => [],
            self::ENCRYPTED_ASSERTIONS, self::IDP_INITIATED => [self::SAML2],
            default                                         => [self::SAML2, self::OIDC],
        };
    }
}
