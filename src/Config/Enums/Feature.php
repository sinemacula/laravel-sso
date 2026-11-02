<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Enums;

/**
 * A feature the application switches in `sso.features`, each off until it does
 * (SSO-12.2), but for the scheduled refresh, which is on until it turns it off
 * (`isOnByDefault()`). The value is the switch's key under `sso.features`.
 *
 * A protocol is the package in use: with neither on, nothing else can run, and
 * the boot check has nothing to check but the switches. Every other feature
 * needs a protocol, and those that exist only in SAML need `saml2`, but for the
 * scheduled refresh, which simply has nothing to do without one; turning one on
 * enables what an application or a connection may then opt into, never the
 * opt-in itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Feature: string
{
    // Connections over SAML 2.0 (SSO-5.3, SSO-6)
    case SAML2 = 'saml2';

    // Connections over OpenID Connect (SSO-5.4, SSO-7)
    case OIDC = 'oidc';

    // Choosing a connection from an email domain, for the applications that
    // offer it (SSO-3.4, SSO-3.5)
    case DISCOVERY = 'discovery';

    // Tenants that require sign-in through their own connections (SSO-4)
    case ENFORCEMENT = 'enforcement';

    // SAML connections that require encrypted assertions (SSO-6.8)
    case ENCRYPTED_ASSERTIONS = 'encrypted_assertions';

    // Scheduled refresh of a connection's metadata or discovery document
    // (SSO-2.8); off stops the schedule, never the stale limit or an
    // administrator's refresh
    case METADATA_REFRESH = 'metadata_refresh';

    // Re-initiation of an unsolicited SAML response (SSO-5.8)
    case IDP_INITIATED = 'idp_initiated';

    // Linking an unlinked sign-in to an existing identity by a verified domain
    // (SSO-8.8)
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
     * Whether the feature is on when its switch is not set: only the scheduled
     * refresh, so a fetched resource goes on being refreshed before its stale
     * limit (SSO-2.8).
     *
     * @return bool
     */
    public function isOnByDefault(): bool
    {
        return $this === self::METADATA_REFRESH;
    }

    /**
     * The protocols of which at least one must be on for the feature to run:
     * none for a protocol or the scheduled refresh, which is on by default and
     * idle without one, `saml2` for a feature only SAML has, and either
     * protocol for every other.
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
