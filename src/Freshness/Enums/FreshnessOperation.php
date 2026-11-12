<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness\Enums;

/**
 * An operation that must ask the freshness contract before it writes.
 *
 * Values are stable names adapters may key on; never rename or reuse one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FreshnessOperation: string
{
    // Creating a connection, or changing a setting that decides what it trusts
    case CONNECTION_TRUST = 'sso.connection.trust';

    // Enabling a connection
    case CONNECTION_ENABLE = 'sso.connection.enable';

    // Disabling a connection
    case CONNECTION_DISABLE = 'sso.connection.disable';

    // Deleting a connection
    case CONNECTION_DELETE = 'sso.connection.delete';

    // Turning IdP-initiated sign-in on or off, or changing where it lands
    case CONNECTION_IDP_INITIATED = 'sso.connection.idp_initiated';

    // Adding, making current or retiring a service provider key
    case KEYS_ROTATE = 'sso.keys.rotate';

    // Claiming a domain for a connection
    case DOMAIN_CLAIM = 'sso.domain.claim';

    // Verifying a claimed domain
    case DOMAIN_VERIFY = 'sso.domain.verify';

    // Removing a domain from a connection
    case DOMAIN_REMOVE = 'sso.domain.remove';

    // Turning enforcement on or off, or changing which connections satisfy it
    case ENFORCEMENT_UPDATE = 'sso.enforcement.update';

    // Starting a `link` flow for an authenticated identity
    case LINK_CREATE = 'sso.link.create';

    // Removing a link
    case LINK_REMOVE = 'sso.link.remove';

    /**
     * The key under `sso.freshness.max_age_seconds`, e.g. `connection_trust`.
     *
     * @return string
     */
    public function configKey(): string
    {
        return str_replace('.', '_', substr($this->value, strlen('sso.')));
    }
}
