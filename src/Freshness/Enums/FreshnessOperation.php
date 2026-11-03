<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness\Enums;

/**
 * An operation that could widen or redirect access, or destroy it, and so asks
 * the freshness contract before it writes (SSO-2.12). The value is the
 * operation's stable name, the one the contract is asked with and the one an
 * adapter passes on to the freshness check of the application's authentication.
 *
 * The names are stable once released: a value is never renamed or reused. Each
 * operation has its own maximum age of the caller's authentication, configured
 * under `sso.freshness.max_age_seconds` by the key `configKey()` gives.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FreshnessOperation: string
{
    // Creating a connection, or changing its trusted certificates, issuer or
    // entity id, endpoints, client id or secret, its subject settings or what
    // decides whether a signature or an algorithm is accepted (SSO-2.13)
    case CONNECTION_TRUST = 'sso.connection.trust';

    // Enabling a connection (SSO-2.1, SSO-2.11)
    case CONNECTION_ENABLE = 'sso.connection.enable';

    // Disabling a connection (SSO-2.1, SSO-2.11)
    case CONNECTION_DISABLE = 'sso.connection.disable';

    // Deleting a connection (SSO-2.1, SSO-2.11)
    case CONNECTION_DELETE = 'sso.connection.delete';

    // Turning IdP-initiated sign-in on or off, or changing where it sends the
    // browser (SSO-5.8)
    case CONNECTION_IDP_INITIATED = 'sso.connection.idp_initiated';

    // Adding, making current or retiring a service provider key and its
    // certificate (SSO-2.7)
    case KEYS_ROTATE = 'sso.keys.rotate';

    // Claiming a domain for a connection (SSO-3.1)
    case DOMAIN_CLAIM = 'sso.domain.claim';

    // Verifying a claimed domain (SSO-3.2)
    case DOMAIN_VERIFY = 'sso.domain.verify';

    // Removing a domain from a connection (SSO-3)
    case DOMAIN_REMOVE = 'sso.domain.remove';

    // Turning enforcement on or off, or changing which connections satisfy it
    // (SSO-4.5)
    case ENFORCEMENT_UPDATE = 'sso.enforcement.update';

    // Starting a `link` flow for an authenticated identity (SSO-5.11)
    case LINK_CREATE = 'sso.link.create';

    // Removing a link (SSO-8.4)
    case LINK_REMOVE = 'sso.link.remove';

    /**
     * The key of the operation's maximum age under
     * `sso.freshness.max_age_seconds`: its name after `sso.`, with the dots as
     * underscores (`connection_trust`).
     *
     * @return string
     */
    public function configKey(): string
    {
        return str_replace('.', '_', substr($this->value, strlen('sso.')));
    }
}
