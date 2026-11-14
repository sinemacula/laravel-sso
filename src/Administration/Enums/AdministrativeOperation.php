<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Administration\Enums;

/**
 * An administrative operation of the package, by the name an application's
 * authorisation can grant it under.
 *
 * Values are stable names; never rename or reuse one. Which freshness each asks
 * is `FreshnessOperation`'s, not this.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AdministrativeOperation: string
{
    // Creating a connection
    case CONNECTION_CREATE = 'sso.connection.create';

    // Changing a connection's settings
    case CONNECTION_UPDATE = 'sso.connection.update';

    // Changing which provider evidence a connection accepts
    case CONNECTION_EVIDENCE = 'sso.connection.evidence';

    // Changing a connection's linking policy
    case CONNECTION_LINKING_POLICY = 'sso.connection.linking_policy';

    // Saving a connection from its provider's metadata
    case CONNECTION_IMPORT = 'sso.connection.import';

    // Changing a setting that decides what a connection trusts
    case CONNECTION_TRUST = 'sso.connection.trust';

    // Enabling a connection
    case CONNECTION_ENABLE = 'sso.connection.enable';

    // Disabling a connection
    case CONNECTION_DISABLE = 'sso.connection.disable';

    // Deleting a connection
    case CONNECTION_DELETE = 'sso.connection.delete';

    // Turning IdP-initiated sign-in on or off, or changing where it lands
    case CONNECTION_IDP_INITIATED = 'sso.connection.idp_initiated';

    // Changing a subject-defining setting, relinking or removing every link
    case CONNECTION_MIGRATE_SUBJECTS = 'sso.connection.migrate_subjects';

    // Refreshing a connection's metadata at once
    case CONNECTION_REFRESH_METADATA = 'sso.connection.refresh_metadata';

    // Adding, making current or retiring a service provider key
    case KEYS_ROTATE = 'sso.keys.rotate';

    // Trusting a provider certificate
    case KEYS_TRUST_CERTIFICATE = 'sso.keys.trust_certificate';

    // Withdrawing trust in a provider certificate
    case KEYS_DISTRUST_CERTIFICATE = 'sso.keys.distrust_certificate';

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

    // Removing one of the caller's own links
    case LINK_REMOVE = 'sso.link.remove';

    // Removing another identity's link
    case LINK_REMOVE_OTHERS = 'sso.link.remove_others';
}
