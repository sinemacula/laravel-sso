<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links\Enums;

/**
 * How a link came to be made (SSO-5.11, SSO-8.5, SSO-8.6, SSO-8.8): by a
 * redeemed `link` flow for an authenticated identity, by the provisioning grant
 * of an unlinked sign-in, or by a verified domain, activated at redemption.
 * Carried on the link-created event.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum LinkOrigin: string
{
    // A redeemed `link` flow, for the identity it was started for
    case LINK_PURPOSE = 'link_purpose';

    // The provisioning grant of an unlinked `sign_in` result
    case PROVISIONING = 'provisioning';

    // A verified domain, activated when its handoff was redeemed
    case VERIFIED_DOMAIN = 'verified_domain';

    // The subject migration of a trust change that alters what subjects mean,
    // relinking an existing link to its new subject
    case MIGRATION = 'migration';
}
