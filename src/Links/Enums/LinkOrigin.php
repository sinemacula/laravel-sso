<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links\Enums;

/**
 * How a link came to be made, as `Events\LinkCreated` carries it.
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

    // A subject migration relinking an existing link to its new subject
    case MIGRATION = 'migration';
}
