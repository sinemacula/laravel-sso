<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting\Enums;

/**
 * What an attempt is counted against (SSO-11.8). The value is the limit's key
 * under its flow in `sso.rate_limits`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AttemptScope: string
{
    // The client's IP address
    case PER_IP = 'per_ip';

    // The domain of the email an authorisation request gave for discovery
    case PER_EMAIL_DOMAIN = 'per_email_domain';

    // The connection the attempt was made through
    case PER_CONNECTION = 'per_connection';
}
