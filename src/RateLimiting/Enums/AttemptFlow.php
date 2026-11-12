<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting\Enums;

/**
 * A rate-limited flow, keyed in `sso.rate_limits`; its limits cannot be turned
 * off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AttemptFlow: string
{
    // Starting an authorisation request
    case AUTHORIZATION_REQUEST = 'authorization_request';

    // A response at an assertion consumer service or a callback
    case COMPLETION = 'completion';

    // Redeeming a handoff code
    case REDEMPTION = 'redemption';

    // Importing or refreshing metadata or a discovery document
    case METADATA = 'metadata';

    // Checking a domain's DNS record
    case DOMAIN_CHECK = 'domain_check';

    /**
     * The scopes the flow is counted in, each with its own limit.
     *
     * @return non-empty-list<\SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope>
     */
    public function scopes(): array
    {
        return match ($this) {
            self::AUTHORIZATION_REQUEST        => [AttemptScope::PER_IP, AttemptScope::PER_EMAIL_DOMAIN],
            self::COMPLETION                   => [AttemptScope::PER_IP, AttemptScope::PER_CONNECTION],
            self::REDEMPTION                   => [AttemptScope::PER_IP],
            self::METADATA, self::DOMAIN_CHECK => [AttemptScope::PER_CONNECTION],
        };
    }
}
