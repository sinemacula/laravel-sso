<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting\Enums;

/**
 * A flow the package limits (SSO-11.8), and the scopes each is counted in. The
 * value is the flow's key in `sso.rate_limits`. Every limit is always on: the
 * configuration sets how many attempts a window allows, never whether it is
 * counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AttemptFlow: string
{
    // Starting an authorisation request, by IP address and, for discovery, by
    // the email's domain
    case AUTHORIZATION_REQUEST = 'authorization_request';

    // A response at an assertion consumer service or a callback, by IP address
    // and by connection
    case COMPLETION = 'completion';

    // Redeeming a handoff code, by IP address
    case REDEMPTION = 'redemption';

    // Importing or refreshing a connection's metadata or discovery document, by
    // connection
    case METADATA = 'metadata';

    // Checking a domain's DNS record, by connection
    case DOMAIN_CHECK = 'domain_check';

    /**
     * The scopes the flow is counted in, each with a limit of its own under the
     * flow's key in `sso.rate_limits`.
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
