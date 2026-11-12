<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Every claim of one domain, of any connection, as `DomainFinder::claimsOf()`
 * read them.
 *
 * Another connection's claim never leaves it, so no answer hints at another
 * tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DomainClaims
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Domain>  $claims
     */
    public function __construct(

        /** Every claim of the domain, in id order. */
        private array $claims,
    ) {}

    /**
     * The connection's own claim of the domain, or `null`.
     *
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Domain
     */
    public function of(string $connectionId): ?Domain
    {
        foreach ($this->claims as $claim) {
            if ($claim->connection_id === $connectionId) {
                return $claim;
            }
        }

        return null;
    }

    /**
     * Whether another connection holds the domain verified, even past its grace
     * period but not yet marked lapsed.
     *
     * @param  string  $connectionId
     * @return bool
     */
    public function isVerifiedOtherThan(string $connectionId): bool
    {
        foreach ($this->claims as $claim) {
            if ($claim->connection_id !== $connectionId && $claim->state === DomainState::VERIFIED) {
                return true;
            }
        }

        return false;
    }

    /**
     * The one claim that routes discovery for the domain at the instant, or
     * `null`.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Sso\Models\Domain
     */
    public function routing(CarbonImmutable $now): ?Domain
    {
        foreach ($this->claims as $claim) {
            if (DomainStanding::routes($claim, $now)) {
                return $claim;
            }
        }

        return null;
    }
}
