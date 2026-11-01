<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Every claim of one domain, of any connection, as `DomainFinder::claimsOf()`
 * read them, locked, under the claiming or verifying connection's lock: which
 * of them is the connection's own, and whether another connection holds the
 * domain verified (SSO-3.2).
 *
 * It is the helpers' working set only: another connection's claim never leaves
 * it, so no answer names or hints at another tenant.
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
     * Whether a connection other than the one given holds the domain verified,
     * including one whose grace period has run out but which has not yet been
     * marked lapsed, since it still holds the domain's one verification.
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
}
