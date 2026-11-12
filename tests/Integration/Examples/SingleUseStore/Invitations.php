<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SingleUseStore;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The application's invitations, judged by the package's clock so the store is
 * never handed an expiry already past.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Invitations
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  array<string, \Carbon\CarbonImmutable>  $closesAt
     */
    public function __construct(

        /** The clock an invitation's closing is judged against. */
        private Clock $clock,

        /** The instant each invitation closes, by its token. */
        private array $closesAt,
    ) {}

    /**
     * When the token's invitation closes, or `null` if unknown or closed.
     *
     * @param  string  $token
     * @return ?\Carbon\CarbonImmutable
     */
    public function openUntil(#[\SensitiveParameter] string $token): ?CarbonImmutable
    {
        $closesAt = $this->closesAt[$token] ?? null;

        return $closesAt !== null && $closesAt > $this->clock->now() ? $closesAt : null;
    }
}
