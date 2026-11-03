<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SingleUseStore;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The example application's invitations (SSO-11.5): each token it has sent,
 * with the instant the invitation closes. An invitation is open until then, by
 * the package's clock, so the single-use store, which judges an expiry by the
 * same clock, is never handed one already past.
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
     * The instant the invitation with the token closes, or `null` when no
     * invitation has the token or it has closed.
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
