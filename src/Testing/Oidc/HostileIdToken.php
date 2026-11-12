<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * One case of the hostile ID token suite: the token, its JWKS and allow-list,
 * the adapter stage that refuses it and the expected failure reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HostileIdToken
{
    /**
     * Constructor.
     *
     * @param  string  $token
     * @param  array{keys: list<array<string, mixed>>}  $jwks
     * @param  list<string>  $algorithms
     * @param  string  $stage
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    public function __construct(

        /** The token, as the token endpoint answers it. */
        public string $token,

        /** The JWKS the provider publishes beside it. */
        public array $jwks,

        /** The connection's ID token algorithm allow-list. */
        public array $algorithms,

        /** The refusing stage: malformed, jwks_refused, refused, unknown, unverified or claims. */
        public string $stage,

        /** The reason a completion through the callback must end with. */
        public FailureReason $reason,
    ) {}
}
