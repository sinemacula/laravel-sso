<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * One hostile ID token of the adversarial suite (SSO-7.3, SSO-7.4, SSO-12.4):
 * the token, the JWKS the provider publishes beside it, the allow-list the
 * connection has, how far the package's JOSE adapter lets it go before it is
 * refused, and the failure reason a completion through the callback must end
 * with.
 *
 * The stages, in the order the adapter reaches them:
 *
 * - `malformed`: `CompactToken::parse()` refuses it;
 * - `jwks_refused`: the JWKS beside it is refused whole;
 * - `refused`: the key selection refuses it, with no refetch;
 * - `unknown`: no stored key is its key, so the JWKS is refetched once, and
 *   the refetched JWKS still holds none;
 * - `unverified`: the key chosen does not verify its signature;
 * - `expired`: its signature verifies, and its time claims fail.
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

        /** How far the adapter lets it go before it is refused. */
        public string $stage,

        /** The reason a completion through the callback must end with. */
        public FailureReason $reason,
    ) {}
}
