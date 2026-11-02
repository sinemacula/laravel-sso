<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Evidence;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Clock\ClockSkew;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Linking\LinkingSettings;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The evidence contract an application binds to accept what its connections'
 * identity providers assert (SSO-8.7, SSO-9.5): the default stays
 * `InsufficientEvidence`. Each result is judged at redemption, by the policy
 * the connection holds now (`EvidenceRules`,
 * `Contracts\SsoConnection::getEvidencePolicy()`), from the result's own
 * `AuthenticationContext` and nothing else.
 *
 * It answers `null`, never a pass, for:
 *
 * - a `link` result, which proves nothing, though the redemption never asks;
 * - a result of another connection, tenant or protocol than the connection's;
 * - no authentication time;
 * - a policy that is empty or malformed;
 * - an authentication time older than the maximum age at the instant asked: the
 *   ceiling `sso.linking.evidence_max_age_seconds`, or the policy's own tighter
 *   `max_age_seconds`, clamped to the ceiling as it is now, so lowering the
 *   ceiling later still wins; or later than that instant by more than the clock
 *   skew. Each bound is itself accepted. A code's short lifetime establishes
 *   nothing, so a code redeemed later than the maximum age, though unexpired,
 *   has none;
 * - a context that satisfies no combination.
 *
 * Otherwise it answers `AcceptedEvidence`: the connection's id as the
 * credential reference, the provider's authentication time, only the accepted
 * RFC 8176 methods, and the raw `acr` or `AuthnContextClassRef`, whether listed
 * or not, as data through `rawContext()`, which is no accepted class. It is an
 * input to the application's policy for further factors and never an assurance
 * level, and which factors combine stays the application's.
 *
 * It never logs or reports a value. A configuration out of its bounds is an
 * `InvalidArgumentException`, and any other error propagates. It keeps nothing
 * of one call for the next (SSO-11.2) and reads the settings on each call. Bind
 * it with `scoped`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConnectionEvidencePolicy implements EvidencePolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkingSettings  $settings
     */
    public function __construct(

        /** The evidence's maximum age. */
        private LinkingSettings $settings,
    ) {}

    /**
     * The evidence the result's own assertion gives at the instant, or `null`
     * when what it gives is insufficient.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
    {
        $context         = $result->authenticationContext;
        $authenticatedAt = self::isOwn($result, $connection) ? $context->authenticatedAt : null;
        $rules           = EvidenceRules::parse($connection->getEvidencePolicy(), $connection->getProtocol());

        if ($authenticatedAt === null || $rules === null || !$this->isCurrent($authenticatedAt, $now, $rules)) {
            return null;
        }

        $methods = $rules->acceptedMethods($context);

        return $methods === null ? null : new AcceptedEvidence($connection->getConnectionId(), $authenticatedAt, $methods, $context->contextClass);
    }

    /**
     * Whether the result is one evidence can be accepted of, on this
     * connection: not a `link`, and of exactly its id, tenant and protocol.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     */
    private static function isOwn(VerifiedResult $result, SsoConnection $connection): bool
    {
        $names = [$connection->getConnectionId(), $connection->getTenantId(), $connection->getProtocol()];

        return $result->purpose !== Purpose::LINK && [$result->connectionId, $result->tenantId, $result->protocol] === $names;
    }

    /**
     * Whether the authentication is no older than the policy's maximum age at
     * the instant, clamped to the ceiling as it is now, and no later than it by
     * more than the clock skew.
     *
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Sso\Evidence\EvidenceRules  $rules
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isCurrent(CarbonImmutable $authenticatedAt, CarbonImmutable $now, EvidenceRules $rules): bool
    {
        $oldest = $now->subSeconds($rules->maxAgeSeconds($this->settings->evidenceMaxAgeSeconds()));
        $latest = $now->addSeconds(ClockSkew::seconds());

        return $authenticatedAt >= $oldest && $authenticatedAt <= $latest;
    }
}
