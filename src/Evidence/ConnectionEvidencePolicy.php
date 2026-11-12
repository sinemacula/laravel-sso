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
 * Accepts provider-asserted evidence by each connection's own evidence policy.
 *
 * Bind it with `scoped`; the default contract is `InsufficientEvidence`.
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
     * The evidence the result's own assertion gives, or `null` when
     * insufficient.
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
     * Whether the result is not a `link` and matches the connection's id,
     * tenant and protocol.
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
     * Whether the authentication is within the clamped maximum age and the
     * clock skew; both bounds inclusive.
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
