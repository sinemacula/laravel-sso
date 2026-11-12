<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

/**
 * Builds authentication's external result from the admitted redemption alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExternalResults
{
    /**
     * Authentication's external result of the admitted redemption.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return \Tests\Integration\Examples\IntegratingWithLaravelIam\ExternalResult
     *
     * @throws \LogicException
     */
    public static function from(RedemptionResult $redemption): ExternalResult
    {
        $result = $redemption->result ?? throw new \LogicException('Only a redeemed sign-in carries a verified result.');

        return new ExternalResult(
            connectionId: $result->connectionId,
            issuer: $result->issuer,
            subject: $result->subject,
            tenantId: $result->tenantId,
            authenticatedAt: $result->authenticationContext->authenticatedAt,
            sessionNotAfter: $redemption->sessionNotAfter,
            policyVersion: $redemption->enforcementVersion,
            evidenceMethods: $redemption->evidence?->methods() ?? [],
            linkId: $redemption->linkId,
            requestReference: $result->requestReference->value,
            providerContext: $redemption->provenance?->toArray(),
        );
    }
}
