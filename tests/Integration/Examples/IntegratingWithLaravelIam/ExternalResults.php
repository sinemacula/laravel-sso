<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

/**
 * The adapter's builder of authentication's external result
 * (`docs/guides/integrating-with-laravel-iam.md`), from the admitted redemption
 * alone, never from anything the client sent: the connection, issuer and
 * subject of its verified result, the connection's tenant, the provider's
 * authentication time, the effective session deadline, the enforcement version
 * the redemption judged under its locks, the evidence the evidence contract
 * accepted, the link it resolved, the request's public reference, and the
 * package's captured provenance in its stored form as the provider context, so
 * authentication keeps it with the session and the `sso` contributor projects
 * it from there.
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
