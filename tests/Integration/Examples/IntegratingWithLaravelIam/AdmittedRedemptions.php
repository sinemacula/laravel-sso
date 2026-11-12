<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Integration\Examples\IntegratingWithLaravelIam\Contracts\ExternalIdentityLinks;

/**
 * The adapter's answer to authentication's link contract, from the admitted
 * redemption, so a link removed and made again never stands in for it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AdmittedRedemptions implements ExternalIdentityLinks
{
    /** @var ?\SineMacula\Laravel\Sso\Handoffs\RedemptionResult The redemption admitted in this request, if any. */
    private ?RedemptionResult $admitted = null;

    /**
     * Record the redemption just admitted.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $redemption
     * @return void
     */
    public function record(RedemptionResult $redemption): void
    {
        $this->admitted = $redemption;
    }

    /**
     * The admitted redemption's link, when it matches the connection, issuer
     * and subject.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return ?string
     */
    #[\Override]
    public function find(string $connectionId, string $issuer, string $subject): ?string
    {
        $result = $this->admitted?->result;

        if ($result === null || [$result->connectionId, $result->issuer, $result->subject] !== [$connectionId, $issuer, $subject]) {
            return null;
        }

        return $this->admitted->linkId;
    }
}
