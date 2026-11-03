<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use Tests\Integration\Examples\IntegratingWithLaravelIam\Contracts\ExternalIdentityLinks;

/**
 * The adapter's request-scoped record of the redemption it admitted, and its
 * answer to authentication's link contract
 * (`docs/guides/integrating-with-laravel-iam.md`): authentication asks which
 * link a connection, an issuer and a subject resolve to, and the adapter
 * answers with the link the admitted redemption resolved under the package's
 * locks, for that connection, issuer and subject alone, so a link removed and
 * made again since never stands in for it.
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
     * The link the admitted redemption resolved, when it is of the connection,
     * the issuer and the subject; otherwise none.
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
