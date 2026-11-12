<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * One of the application's own handoff codes as its store reads it back,
 * without the code itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OwnHandoffCode
{
    /**
     * Hold what the issuer was given in its grant.
     *
     * @param  string  $reference
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Flows\S256Challenge  $challenge
     * @param  int  $expiresAt
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @param  ?string  $reservationId
     * @param  ?int  $trustVersion
     * @param  ?\Carbon\CarbonImmutable  $sessionNotAfter
     */
    public function __construct(

        /** The code's opaque reference, which its issuer answered. */
        public string $reference,

        /** The verified result the code carries. */
        public VerifiedResult $result,

        /** The S256 challenge of the verifier the code is redeemed with. */
        public S256Challenge $challenge,

        /** When the code expires, in seconds since the epoch. */
        public int $expiresAt,

        /** The identity the result's link resolved to at completion, if any. */
        public ?IdentityReference $linkedIdentity = null,

        /** The link observed at completion, active or suspended, if any. */
        public ?string $linkId = null,

        /** The identity a `link` or `reauthenticate` flow was started for. */
        public ?IdentityReference $identity = null,

        /** The session a `reauthenticate` flow was started on. */
        public ?string $sessionId = null,

        /** The reservation the code holds, if any. */
        public ?string $reservationId = null,

        /** The connection's trust version the code was issued under. */
        public ?int $trustVersion = null,

        /** The latest end of the session the code may establish, if any. */
        public ?CarbonImmutable $sessionNotAfter = null,
    ) {}

    /**
     * Whether the verifier matches the challenge the flow was started with.
     *
     * @param  string  $verifier
     * @return bool
     */
    public function isVerifiedBy(#[\SensitiveParameter] string $verifier): bool
    {
        return Verifier::isWellFormed($verifier) && $this->challenge->isSatisfiedBy(Verifier::fromString($verifier));
    }
}
