<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;

/**
 * The replay record of a validated SAML assertion, held until the last moment
 * any rule would accept it. Bounds come only from inside the signed assertion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReplayWindow
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The replay record of the assertion accepted by the confirmation.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation  $confirmation
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return \SineMacula\Laravel\Sso\Protocols\ReplayRecord
     *
     * @throws \InvalidArgumentException
     */
    public static function record(SamlAssertion $assertion, SubjectConfirmation $confirmation, ValidationContext $context): ReplayRecord
    {
        return ReplayRecord::samlAssertion($context->connectionId, $assertion->issuer()->value(), $assertion->id(), self::until($assertion, $confirmation, $context));
    }

    /**
     * The earliest skewed bound, to the microsecond, so the record never ends
     * before a rule stops accepting.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation  $confirmation
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return \Carbon\CarbonImmutable
     */
    public static function until(SamlAssertion $assertion, SubjectConfirmation $confirmation, ValidationContext $context): CarbonImmutable
    {
        $until = $context->freshUntil($assertion->issueInstant());

        foreach ([$assertion->conditions()?->notOnOrAfter(), $confirmation->notOnOrAfter()] as $notOnOrAfter) {

            if ($notOnOrAfter === null) {
                continue;
            }

            $until = $until->min($context->skewed($notOnOrAfter));
        }

        return $until;
    }
}
