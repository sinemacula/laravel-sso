<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;

/**
 * The envelope and assertion provenance rules, checked in order with the first
 * broken one answering.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResponseRules
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why a successful response and its assertion are refused, or `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function refusal(SamlResponse $response, SamlAssertion $assertion, ValidationContext $context): ?FailureReason
    {
        return match (true) {
            !self::isResponseIssuer($response, $context)                 => FailureReason::ISSUER_MISMATCH,
            !$context->isIdentityProvider($assertion->issuer()->value()) => FailureReason::ISSUER_MISMATCH,
            !self::isDestination($response, $context)                    => FailureReason::RECIPIENT_MISMATCH,
            self::isPlainWhereEncryptionIsRequired($assertion, $context) => FailureReason::ENCRYPTION_REQUIRED,
            self::isUnsignedWhereSignatureIsWanted($assertion, $context) => FailureReason::SIGNATURE_INVALID,
            default                                                      => null,
        };
    }

    /**
     * Why an unsuccessful response's `Issuer` or `Destination` is refused.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function envelopeRefusal(SamlResponse $response, ValidationContext $context): ?FailureReason
    {
        return match (true) {
            !self::isResponseIssuer($response, $context) => FailureReason::ISSUER_MISMATCH,
            !self::isDestination($response, $context)    => FailureReason::RECIPIENT_MISMATCH,
            default                                      => null,
        };
    }

    /**
     * Whether the response names the identity provider as `Issuer`, signed or
     * not.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isResponseIssuer(SamlResponse $response, ValidationContext $context): bool
    {
        $issuer = $response->issuer();

        return $issuer !== null && $context->isIdentityProvider($issuer->value());
    }

    /**
     * Whether the response's `Destination` is present and exactly the assertion
     * consumer service, signed or not.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isDestination(SamlResponse $response, ValidationContext $context): bool
    {
        return $response->destination() === $context->assertionConsumerService;
    }

    /**
     * Whether a plain assertion arrived where encryption is required, which
     * would be a downgrade.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isPlainWhereEncryptionIsRequired(SamlAssertion $assertion, ValidationContext $context): bool
    {
        return $context->options->isOn(Saml2Setting::REQUIRE_ENCRYPTED_ASSERTIONS) && !$assertion->isEncrypted();
    }

    /**
     * Whether signed assertions are wanted and this one has no signature of its
     * own, even if the response's covers it.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isUnsignedWhereSignatureIsWanted(SamlAssertion $assertion, ValidationContext $context): bool
    {
        return $context->options->isOn(Saml2Setting::WANT_ASSERTIONS_SIGNED) && !$assertion->isSigned();
    }
}
