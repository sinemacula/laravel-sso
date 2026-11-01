<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Results;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Verified results and claims for tests: a full result with every part set, and
 * a bare one, each for the purpose and connection given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExampleResults
{
    /** @var string The reference every example result carries. */
    public const string REFERENCE = 'ref0ref1ref2ref3ref4ref5ref6ref7';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A result with every part set: a SAML subject with its format, mapped
     * attributes, an authentication context and a linking email.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    public static function full(Purpose $purpose = Purpose::SIGN_IN, string $connectionId = '01jbexampleconnection00000', string $subject = 'Subject 1 '): VerifiedResult
    {
        return new VerifiedResult(
            issuer: 'https://idp.example.com',
            subject: $subject,
            nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            connectionId: $connectionId,
            tenantId: 'tenant-1',
            protocol: 'saml2',
            application: 'web',
            purpose: $purpose,
            requestReference: RequestReference::fromString(self::REFERENCE),
            attributes: ['email' => 'person@example.com', 'groups' => ['staff', 'admins']],
            emailDomainVerified: true,
            authenticationContext: self::context(),
            linkingEmail: new LinkingEmail('person@example.com', LinkingEmailSource::SAML_ATTRIBUTE, 'example.com'),
        );
    }

    /**
     * A result with only what every result has: an OIDC subject, no attributes,
     * no context and no linking email.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    public static function bare(Purpose $purpose = Purpose::SIGN_IN, string $connectionId = '01jbexampleconnection00000'): VerifiedResult
    {
        return new VerifiedResult(
            'https://op.example.com',
            'sub-1',
            null,
            $connectionId,
            'tenant-1',
            'oidc',
            'web',
            $purpose,
            RequestReference::fromString(self::REFERENCE),
            [],
            false,
            new AuthenticationContext,
        );
    }

    /**
     * Claims a driver verified, with every part set.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    public static function claims(): VerifiedClaims
    {
        return new VerifiedClaims(
            'https://idp.example.com',
            'Subject 1 ',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            ['mail' => ['person@example.com'], 'memberOf' => ['staff']],
            self::context(),
        );
    }

    /**
     * An authentication context with every part set.
     *
     * @return \SineMacula\Laravel\Sso\Results\AuthenticationContext
     */
    public static function context(): AuthenticationContext
    {
        return new AuthenticationContext(
            CarbonImmutable::parse('2026-11-01T10:00:00.123456Z'),
            ['pwd', 'otp'],
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            'session-index-1',
            CarbonImmutable::parse('2026-11-01T18:00:00Z'),
        );
    }
}
