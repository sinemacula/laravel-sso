<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlStatus;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ResponseRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for the rules of a SAML response's envelope and its
 * assertion's provenance (SSO-6.2, SSO-6.4, SSO-6.8): each issuer equal to the
 * identity provider's entity id exactly, the response's when present; the
 * `Destination` equal to the assertion consumer service and required of a
 * signed response; encryption required refusing a plain assertion; a wanted
 * assertion signature refusing one covered only by the response's; the
 * envelope's rules for an unsuccessful response; and the order they answer in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResponseRules::class)]
#[CoversClass(ValidationContext::class)]
final class ResponseRulesTest extends TestCase
{
    /** @var string The identity provider's entity id. */
    private const string IDP = 'https://idp.example.test/saml';

    /** @var string The service provider's entity id. */
    private const string SP = 'https://sp.example.test/saml/metadata';

    /** @var string The assertion consumer service. */
    private const string ACS = 'https://sp.example.test/saml/acs';

    /**
     * A signed response from the identity provider, to the assertion consumer
     * service, with a signed plain assertion from it, is accepted.
     *
     * @return void
     */
    public function testAcceptsAResponseThatHoldsEveryRule(): void
    {
        self::assertNull(ResponseRules::refusal(self::response(), self::assertion(), self::context()));
        self::assertNull(ResponseRules::envelopeRefusal(self::response(), self::context()));
    }

    /**
     * Rows of `[responseIssuer, assertionIssuer, reason]`: each issuer, `null`
     * for none, and the refusal.
     *
     * @return iterable<string, array{0: ?string, 1: string, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideIssuers(): iterable
    {
        yield from [
            'both the identity provider'          => [self::IDP, self::IDP, null],
            'no response issuer'                  => [null, self::IDP, null],
            'another response issuer'             => ['https://attacker.example.test', self::IDP, FailureReason::ISSUER_MISMATCH],
            'another assertion issuer'            => [self::IDP, 'https://attacker.example.test', FailureReason::ISSUER_MISMATCH],
            'an assertion issuer in another case' => [self::IDP, strtoupper(self::IDP), FailureReason::ISSUER_MISMATCH],
            'an assertion issuer with a space'    => [self::IDP, self::IDP . ' ', FailureReason::ISSUER_MISMATCH],
            'an empty response issuer'            => ['', self::IDP, FailureReason::ISSUER_MISMATCH],
        ];
    }

    /**
     * The response's issuer, when present, and the assertion's must each be the
     * identity provider's entity id exactly.
     *
     * @param  ?string  $responseIssuer
     * @param  string  $assertionIssuer
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideIssuers')]
    public function testEachIssuerMustBeTheIdentityProvider(?string $responseIssuer, string $assertionIssuer, ?FailureReason $reason): void
    {
        $response = self::response(['issuer' => $responseIssuer === null ? null : new NameId($responseIssuer)]);

        self::assertSame($reason, ResponseRules::refusal($response, self::assertion($assertionIssuer), self::context()));
    }

    /**
     * A connection that names no entity id matches no issuer, an empty one
     * included.
     *
     * @return void
     */
    public function testAConnectionWithNoEntityIdMatchesNoIssuer(): void
    {
        $context = self::context([], null);

        self::assertSame(FailureReason::ISSUER_MISMATCH, ResponseRules::refusal(self::response(['issuer' => null]), self::assertion(''), $context));
        self::assertSame(FailureReason::ISSUER_MISMATCH, ResponseRules::envelopeRefusal(self::response(['issuer' => new NameId('')]), $context));
        self::assertNull(ResponseRules::envelopeRefusal(self::response(['issuer' => null]), $context));
    }

    /**
     * Rows of `[destination, signed, reason]`: the response's `Destination`,
     * `null` for none, whether the response is signed, and the refusal.
     *
     * @return iterable<string, array{0: ?string, 1: bool, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideDestinations(): iterable
    {
        yield from [
            'the service, signed'               => [self::ACS, true, null],
            'the service, unsigned'             => [self::ACS, false, null],
            'none, unsigned'                    => [null, false, FailureReason::RECIPIENT_MISMATCH],
            'none, signed'                      => [null, true, FailureReason::RECIPIENT_MISMATCH],
            'empty, unsigned'                   => ['', false, FailureReason::RECIPIENT_MISMATCH],
            'another URL'                       => ['https://sp.example.test/other', false, FailureReason::RECIPIENT_MISMATCH],
            'another URL, signed'               => ['https://sp.example.test/other', true, FailureReason::RECIPIENT_MISMATCH],
            'the service with a trailing slash' => [self::ACS . '/', true, FailureReason::RECIPIENT_MISMATCH],
            'the service with a query'          => [self::ACS . '?x=1', true, FailureReason::RECIPIENT_MISMATCH],
            'the service in another case'       => [strtoupper(self::ACS), true, FailureReason::RECIPIENT_MISMATCH],
        ];
    }

    /**
     * The `Destination` must be present and the assertion consumer service
     * exactly, whether the response is signed or not; for an unsuccessful
     * response too.
     *
     * @param  ?string  $destination
     * @param  bool  $signed
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideDestinations')]
    public function testTheDestinationMustBeTheAssertionConsumerService(?string $destination, bool $signed, ?FailureReason $reason): void
    {
        $response = self::response(['destination' => $destination], $signed);

        self::assertSame($reason, ResponseRules::refusal($response, self::assertion(), self::context()));
        self::assertSame($reason, ResponseRules::envelopeRefusal($response, self::context()));
    }

    /**
     * A connection that requires encrypted assertions refuses a plain one, and
     * accepts an encrypted one; one that does not accepts either.
     *
     * @return void
     */
    public function testRequiredEncryptionRefusesAPlainAssertion(): void
    {
        $required = self::context(['require_encrypted_assertions' => true]);

        self::assertSame(FailureReason::ENCRYPTION_REQUIRED, ResponseRules::refusal(self::response(), self::assertion(), $required));
        self::assertNull(ResponseRules::refusal(self::response(), self::assertion(self::IDP, ['signed' => true, 'encrypted' => true]), $required));
        self::assertNull(ResponseRules::refusal(self::response(), self::assertion(self::IDP, ['signed' => true, 'encrypted' => true]), self::context()));
    }

    /**
     * A connection that wants assertions signed, as by default, refuses one
     * covered only by the response's signature; one that does not accepts it.
     *
     * @return void
     */
    public function testAWantedAssertionSignatureRefusesOneCoveredOnlyByTheResponse(): void
    {
        $unsigned = self::assertion(self::IDP, []);

        self::assertSame(FailureReason::SIGNATURE_INVALID, ResponseRules::refusal(self::response(), $unsigned, self::context()));
        self::assertSame(FailureReason::SIGNATURE_INVALID, ResponseRules::refusal(self::response(), $unsigned, self::context(['want_assertions_signed' => true])));
        self::assertNull(ResponseRules::refusal(self::response(), $unsigned, self::context(['want_assertions_signed' => false])));
    }

    /**
     * The rules answer in their order: the response's issuer, the assertion's,
     * the destination, encryption, then the assertion's signature.
     *
     * @return void
     */
    public function testAnswersInItsOrder(): void
    {
        $required    = self::context(['require_encrypted_assertions' => true]);
        $other       = new NameId('https://attacker.example.test');
        $plain       = self::assertion('https://attacker.example.test', []);
        $elsewhere   = ['destination' => 'https://sp.example.test/other'];
        $assertionOk = self::assertion(self::IDP, []);

        self::assertSame(FailureReason::ISSUER_MISMATCH, ResponseRules::refusal(self::response(['issuer' => $other, ...$elsewhere]), $plain, $required));
        self::assertSame(FailureReason::ISSUER_MISMATCH, ResponseRules::refusal(self::response($elsewhere), $plain, $required));
        self::assertSame(FailureReason::RECIPIENT_MISMATCH, ResponseRules::refusal(self::response($elsewhere), $assertionOk, $required));
        self::assertSame(FailureReason::ENCRYPTION_REQUIRED, ResponseRules::refusal(self::response(), $assertionOk, $required));
        self::assertSame(FailureReason::ISSUER_MISMATCH, ResponseRules::envelopeRefusal(self::response(['issuer' => $other, ...$elsewhere]), self::context()));
    }

    /**
     * A successful, solicited response with the envelope given over the
     * defaults (the identity provider's issuer, the assertion consumer service
     * as destination), signed or not.
     *
     * @param  array<string, mixed>  $envelope
     * @param  bool  $signed
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse
     */
    private static function response(array $envelope = [], bool $signed = true): SamlResponse
    {
        /** @var array{issuer?: ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId, destination?: ?string, in_response_to?: ?string} $values */
        $values = [...['issuer' => new NameId(self::IDP), 'destination' => self::ACS], ...$envelope];

        return new SamlResponse(ValidationProfile::SOLICITED, '_response-1', self::now(), new SamlStatus(SamlStatus::SUCCESS), $values, $signed);
    }

    /**
     * An assertion from the issuer, with the provenance given (its own
     * signature verified, plain, by default).
     *
     * @param  string  $issuer
     * @param  array{signed?: bool, encrypted?: bool}  $facts
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertion(string $issuer = self::IDP, array $facts = ['signed' => true]): SamlAssertion
    {
        return new SamlAssertion('_assertion-1', new NameId($issuer), self::now(), facts: $facts);
    }

    /**
     * The context the rules are judged in, for a connection with the settings
     * given and the entity id.
     *
     * @param  array<string, mixed>  $settings
     * @param  ?string  $entityId
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function context(array $settings = [], ?string $entityId = self::IDP): ValidationContext
    {
        $options = Saml2Options::of(new ExampleConnection('saml2', [...$settings, 'idp_entity_id' => $entityId]));

        return new ValidationContext('01jbexampleconnection00000', $options, self::ACS, self::SP, self::now(), 60, 300);
    }

    /**
     * The instant every rule is judged at.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function now(): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01T09:30:00Z');
    }
}
