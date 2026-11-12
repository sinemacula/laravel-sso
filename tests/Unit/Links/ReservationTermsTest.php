<?php

declare(strict_types = 1);

namespace Tests\Unit\Links;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\ReservationTerms;
use SineMacula\Laravel\Sso\Links\ReservedCandidate;
use SineMacula\Laravel\Sso\Models\Domain;
use Tests\Concerns\DumpsValues;
use Tests\TestCase;

/**
 * Unit tests for reservation terms and candidates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReservationTerms::class)]
#[CoversClass(ReservedCandidate::class)]
#[CoversClass(LinkReservations::class)]
final class ReservationTermsTest extends TestCase
{
    use DumpsValues;

    /** @var string The email the terms hold. */
    private const string EMAIL = 'Person@Example.COM';

    /** @var string The organisation the terms hold. */
    private const string ORGANIZATION = 'the-organisation-value';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Tq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /**
     * The terms hold what they are given, and the email exactly as asserted.
     *
     * @return void
     */
    public function testTheTermsHoldWhatTheyAreGiven(): void
    {
        $expires = CarbonImmutable::parse('2026-11-01T09:31:00Z');
        $terms   = new ReservationTerms(RequestReference::fromString(self::REFERENCE), self::EMAIL, self::ORGANIZATION, self::domain(), 4, $expires);

        self::assertSame(self::EMAIL, $terms->email());
        self::assertSame(self::REFERENCE, $terms->reference->value);
        self::assertSame(self::ORGANIZATION, $terms->organization());
        self::assertSame('domain-1', $terms->domainId);
        self::assertSame(3, $terms->domainGeneration);
        self::assertSame(4, $terms->linkingVersion);
        self::assertSame($expires, $terms->expiresAt);
    }

    /**
     * No dump or encoding shows the email or the organisation.
     *
     * @return void
     */
    public function testADumpNeverShowsTheEmailOrTheOrganisation(): void
    {
        $terms = self::terms();

        self::assertSame(['request_reference' => self::REFERENCE, 'domain_id' => 'domain-1', 'linking_version' => 4], $terms->__debugInfo());

        self::assertSame(
            ['request_reference' => self::REFERENCE, 'domain_id' => 'domain-1', 'linking_version' => 4, 'email' => '[redacted]', 'organization' => '[redacted]'],
            $terms->jsonSerialize(),
        );

        foreach ([...self::dumps($terms), 'json' => (string) json_encode($terms), 'array' => print_r((array) $terms, true)] as $form => $dump) {
            self::assertStringNotContainsString(self::EMAIL, $dump, $form);
            self::assertStringNotContainsString(self::ORGANIZATION, $dump, $form);
        }
    }

    /**
     * The terms refuse to be serialised, in those words.
     *
     * @return void
     */
    public function testTheTermsRefuseToBeSerialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A reservation\'s terms cannot be serialised.');

        serialize(self::terms());
    }

    /**
     * The terms refuse to be unserialised, in those words.
     *
     * @return void
     */
    public function testTheTermsRefuseToBeUnserialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A reservation\'s terms cannot be unserialised.');

        (new \ReflectionClass(ReservationTerms::class))->newInstanceWithoutConstructor()->__unserialize([]);
    }

    /**
     * A candidate holds opaque references and a time.
     *
     * @return void
     */
    public function testACandidateHoldsReferencesAndATime(): void
    {
        $identity  = new IdentityReference('App\Models\User', '7');
        $expires   = CarbonImmutable::parse('2026-11-01T09:31:00Z');
        $candidate = new ReservedCandidate('reservation-1', $identity, $expires);

        self::assertSame(['reservation-1', $identity, $expires], [$candidate->reservationId, $candidate->identity, $candidate->expiresAt]);
    }

    /**
     * The digest salts the exact email with the reservation's identity.
     *
     * @return void
     */
    public function testTheDigestSaltsTheEmailWithTheReservation(): void
    {
        $digest = LinkReservations::emailDigest('reservation-1', self::EMAIL);

        self::assertSame(hash('sha256', "sso-reservation-email-v1\0reservation-1\0" . self::EMAIL), $digest);
        self::assertNotSame($digest, LinkReservations::emailDigest('reservation-2', self::EMAIL));
        self::assertNotSame($digest, LinkReservations::emailDigest('reservation-1', strtolower(self::EMAIL)));
    }

    /**
     * Terms of the fixed values.
     *
     * @return \SineMacula\Laravel\Sso\Links\ReservationTerms
     */
    private static function terms(): ReservationTerms
    {
        $expires = CarbonImmutable::parse('2026-11-01T09:31:00Z');

        return new ReservationTerms(RequestReference::fromString(self::REFERENCE), self::EMAIL, self::ORGANIZATION, self::domain(), 4, $expires);
    }

    /**
     * A domain claim, not saved.
     *
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private static function domain(): Domain
    {
        return (new Domain)->forceFill(['id' => 'domain-1', 'verification_generation' => 3]);
    }
}
