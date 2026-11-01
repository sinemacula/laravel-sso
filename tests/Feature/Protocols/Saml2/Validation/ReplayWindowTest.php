<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ReplayWindow;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for what a validated SAML assertion is recorded as against
 * replay (SSO-6.6): its id scoped by the connection and its issuer, in the
 * assertion namespace, until the earliest of the conditions' `NotOnOrAfter`,
 * the chosen confirmation's and the assertion's `IssueInstant` maximum age,
 * each with the skew, so the record never outlives the last moment a rule would
 * accept the assertion and never ends before it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReplayWindow::class)]
#[CoversClass(ValidationContext::class)]
final class ReplayWindowTest extends TestCase
{
    /** @var string The identity provider's entity id. */
    private const string IDP = 'https://idp.example.test/saml';

    /** @var string The connection's id. */
    private const string CONNECTION = '01jbexampleconnection00000';

    /**
     * The record is the assertion's id, scoped by the connection and the
     * assertion's issuer, in the assertion namespace.
     *
     * @return void
     */
    public function testRecordsTheAssertionIdScopedByConnectionAndIssuer(): void
    {
        $record = ReplayWindow::record(self::assertion(300, 0), self::confirmation(300), self::context());

        self::assertSame(ReplayRecord::SAML_ASSERTION, $record->namespace);
        self::assertSame('v1|26:' . self::CONNECTION . '|29:' . self::IDP . '|12:_assertion-1', $record->key());
        self::assertSame(ReplayRecord::samlAssertion(self::CONNECTION, self::IDP, '_assertion-1', $record->until)->key(), $record->key());
    }

    /**
     * Rows of `[conditions, confirmation, issued, until]`: the conditions' and
     * the confirmation's `NotOnOrAfter` and the assertion's `IssueInstant`, in
     * seconds from now, and the record's expiry, in seconds from now; the skew
     * is 60 seconds and the maximum age 300.
     *
     * @return iterable<string, array{0: ?int, 1: int, 2: int, 3: int}>
     */
    public static function provideExpiries(): iterable
    {
        yield from [
            'the conditions end first'              => [120, 240, 0, 180],
            'the confirmation ends first'           => [240, 120, 0, 180],
            'the maximum age ends first'            => [600, 600, 0, 360],
            'an older assertion, its age first'     => [600, 600, -200, 160],
            'no conditions, the confirmation first' => [null, 120, 0, 180],
            'no conditions, the age first'          => [null, 3600, -30, 330],
            'two bounds equal'                      => [120, 120, 0, 180],
            'all three equal'                       => [300, 300, 0, 360],
        ];
    }

    /**
     * The record expires at the earliest of the three bounds, each with the
     * skew.
     *
     * @param  ?int  $conditions
     * @param  int  $confirmation
     * @param  int  $issued
     * @param  int  $until
     * @return void
     */
    #[DataProvider('provideExpiries')]
    public function testExpiresAtTheLastMomentAnyRuleAccepts(?int $conditions, int $confirmation, int $issued, int $until): void
    {
        $record   = ReplayWindow::record(self::assertion($conditions, $issued), self::confirmation($confirmation), self::context());
        $computed = ReplayWindow::until(self::assertion($conditions, $issued), self::confirmation($confirmation), self::context());
        $expected = self::now()->addSeconds($until)->toIso8601String();

        self::assertSame([$expected, $expected], [$record->until->toIso8601String(), $computed->toIso8601String()]);
    }

    /**
     * The skew and the maximum age are the context's.
     *
     * @return void
     */
    public function testReadsTheSkewAndMaximumAgeFromTheContext(): void
    {
        $context = new ValidationContext(self::CONNECTION, self::saml2Options(), 'https://sp.example.test/saml/acs', 'https://sp.example.test/saml/metadata', self::now(), 0, 30);

        self::assertSame('2026-11-01T09:30:30+00:00', ReplayWindow::until(self::assertion(600, 0), self::confirmation(600), $context)->toIso8601String());
        self::assertSame('2026-11-01T09:30:10+00:00', ReplayWindow::until(self::assertion(10, 0), self::confirmation(600), $context)->toIso8601String());
    }

    /**
     * An assertion whose conditions end at the offset, or which has none,
     * issued at its own offset, both in seconds from now.
     *
     * @param  ?int  $notOnOrAfter
     * @param  int  $issued
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertion(?int $notOnOrAfter, int $issued): SamlAssertion
    {
        $conditions = $notOnOrAfter === null ? null : new SamlConditions(null, self::now()->addSeconds($notOnOrAfter));

        return new SamlAssertion('_assertion-1', new NameId(self::IDP), self::now()->addSeconds($issued), null, $conditions);
    }

    /**
     * A bearer confirmation ending at the offset, in seconds from now.
     *
     * @param  int  $notOnOrAfter
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation
     */
    private static function confirmation(int $notOnOrAfter): SubjectConfirmation
    {
        return new SubjectConfirmation(SubjectConfirmation::BEARER, true, null, self::now()->addSeconds($notOnOrAfter), 'https://sp.example.test/saml/acs', '_request-1');
    }

    /**
     * The context the record is made in: a skew of 60 seconds and a maximum age
     * of 300.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function context(): ValidationContext
    {
        return new ValidationContext(self::CONNECTION, self::saml2Options(), 'https://sp.example.test/saml/acs', 'https://sp.example.test/saml/metadata', self::now(), 60, 300);
    }

    /**
     * The connection's options.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options
     */
    private static function saml2Options(): Saml2Options
    {
        return Saml2Options::of(new ExampleConnection('saml2', ['idp_entity_id' => self::IDP]));
    }

    /**
     * The instant every bound is measured from.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function now(): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01T09:30:00Z');
    }
}
