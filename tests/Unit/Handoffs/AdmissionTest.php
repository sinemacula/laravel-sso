<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Pins the frozen shape of what a redemption's checks and writes came to:
 * exactly these four parts, in this order; a refusal carries its outcome and
 * nothing else, and only `passed` counts as passed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Admission::class)]
final class AdmissionTest extends TestCase
{
    /**
     * Every part is kept, under its own name and in its own place.
     *
     * @return void
     */
    public function testKeepsEveryPartInItsPlace(): void
    {
        $identity  = new IdentityReference('user', '1');
        $evidence  = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd']);
        $admission = new Admission(RecheckOutcome::PASSED, $identity, 'link-1', $evidence);

        self::assertSame([
            'outcome'  => RecheckOutcome::PASSED,
            'identity' => $identity,
            'linkId'   => 'link-1',
            'evidence' => $evidence,
        ], get_object_vars($admission));
    }

    /**
     * What it passed with defaults to nothing, as an unlinked handoff's does.
     *
     * @return void
     */
    public function testEverythingButTheOutcomeDefaultsToNull(): void
    {
        self::assertSame([
            'outcome'  => RecheckOutcome::PASSED,
            'identity' => null,
            'linkId'   => null,
            'evidence' => null,
        ], get_object_vars(new Admission(RecheckOutcome::PASSED)));
    }

    /**
     * Only `passed` counts as passed, whatever else it carries.
     *
     * @return void
     */
    public function testPassedCountsAsPassed(): void
    {
        self::assertTrue((new Admission(RecheckOutcome::PASSED))->isPassed());
        self::assertTrue((new Admission(RecheckOutcome::PASSED, new IdentityReference('user', '1'), 'link-1'))->isPassed());
    }

    /**
     * Every outcome but `passed`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome}>
     */
    public static function refusals(): iterable
    {
        foreach (RecheckOutcome::cases() as $outcome) {

            if ($outcome === RecheckOutcome::PASSED) {
                continue;
            }

            yield $outcome->value => [$outcome];
        }
    }

    /**
     * A refusal carries its outcome and nothing else, and is not passed.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $outcome
     * @return void
     */
    #[DataProvider('refusals')]
    public function testARefusalCarriesOnlyItsOutcome(RecheckOutcome $outcome): void
    {
        $admission = Admission::refused($outcome);

        self::assertSame(['outcome' => $outcome, 'identity' => null, 'linkId' => null, 'evidence' => null], get_object_vars($admission));
        self::assertFalse($admission->isPassed());
    }

    /**
     * An outcome that refuses is not passed even carrying an identity and a
     * link, so a redeemer can never read one as established.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $outcome
     * @return void
     */
    #[DataProvider('refusals')]
    public function testARefusingOutcomeIsNeverPassedWhateverItCarries(RecheckOutcome $outcome): void
    {
        self::assertFalse((new Admission($outcome, new IdentityReference('user', '1'), 'link-1'))->isPassed());
    }
}
