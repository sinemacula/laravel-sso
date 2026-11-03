<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * Pins the shape of what a purpose's rules came to at redemption: the outcome,
 * the provenance of the link judged and the version of the enforcement judged,
 * exactly these three parts, in this order; `of()` names neither, and `under()`
 * changes the version alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Judgement::class)]
final class JudgementTest extends TestCase
{
    /**
     * Both parts are kept, under their own names and in their own places.
     *
     * @return void
     */
    public function testKeepsEveryPartInItsPlace(): void
    {
        self::assertSame(
            ['outcome' => RecheckOutcome::PASSED, 'linkProvenance' => LinkOrigin::VERIFIED_DOMAIN, 'enforcementVersion' => 'enforcement-1'],
            get_object_vars(new Judgement(RecheckOutcome::PASSED, LinkOrigin::VERIFIED_DOMAIN, 'enforcement-1')),
        );
    }

    /**
     * Judged under an enforcement version, a judgement keeps its outcome and
     * provenance and takes that version, whatever it had.
     *
     * @return void
     */
    public function testUnderAVersionChangesTheVersionAlone(): void
    {
        $judgement = new Judgement(RecheckOutcome::PASSED, LinkOrigin::PROVISIONING, 'enforcement-1');

        self::assertSame(
            ['outcome' => RecheckOutcome::PASSED, 'linkProvenance' => LinkOrigin::PROVISIONING, 'enforcementVersion' => 'enforcement-2'],
            get_object_vars($judgement->under('enforcement-2')),
        );
        self::assertSame(
            ['outcome' => RecheckOutcome::LINK_CHANGED, 'linkProvenance' => null, 'enforcementVersion' => null],
            get_object_vars(Judgement::of(RecheckOutcome::LINK_CHANGED)->under(null)),
        );
        self::assertSame('enforcement-1', $judgement->enforcementVersion);
    }

    /**
     * An outcome alone names no link provenance, by default and through `of()`,
     * for every outcome.
     *
     * @return void
     */
    public function testAnOutcomeAloneNamesNoProvenance(): void
    {
        foreach (RecheckOutcome::cases() as $outcome) {
            self::assertSame(['outcome' => $outcome, 'linkProvenance' => null, 'enforcementVersion' => null], get_object_vars(Judgement::of($outcome)));
            self::assertSame(['outcome' => $outcome, 'linkProvenance' => null, 'enforcementVersion' => null], get_object_vars(new Judgement($outcome)));
        }
    }
}
