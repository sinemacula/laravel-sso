<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * Unit tests for the shape of a redemption judgement.
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
     * `under()` changes the enforcement version alone.
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
     * An outcome alone names no link provenance.
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
