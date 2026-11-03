<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * Pins the shape of what a purpose's rules came to at redemption: the outcome
 * and the provenance of the link judged, exactly these two parts, in this
 * order; `of()` names no provenance.
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
    public function testKeepsBothPartsInTheirPlaces(): void
    {
        self::assertSame(
            ['outcome' => RecheckOutcome::PASSED, 'linkProvenance' => LinkOrigin::VERIFIED_DOMAIN],
            get_object_vars(new Judgement(RecheckOutcome::PASSED, LinkOrigin::VERIFIED_DOMAIN)),
        );
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
            self::assertSame(['outcome' => $outcome, 'linkProvenance' => null], get_object_vars(Judgement::of($outcome)));
            self::assertSame(['outcome' => $outcome, 'linkProvenance' => null], get_object_vars(new Judgement($outcome)));
        }
    }
}
