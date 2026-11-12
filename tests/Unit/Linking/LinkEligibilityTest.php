<?php

declare(strict_types = 1);

namespace Tests\Unit\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Unit tests for the default link eligibility, which refuses everyone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusingLinkEligibility::class)]
#[CoversClass(LinkEligibilityVerdict::class)]
final class LinkEligibilityTest extends TestCase
{
    /**
     * With nothing bound, the contract is the one that refuses.
     *
     * @return void
     */
    public function testTheDefaultBindingIsTheRefusingOne(): void
    {
        self::assertInstanceOf(RefusingLinkEligibility::class, app(LinkEligibility::class));
    }

    /**
     * The default refuses any identity through any connection.
     *
     * @return void
     */
    public function testTheDefaultRefusesEveryIdentityThroughEveryConnection(): void
    {
        $eligibility = app(LinkEligibility::class);

        self::assertSame(LinkEligibilityVerdict::INELIGIBLE, $eligibility->judge(new IdentityReference('App\Models\User', '7'), new ExampleConnection));
        self::assertSame(LinkEligibilityVerdict::INELIGIBLE, $eligibility->judge(new IdentityReference('App\Models\Admin', 'root'), new ExampleConnection('oidc')));
        self::assertSame(LinkEligibilityVerdict::INELIGIBLE, $eligibility->judge(new IdentityReference('App\Models\User', '7'), new ExampleConnection('saml2', [], false)));
    }

    /**
     * Asking keeps nothing: the same answer every time, from one instance.
     *
     * @return void
     */
    public function testTheDefaultKeepsNothingBetweenCalls(): void
    {
        $eligibility = new RefusingLinkEligibility;
        $identity    = new IdentityReference('App\Models\User', '7');

        self::assertSame(LinkEligibilityVerdict::INELIGIBLE, $eligibility->judge($identity, new ExampleConnection));
        self::assertSame(LinkEligibilityVerdict::INELIGIBLE, $eligibility->judge($identity, new ExampleConnection));
        self::assertSame([], get_object_vars($eligibility));
    }

    /**
     * The verdict values are fixed and only one lets an identity link.
     *
     * @return void
     */
    public function testTheVerdictsValuesAreStable(): void
    {
        self::assertSame(
            ['eligible', 'ineligible'],
            array_map(static fn (LinkEligibilityVerdict $verdict): string => $verdict->value, LinkEligibilityVerdict::cases()),
        );
        self::assertTrue(LinkEligibilityVerdict::ELIGIBLE->isEligible());
        self::assertFalse(LinkEligibilityVerdict::INELIGIBLE->isEligible());
    }
}
