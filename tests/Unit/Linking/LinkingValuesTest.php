<?php

declare(strict_types = 1);

namespace Tests\Unit\Linking;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for the values and defaults of linking by a verified domain
 * (SSO-8.8): the query that holds the email and shows it to nobody but the
 * matcher; none, exactly one or ambiguous, the last naming nobody; a membership
 * accepted strictly before an instant; the scope verdicts, of which only one
 * allows anything; and the defaults, each of which refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkEmailQuery::class)]
#[CoversClass(LinkEmailMatch::class)]
#[CoversClass(MembershipStanding::class)]
#[CoversClass(ScopeVerdict::class)]
#[CoversClass(NoEmailMatches::class)]
#[CoversClass(NoTenantMembership::class)]
#[CoversClass(RefusingPrincipalScope::class)]
final class LinkingValuesTest extends TestCase
{
    use DumpsValues;

    /** @var string The email the query holds. */
    private const string EMAIL = 'Person+tag@Example.COM';

    /**
     * The query holds the email exactly as asserted, and what the matcher
     * compares its domain with.
     *
     * @return void
     */
    public function testTheQueryHoldsTheEmailUnchanged(): void
    {
        $query = self::query();

        self::assertSame(self::EMAIL, $query->email());
        self::assertSame('tenant-1', $query->tenantId);
        self::assertSame('example.com', $query->domain);
    }

    /**
     * A dump shows the tenant and the domain alone, `json_encode()` writes the
     * email redacted, and no form of a dump shows it.
     *
     * @return void
     */
    public function testADumpOrAnEncodingNeverShowsTheEmail(): void
    {
        $query    = self::query();
        $expected = ['tenant_id' => 'tenant-1', 'email' => '[redacted]', 'domain' => 'example.com'];

        self::assertSame($expected, $query->jsonSerialize());
        self::assertSame($expected, $query->__debugInfo());
        self::assertSame('{"tenant_id":"tenant-1","email":"[redacted]","domain":"example.com"}', json_encode($query));

        foreach (self::dumps($query) as $form => $dump) {
            self::assertStringNotContainsString(self::EMAIL, $dump, $form);
        }
    }

    /**
     * The query refuses to be serialised, in those words.
     *
     * @return void
     */
    public function testTheQueryRefusesToBeSerialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A link email query cannot be serialised.');

        serialize(self::query());
    }

    /**
     * The query refuses to be unserialised, in those words.
     *
     * @return void
     */
    public function testTheQueryRefusesToBeUnserialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A link email query cannot be unserialised.');

        (new \ReflectionClass(LinkEmailQuery::class))->newInstanceWithoutConstructor()->__unserialize([]);
    }

    /**
     * None names nobody and is nobody's sole match.
     *
     * @return void
     */
    public function testNoMatchNamesNobody(): void
    {
        $match = LinkEmailMatch::none();

        self::assertNull($match->identity);
        self::assertFalse($match->ambiguous);
        self::assertFalse($match->isSolely(self::person()));
    }

    /**
     * More than one names nobody, and so is nobody's sole match.
     *
     * @return void
     */
    public function testAnAmbiguousMatchNamesNobody(): void
    {
        $match = LinkEmailMatch::ambiguous();

        self::assertNull($match->identity);
        self::assertTrue($match->ambiguous);
        self::assertFalse($match->isSolely(self::person()));
    }

    /**
     * Exactly one is that identity's sole match, byte for byte, and no other's.
     *
     * @return void
     */
    public function testExactlyOneIsThatIdentitysSoleMatch(): void
    {
        $match = LinkEmailMatch::exactlyOne(self::person());

        self::assertFalse($match->ambiguous);
        self::assertTrue($match->isSolely(new IdentityReference('App\Models\User', 'a7')));
        self::assertFalse($match->isSolely(new IdentityReference('App\Models\User', 'A7')));
        self::assertFalse($match->isSolely(new IdentityReference('App\Models\Admin', 'a7')));
    }

    /**
     * A membership accepted counts strictly before the instant: one second
     * before it does, at it and after it do not.
     *
     * @return void
     */
    public function testAMembershipWasAcceptedStrictlyBefore(): void
    {
        $instant = CarbonImmutable::parse('2026-11-01T09:30:00Z');

        self::assertTrue(MembershipStanding::accepted($instant->subSecond())->wasAcceptedBefore($instant));
        self::assertFalse(MembershipStanding::accepted($instant)->wasAcceptedBefore($instant));
        self::assertFalse(MembershipStanding::accepted($instant->addSecond())->wasAcceptedBefore($instant));
        self::assertSame($instant, MembershipStanding::accepted($instant)->acceptedAt);
    }

    /**
     * No membership was accepted before any instant.
     *
     * @return void
     */
    public function testNoMembershipWasNeverAccepted(): void
    {
        $standing = MembershipStanding::none();

        self::assertNull($standing->acceptedAt);
        self::assertFalse($standing->wasAcceptedBefore(CarbonImmutable::parse('2999-01-01T00:00:00Z')));
    }

    /**
     * Only `within_tenant` allows anything, and the names are stable.
     *
     * @return void
     */
    public function testOnlyWithinTenantAllowsAnything(): void
    {
        self::assertSame(['within_tenant', 'outside_tenant', 'unknown'], array_column(ScopeVerdict::cases(), 'value'));
        self::assertTrue(ScopeVerdict::WITHIN_TENANT->isWithinTenant());
        self::assertFalse(ScopeVerdict::OUTSIDE_TENANT->isWithinTenant());
        self::assertFalse(ScopeVerdict::UNKNOWN->isWithinTenant());
    }

    /**
     * The matcher finds none by default, the membership answers none, and the
     * scope is unknown.
     *
     * @return void
     */
    public function testEachDefaultRefuses(): void
    {
        $match = (new NoEmailMatches)->match(self::query());

        self::assertNull($match->identity);
        self::assertFalse($match->ambiguous);
        self::assertNull((new NoTenantMembership)->standing(self::person(), 'tenant-1')->acceptedAt);
        self::assertSame(ScopeVerdict::UNKNOWN, (new RefusingPrincipalScope)->judge(self::person(), 'tenant-1'));
    }

    /**
     * A query of the fixed values.
     *
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailQuery
     */
    private static function query(): LinkEmailQuery
    {
        return new LinkEmailQuery('tenant-1', self::EMAIL, 'example.com');
    }

    /**
     * The identity the tests match.
     *
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function person(): IdentityReference
    {
        return new IdentityReference('App\Models\User', 'a7');
    }
}
