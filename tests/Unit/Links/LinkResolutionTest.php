<?php

declare(strict_types = 1);

namespace Tests\Unit\Links;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkResolutionStatus;
use SineMacula\Laravel\Sso\Links\LinkResolution;

/**
 * Unit tests for what a verified result's link resolved to (SSO-8.2, SSO-8.3,
 * SSO-8.8): each of the four statuses, what each names, so a suspended or
 * reserved subject can never pass for an unlinked one, and the bounds of a link
 * id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkResolution::class)]
#[CoversClass(LinkResolutionStatus::class)]
final class LinkResolutionTest extends TestCase
{
    /**
     * An active link names the identity, its holder and the link, and is
     * nothing but linked.
     *
     * @return void
     */
    public function testALinkedResolutionNamesTheIdentityAndTheLink(): void
    {
        $identity   = new IdentityReference('App\Models\User', '7');
        $resolution = LinkResolution::linked($identity, 'link-1');

        self::assertSame(LinkResolutionStatus::LINKED, $resolution->status);
        self::assertSame($identity, $resolution->identity);
        self::assertSame($identity, $resolution->holder);
        self::assertSame('link-1', $resolution->linkId);
        self::assertSame([true, false, false, false], self::predicates($resolution));
    }

    /**
     * An absent resolution names nothing, and is nothing but absent.
     *
     * @return void
     */
    public function testAnAbsentResolutionNamesNothing(): void
    {
        $resolution = LinkResolution::absent();

        self::assertSame(LinkResolutionStatus::ABSENT, $resolution->status);
        self::assertSame([null, null, null], [$resolution->identity, $resolution->holder, $resolution->linkId]);
        self::assertSame([false, true, false, false], self::predicates($resolution));
    }

    /**
     * A reserved resolution names nothing: a reservation never resolves a
     * sign-in, and a result is refused rather than told whose it is.
     *
     * @return void
     */
    public function testAReservedResolutionNamesNothing(): void
    {
        $resolution = LinkResolution::reserved();

        self::assertSame(LinkResolutionStatus::RESERVED, $resolution->status);
        self::assertSame([null, null, null], [$resolution->identity, $resolution->holder, $resolution->linkId]);
        self::assertSame([false, false, true, false], self::predicates($resolution));
    }

    /**
     * A suspended resolution resolves no identity, and says whose link it is
     * for a confirming `link` alone.
     *
     * @return void
     */
    public function testASuspendedResolutionResolvesNoIdentity(): void
    {
        $holder     = new IdentityReference('App\Models\User', '7');
        $resolution = LinkResolution::suspended($holder, 'link-1');

        self::assertSame(LinkResolutionStatus::SUSPENDED, $resolution->status);
        self::assertNull($resolution->identity);
        self::assertSame($holder, $resolution->holder);
        self::assertSame('link-1', $resolution->linkId);
        self::assertSame([false, false, false, true], self::predicates($resolution));
    }

    /**
     * Whose link holds the subject is compared byte for byte, and a status with
     * no holder is held by nobody.
     *
     * @return void
     */
    public function testIsHeldByComparesByteForByte(): void
    {
        $holder = new IdentityReference('App\Models\User', 'a');

        self::assertTrue(LinkResolution::linked($holder, 'l')->isHeldBy(new IdentityReference('App\Models\User', 'a')));
        self::assertTrue(LinkResolution::suspended($holder, 'l')->isHeldBy(new IdentityReference('App\Models\User', 'a')));
        self::assertFalse(LinkResolution::linked($holder, 'l')->isHeldBy(new IdentityReference('App\Models\User', 'A')));
        self::assertFalse(LinkResolution::linked($holder, 'l')->isHeldBy(new IdentityReference('App\Models\Admin', 'a')));
        self::assertFalse(LinkResolution::absent()->isHeldBy($holder));
        self::assertFalse(LinkResolution::reserved()->isHeldBy($holder));
        self::assertTrue(LinkResolution::scopeUnknown($holder, 'l')->isHeldBy(new IdentityReference('App\Models\User', 'a')));
    }

    /**
     * A link whose scope could not be judged resolves nothing: it names its
     * holder and its link, and is nothing but of unknown scope.
     *
     * @return void
     */
    public function testAScopeUnknownResolutionResolvesNothing(): void
    {
        $holder     = new IdentityReference('App\Models\User', 'a');
        $resolution = LinkResolution::scopeUnknown($holder, 'l');

        self::assertNull($resolution->identity);
        self::assertSame($holder, $resolution->holder);
        self::assertSame('l', $resolution->linkId);
        self::assertTrue($resolution->isScopeUnknown());
        self::assertFalse($resolution->isLinked());
        self::assertFalse($resolution->isAbsent());
        self::assertFalse($resolution->isReserved());
        self::assertFalse($resolution->isSuspended());
        self::assertFalse(LinkResolution::absent()->isScopeUnknown());
    }

    /**
     * Rows of `[length, whether it is accepted]`: a link id's bounds, at one
     * under, at, and one over.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideLinkIdLengths(): iterable
    {
        yield 'empty' => [0, false];
        yield 'one byte' => [1, true];
        yield 'one under the most' => [254, true];
        yield 'the most' => [255, true];
        yield 'one over the most' => [256, false];
    }

    /**
     * A link id is 1 to 255 bytes, for a linked and for a suspended link alike.
     *
     * @param  int  $length
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideLinkIdLengths')]
    public function testALinkIdIsBounded(int $length, bool $accepted): void
    {
        $identity = new IdentityReference('App\Models\User', '7');
        $id       = str_repeat('l', $length);

        foreach ([LinkResolution::linked(...), LinkResolution::suspended(...)] as $make) {

            try {
                self::assertSame($id, $make($identity, $id)->linkId);
                self::assertTrue($accepted);
            } catch (\InvalidArgumentException $exception) {
                self::assertFalse($accepted);
                self::assertSame('A link id is 1 to 255 bytes.', $exception->getMessage());
            }
        }
    }

    /**
     * The status names are stable.
     *
     * @return void
     */
    public function testTheStatusNamesAreStable(): void
    {
        self::assertSame(['linked', 'absent', 'reserved', 'suspended', 'scope_unknown'], array_column(LinkResolutionStatus::cases(), 'value'));
    }

    /**
     * Each predicate of the resolution, in the order of the statuses.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @return list<bool>
     */
    private static function predicates(LinkResolution $resolution): array
    {
        return [$resolution->isLinked(), $resolution->isAbsent(), $resolution->isReserved(), $resolution->isSuspended()];
    }
}
