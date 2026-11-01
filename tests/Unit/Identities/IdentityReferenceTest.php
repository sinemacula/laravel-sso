<?php

declare(strict_types = 1);

namespace Tests\Unit\Identities;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Unit tests for an identity reference: a type and an id, each 1 to 255 bytes,
 * the same identity only when both are equal byte for byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityReference::class)]
final class IdentityReferenceTest extends TestCase
{
    /**
     * Two references are the same identity only when both parts are equal.
     *
     * @return void
     */
    public function testIsTheSameIdentityOnlyWhenBothPartsAreEqual(): void
    {
        $reference = new IdentityReference('App\Models\User', '42');

        self::assertTrue($reference->is(new IdentityReference('App\Models\User', '42')));
        self::assertFalse($reference->is(new IdentityReference('App\Models\Admin', '42')));
        self::assertFalse($reference->is(new IdentityReference('App\Models\User', '420')));
        self::assertFalse($reference->is(new IdentityReference('app\models\user', '42')));
        self::assertSame(['type' => 'App\Models\User', 'id' => '42'], $reference->jsonSerialize());
    }

    /**
     * An empty or overlong part is the caller's mistake.
     *
     * @return void
     */
    public function testRefusesAnEmptyOrOverlongPart(): void
    {
        self::assertSame(str_repeat('x', 255), (new IdentityReference('T', str_repeat('x', 255)))->id);

        foreach ([['', '1'], ['T', ''], [str_repeat('x', 256), '1']] as [$type, $id]) {
            try {
                new IdentityReference($type, $id);
                self::fail('The reference was built.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('An identity reference has a type and an id, each 1 to 255 bytes.', $exception->getMessage());
            }
        }
    }

    /**
     * Two nullable columns name an identity only when both are set.
     *
     * @return void
     */
    public function testReadsAReferenceFromTwoColumns(): void
    {
        $reference = IdentityReference::fromColumns('user', '7');

        self::assertNotNull($reference);
        self::assertSame(['type' => 'user', 'id' => '7'], $reference->jsonSerialize());
        self::assertNull(IdentityReference::fromColumns(null, '7'));
        self::assertNull(IdentityReference::fromColumns('user', null));
        self::assertNull(IdentityReference::fromColumns(null, null));

        $this->expectException(\InvalidArgumentException::class);

        IdentityReference::fromColumns('', '7');
    }
}
