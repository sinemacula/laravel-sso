<?php

declare(strict_types = 1);

namespace Tests\Unit\Identities;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Unit tests for a caller: the identity it is given and, when given, a session
 * id of 1 to 255 bytes, kept as given; no session is none, never another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Caller::class)]
final class CallerTest extends TestCase
{
    /**
     * A caller keeps the identity and the session given, and no session when
     * none is given.
     *
     * @return void
     */
    public function testKeepsTheIdentityAndTheSessionGiven(): void
    {
        $identity = new IdentityReference('App\Models\User', '42');

        $onSession = new Caller($identity, 'session-1');
        $alone     = new Caller($identity);

        self::assertSame($identity, $onSession->identity);
        self::assertSame('session-1', $onSession->sessionId);
        self::assertSame($identity, $alone->identity);
        self::assertNull($alone->sessionId);
        self::assertNull((new Caller($identity, null))->sessionId);
    }

    /**
     * A session id of one byte and one of 255 bytes are kept, byte for byte.
     *
     * @return void
     */
    public function testKeepsASessionIdAtEitherBound(): void
    {
        $identity = new IdentityReference('App\Models\User', '42');

        self::assertSame('s', (new Caller($identity, 's'))->sessionId);
        self::assertSame(str_repeat('x', Caller::MAX_SESSION_ID_LENGTH), (new Caller($identity, str_repeat('x', 255)))->sessionId);
        self::assertSame(' é ', (new Caller($identity, ' é '))->sessionId);
    }

    /**
     * Rows of `[session id]`: an empty one, and ones a byte and many bytes too
     * long, multibyte characters counted in bytes.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedSessionIds(): iterable
    {
        yield 'empty' => [''];
        yield 'a byte too long' => [str_repeat('x', 256)];
        yield 'too long in bytes, not characters' => [str_repeat('é', 128)];
        yield 'far too long' => [str_repeat('x', 10000)];
    }

    /**
     * A session id that is empty or longer than 255 bytes is the caller's
     * mistake.
     *
     * @param  string  $sessionId
     * @return void
     */
    #[DataProvider('provideMalformedSessionIds')]
    public function testRefusesAMalformedSessionId(string $sessionId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A session id is 1 to 255 bytes.');

        new Caller(new IdentityReference('App\Models\User', '42'), $sessionId);
    }
}
