<?php

declare(strict_types = 1);

namespace Tests\Unit\Results;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Results\AssertedEmail;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for a provider-asserted email.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssertedEmail::class)]
final class AssertedEmailTest extends TestCase
{
    use DumpsValues;

    /** @var string The email the examples assert, exactly as received. */
    private const string EMAIL = ' Person+Tag@Example.COM ';

    /**
     * The email is kept exactly, never trimmed or normalised.
     *
     * @return void
     */
    public function testKeepsTheEmailExactly(): void
    {
        $asserted = new AssertedEmail(self::EMAIL, true, LinkingEmailSource::ID_TOKEN);

        self::assertSame(self::EMAIL, $asserted->email());
        self::assertTrue($asserted->verified);
        self::assertSame(LinkingEmailSource::ID_TOKEN, $asserted->source);
        self::assertSame(['email' => self::EMAIL, 'verified' => true, 'source' => 'id_token'], $asserted->toArray());
    }

    /**
     * Rows of `[verified]`: each thing `email_verified` may be.
     *
     * @return iterable<string, array{0: ?bool}>
     */
    public static function provideAssertions(): iterable
    {
        yield 'verified' => [true];
        yield 'not verified' => [false];
        yield 'unknown' => [null];
    }

    /**
     * `email_verified` is carried exactly as asserted, stored and in JSON.
     *
     * @param  ?bool  $verified
     * @return void
     */
    #[DataProvider('provideAssertions')]
    public function testCarriesTheFlagAsAsserted(?bool $verified): void
    {
        $asserted = new AssertedEmail(self::EMAIL, $verified, LinkingEmailSource::USERINFO);

        self::assertSame($verified, $asserted->verified);
        self::assertSame(['email' => self::EMAIL, 'verified' => $verified, 'source' => 'userinfo'], $asserted->toArray());
        self::assertSame(['source' => 'userinfo', 'verified' => $verified], $asserted->jsonSerialize());
        self::assertSame($verified, AssertedEmail::restore($asserted->toArray())->verified);
    }

    /**
     * An email is 1 to 320 bytes, and need not be well formed.
     *
     * @return void
     */
    public function testAcceptsAnEmailOfOneTo320Bytes(): void
    {
        self::assertSame(320, AssertedEmail::MAX_EMAIL_LENGTH);
        self::assertSame('a', (new AssertedEmail('a', null, LinkingEmailSource::ID_TOKEN))->email());
        self::assertSame(str_repeat('a', 320), (new AssertedEmail(str_repeat('a', 320), null, LinkingEmailSource::ID_TOKEN))->email());
    }

    /**
     * Rows of `[email]`: emails outside the bounds.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOutOfBoundsEmails(): iterable
    {
        yield 'empty' => [''];
        yield 'one byte over' => [str_repeat('a', 321)];
    }

    /**
     * An email outside the bounds is refused, in a message that never names it.
     *
     * @param  string  $email
     * @return void
     */
    #[DataProvider('provideOutOfBoundsEmails')]
    public function testRefusesAnEmailOutsideTheBounds(string $email): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('A verified result\'s asserted email is 1 to 320 bytes.'));

        new AssertedEmail($email, true, LinkingEmailSource::ID_TOKEN);
    }

    /**
     * JSON shows only the source and the flag, never the email.
     *
     * @return void
     */
    public function testJsonNeverShowsTheEmail(): void
    {
        self::assertSame('{"source":"id_token","verified":false}', json_encode(new AssertedEmail(self::EMAIL, false, LinkingEmailSource::ID_TOKEN)));
    }

    /**
     * No dump or cast shows the email.
     *
     * @return void
     */
    public function testNoDumpShowsTheEmail(): void
    {
        $asserted = new AssertedEmail(self::EMAIL, true, LinkingEmailSource::USERINFO);

        self::assertSame(['email' => '[redacted]', 'verified' => true, 'source' => 'userinfo'], $asserted->__debugInfo());

        foreach (self::dumps($asserted) as $name => $dump) {
            self::assertStringNotContainsString('Person', $dump, $name);
        }

        self::assertStringNotContainsString('Person', print_r((array) $asserted, true));
    }

    /**
     * It cannot be serialised: only the verified result stores it.
     *
     * @return void
     */
    public function testCannotBeSerialized(): void
    {
        $this->expectExceptionObject(new \LogicException('An asserted email cannot be serialised.'));

        serialize(new AssertedEmail(self::EMAIL, true, LinkingEmailSource::ID_TOKEN));
    }

    /**
     * It cannot be unserialised.
     *
     * @return void
     */
    public function testCannotBeUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('An asserted email cannot be unserialised.'));

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(AssertedEmail::class), AssertedEmail::class));
    }

    /**
     * The stored form reads back exactly; without a flag it is unknown.
     *
     * @return void
     */
    public function testReadsBackWhatItStored(): void
    {
        $restored = AssertedEmail::restore((new AssertedEmail(self::EMAIL, false, LinkingEmailSource::USERINFO))->toArray());

        self::assertSame(['email' => self::EMAIL, 'verified' => false, 'source' => 'userinfo'], $restored->toArray());
        self::assertNull(AssertedEmail::restore(['email' => self::EMAIL, 'source' => 'id_token'])->verified);
    }

    /**
     * Rows of `[stored]`: stored forms the package never wrote.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideCorruptForms(): iterable
    {
        yield 'no email' => [['verified' => true, 'source' => 'id_token']];
        yield 'a null email' => [['email' => null, 'verified' => true, 'source' => 'id_token']];
        yield 'a numeric email' => [['email' => 1, 'verified' => true, 'source' => 'id_token']];
        yield 'an empty email' => [['email' => '', 'verified' => true, 'source' => 'id_token']];
        yield 'an email too long' => [['email' => str_repeat('a', 321), 'verified' => true, 'source' => 'id_token']];
        yield 'a flag that is a string' => [['email' => 'a', 'verified' => 'true', 'source' => 'id_token']];
        yield 'a flag that is a number' => [['email' => 'a', 'verified' => 1, 'source' => 'id_token']];
        yield 'no source' => [['email' => 'a', 'verified' => true]];
        yield 'an unknown source' => [['email' => 'a', 'verified' => true, 'source' => 'header']];
    }

    /**
     * A stored form the package never wrote fails as corrupt storage.
     *
     * @param  array<string, mixed>  $stored
     * @return void
     */
    #[DataProvider('provideCorruptForms')]
    public function testRefusesAFormItNeverWrote(array $stored): void
    {
        $this->expectExceptionObject(new \UnexpectedValueException('A stored verified result is not one the package wrote.'));

        AssertedEmail::restore($stored);
    }
}
