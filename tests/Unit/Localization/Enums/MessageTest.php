<?php

declare(strict_types = 1);

namespace Tests\Unit\Localization\Enums;

use Illuminate\Support\Arr;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Localization\Enums\Message;

/**
 * Unit tests for the translatable messages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Message::class)]
final class MessageTest extends TestCase
{
    /**
     * Every message has a non-empty English line.
     *
     * @return void
     */
    public function testEveryMessageHasAnEnglishLine(): void
    {
        $lines = self::englishLines();

        foreach (Message::cases() as $message) {
            $line = Arr::get($lines, $message->value);

            self::assertIsString($line, "{$message->name} has no English line.");
            self::assertNotSame('', trim($line), "{$message->name} has an empty English line.");
        }
    }

    /**
     * Every English line belongs to a message.
     *
     * @return void
     */
    public function testEveryEnglishLineIsAMessage(): void
    {
        $keys = array_keys(Arr::dot(self::englishLines()));

        self::assertNotEmpty($keys);

        foreach ($keys as $key) {
            self::assertInstanceOf(Message::class, Message::tryFrom((string) $key), "The English line {$key} is not a message.");
        }
    }

    /**
     * No two messages share a line.
     *
     * @return void
     */
    public function testTheValuesAreUnique(): void
    {
        $values = array_column(Message::cases(), 'value');

        self::assertSame($values, array_values(array_unique($values)));
    }

    /**
     * The message keys are fixed, since applications override them.
     *
     * @return void
     */
    public function testTheMessagesAreStable(): void
    {
        self::assertSame([
            'post_navigation.title', 'post_navigation.continue', 'post_navigation.noscript', 'completion.invalid',
            'completion.redirecting',
        ], array_column(Message::cases(), 'value'));
    }

    /**
     * Each English line is plain text without markup.
     *
     * @return void
     */
    public function testEachEnglishLineIsPlainText(): void
    {
        foreach (Arr::dot(self::englishLines()) as $key => $line) {
            self::assertIsString($line);
            self::assertSame(strip_tags($line), $line, "The English line {$key} holds markup.");
            self::assertSame(htmlspecialchars($line, ENT_NOQUOTES), $line, "The English line {$key} holds an entity or a bracket.");
        }
    }

    /**
     * The package's English lines, as the translation file returns them.
     *
     * @return array<array-key, mixed>
     */
    private static function englishLines(): array
    {
        /** @var array<array-key, mixed> $lines */
        $lines = require dirname(__DIR__, 4) . '/lang/en/messages.php';

        return $lines;
    }
}
