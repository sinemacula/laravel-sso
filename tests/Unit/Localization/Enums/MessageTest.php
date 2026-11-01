<?php

declare(strict_types = 1);

namespace Tests\Unit\Localization\Enums;

use Illuminate\Support\Arr;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Localization\Enums\Message;

/**
 * Unit tests for the messages: every message has an English line, every English
 * line is a message, and each line is plain text (SSO-12.6).
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
     * Every message has a non-empty English line, so a message is never shown
     * as its key.
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
     * Every English line is a message, so no line is shipped that nothing
     * reads.
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
     * The messages are these: a key an application overrides is never renamed
     * or reused, so a change here is a deliberate one.
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
     * Each English line is plain text, with no markup for a caller to trust:
     * whoever renders it escapes it.
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
