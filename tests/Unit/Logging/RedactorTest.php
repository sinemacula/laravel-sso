<?php

declare(strict_types = 1);

namespace Tests\Unit\Logging;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Logging\DiagnosticSanitizer;
use SineMacula\Laravel\Sso\Logging\LoggingSettings;
use SineMacula\Laravel\Sso\Logging\Redactor;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Unit tests for context redaction (SSO-9.8, SSO-11.9): values under a
 * redacted key, in any case or separator and at any depth, redacted whole;
 * other strings sanitised; scalars and enums kept; exceptions reduced; objects
 * never dumped; and the depth capped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Redactor::class)]
final class RedactorTest extends TestCase
{
    /**
     * Rows of `[key]`: every built-in redacted key, as written.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBuiltInKeys(): iterable
    {
        foreach (Redactor::REDACTED_KEYS as $key) {
            yield $key => [$key];
        }
    }

    /**
     * Every built-in key is redacted, however its value is shaped.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideBuiltInKeys')]
    public function testRedactsEveryBuiltInKey(string $key): void
    {
        $redacted = self::redactor()->redact([
            $key        => 'a short value',
            'nested'    => [$key => ['an' => 'array']],
            'reference' => 'ref-1',
        ]);

        self::assertSame([
            $key        => '[redacted]',
            'nested'    => [$key => '[redacted]'],
            'reference' => 'ref-1',
        ], $redacted);
    }

    /**
     * Rows of `[key]`: one key in the forms it may be written in.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideKeyForms(): iterable
    {
        yield from [
            'snake case'       => ['client_secret'],
            'kebab title case' => ['Client-Secret'],
            'upper case'       => ['CLIENT_SECRET'],
            'camel case'       => ['clientSecret'],
            'pascal case'      => ['ClientSecret'],
            'dotted'           => ['client.secret'],
            'spaced'           => ['Client Secret'],
        ];
    }

    /**
     * A key is compared normalised, so any case or separator is redacted.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideKeyForms')]
    public function testComparesKeysNormalized(string $key): void
    {
        self::assertSame([$key => '[redacted]'], self::redactor()->redact([$key => 'a-client-secret']));
    }

    /**
     * Only a key whose whole name normalises to a redacted key is redacted: one
     * that merely contains one is kept, its value sanitised.
     *
     * @return void
     */
    public function testKeepsKeysThatOnlyContainARedactedKey(): void
    {
        $context = ['error_code' => 'E1', 'token_type' => 'Bearer', 'codes' => [1, 2], 'request_reference' => 'ref-1', 7 => 'seven'];

        self::assertSame($context, self::redactor()->redact($context));
    }

    /**
     * A key added in `sso.logging.redacted_keys` is redacted too, in any form,
     * and the built-in keys still are.
     *
     * @return void
     */
    public function testRedactsAConfiguredKey(): void
    {
        $redactor = self::redactor(['redacted_keys' => ['tenant_secret']]);

        self::assertSame(
            ['TenantSecret' => '[redacted]', 'code' => '[redacted]', 'tenant' => 'acme'],
            $redactor->redact(['TenantSecret' => 'x', 'code' => 'y', 'tenant' => 'acme']),
        );
    }

    /**
     * Strings under other keys are sanitised as diagnostics, so a secret under
     * an innocent key is caught by its shape, and a list is followed.
     *
     * @return void
     */
    public function testSanitizesOtherStrings(): void
    {
        $redacted = self::redactor()->redact([
            'url'     => 'https://app.example.com/cb?code=abc&state=xyz',
            'details' => ['lines' => ["line one\nline two", 'Bearer abc.def']],
            'body'    => '{"access_token":"x","error":"invalid_grant"}',
        ]);

        self::assertSame([
            'url'     => 'https://app.example.com/cb?code=[redacted]&state=[redacted]',
            'details' => ['lines' => ['line one line two', 'Bearer [redacted]']],
            'body'    => '{"access_token":"[redacted]","error":"invalid_grant"}',
        ], $redacted);
    }

    /**
     * Integers, floats, booleans and `null` are kept as they are, and a backed
     * enum is its value.
     *
     * @return void
     */
    public function testKeepsScalarsAndEnumValues(): void
    {
        $context = ['count' => 3, 'ratio' => 1.5, 'enabled' => false, 'previous' => null, 'reason' => FailureReason::SIGNATURE_INVALID];

        self::assertSame(
            ['count' => 3, 'ratio' => 1.5, 'enabled' => false, 'previous' => null, 'reason' => 'signature_invalid'],
            self::redactor()->redact($context),
        );
    }

    /**
     * An exception is reduced to its class, its sanitised message and its code:
     * no trace, no file, no previous exception.
     *
     * @return void
     */
    public function testReducesAThrowable(): void
    {
        $previous  = new \LogicException('the previous one held code=hidden');
        $exception = new \RuntimeException("Handoff code=abc123 was refused\nagain", 42, $previous);

        $redacted = self::redactor()->redact(['exception' => $exception]);

        self::assertSame(['exception' => [
            'class'   => \RuntimeException::class,
            'message' => 'Handoff code=[redacted] was refused again',
            'code'    => 42,
        ]], $redacted);
    }

    /**
     * A string exception code, as a PDO exception carries, is sanitised too.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testSanitizesAStringExceptionCode(): void
    {
        $exception = new \PDOException('SQLSTATE[23000]: duplicate');

        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($exception, "23000\n");

        $redacted = self::redactor()->redact(['error' => $exception]);

        self::assertSame(['class' => \PDOException::class, 'message' => 'SQLSTATE[23000]: duplicate', 'code' => '23000'], $redacted['error']);
    }

    /**
     * An exception under a redacted key is redacted whole, like any value.
     *
     * @return void
     */
    public function testRedactsAThrowableUnderARedactedKey(): void
    {
        self::assertSame(['token' => '[redacted]'], self::redactor()->redact(['token' => new \RuntimeException('x')]));
    }

    /**
     * Any other object is named by its class and never dumped, cast or
     * serialised, whatever it holds or can turn into.
     *
     * @return void
     */
    public function testNeverDumpsAnObject(): void
    {
        $stringable = new class implements \Stringable {
            /**
             * What a cast would give, which must never be logged.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'stringable-secret';
            }
        };

        $redacted = self::redactor()->redact([
            'secret'     => new Secret('the-secret'),
            'held'       => new Secret('the-held-secret'),
            'list'       => new \ArrayObject(['access_token' => 'x']),
            'stringable' => $stringable,
            'date'       => new \DateTimeImmutable('2026-11-01T00:00:00Z'),
        ]);

        self::assertSame('[redacted]', $redacted['secret']);
        self::assertSame('[object ' . Secret::class . ']', $redacted['held']);
        self::assertSame('[object ArrayObject]', $redacted['list']);
        self::assertSame('[object ' . $stringable::class . ']', $redacted['stringable']);
        self::assertSame('[object DateTimeImmutable]', $redacted['date']);
        self::assertStringNotContainsString('stringable-secret', (string) json_encode($redacted));
    }

    /**
     * A resource is named by its type, never read.
     *
     * @return void
     */
    public function testNamesAResourceByItsType(): void
    {
        $stream = fopen('php://memory', 'rb');

        self::assertIsResource($stream);

        try {
            self::assertSame(['stream' => '[resource (stream)]'], self::redactor()->redact(['stream' => $stream]));
        } finally {
            fclose($stream);
        }
    }

    /**
     * Arrays are followed to a depth of eight, the context itself the first;
     * an array deeper than that is `[truncated]`, while a redacted key at the
     * deepest level is still redacted.
     *
     * @return void
     */
    public function testCapsTheDepth(): void
    {
        $deepest = ['value' => 'kept', 'code' => 'hidden', 'deeper' => ['value' => 'lost']];
        $context = $deepest;

        for ($level = 1; $level < Redactor::MAX_DEPTH; $level++) {
            $context = ['level' => $context];
        }

        $redacted = self::redactor()->redact($context);

        for ($level = 1; $level < Redactor::MAX_DEPTH; $level++) {
            self::assertIsArray($redacted['level']);
            $redacted = $redacted['level'];
        }

        self::assertSame(['value' => 'kept', 'code' => '[redacted]', 'deeper' => '[truncated]'], $redacted);
    }

    /**
     * An empty context is an empty context.
     *
     * @return void
     */
    public function testRedactsAnEmptyContext(): void
    {
        self::assertSame([], self::redactor()->redact([]));
    }

    /**
     * Every built-in key normalises to a distinct, non-empty key among the
     * settings' redacted keys.
     *
     * @return void
     */
    public function testTheBuiltInKeysAreAmongTheSettingsKeys(): void
    {
        $keys = (new LoggingSettings(new Repository([])))->redactedKeys();

        foreach (Redactor::REDACTED_KEYS as $key) {
            self::assertContains(LoggingSettings::normalizeKey($key), $keys);
        }
    }

    /**
     * A redactor over the logging settings given.
     *
     * @param  array<string, mixed>  $logging
     * @return \SineMacula\Laravel\Sso\Logging\Redactor
     */
    private static function redactor(array $logging = []): Redactor
    {
        $settings = new LoggingSettings(new Repository(['sso' => ['logging' => $logging]]));

        return new Redactor($settings, new DiagnosticSanitizer($settings));
    }
}
