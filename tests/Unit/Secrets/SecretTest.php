<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for a plaintext secret: revealed only on request, compared in
 * constant time, never empty, and never shown by a dump, `json_encode()`, an
 * exception's trace or serialisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Secret::class)]
#[CoversClass(ConstantTime::class)]
final class SecretTest extends TestCase
{
    /** @var string A secret no output may show. */
    private const string SECRET = 'the-client-secret-value';

    /** @var string An ordinary value, passed where traces show arguments. */
    private const string MARKER = 'an-ordinary-trace-marker';

    /**
     * The secret is revealed to the code that asks for it.
     *
     * @return void
     */
    public function testRevealsTheSecret(): void
    {
        self::assertSame(self::SECRET, (new Secret(self::SECRET))->reveal());
    }

    /**
     * The secret equals itself and nothing else.
     *
     * @return void
     */
    public function testEquals(): void
    {
        $secret = new Secret(self::SECRET);

        self::assertTrue($secret->equals(self::SECRET));

        self::assertFalse($secret->equals('the-client-secret-valuE'));
        self::assertFalse($secret->equals(self::SECRET . ' '));
        self::assertFalse($secret->equals(''));
    }

    /**
     * An empty secret is a caller's mistake.
     *
     * @return void
     */
    public function testRefusesAnEmptySecret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A secret cannot be empty.');

        new Secret('');
    }

    /**
     * Neither a dump (PHP's own, or the one behind Laravel's `dump()` and error
     * pages, which also lists private properties), an array cast nor
     * `json_encode()` shows the secret.
     *
     * @return void
     */
    public function testNoDumpShowsTheSecret(): void
    {
        $secret = new Secret(self::SECRET);
        $dumped = (string) (new CliDumper)->dump((new VarCloner)->cloneVar($secret), true);

        self::assertSame(['secret' => '[redacted]'], $secret->__debugInfo());
        self::assertStringNotContainsString(self::SECRET, print_r($secret, true));
        self::assertStringContainsString('[redacted]', print_r($secret, true));
        self::assertStringNotContainsString(self::SECRET, var_export($secret, true));
        self::assertStringNotContainsString(self::SECRET, (string) json_encode((array) $secret));
        self::assertStringNotContainsString(self::SECRET, $dumped);
        self::assertStringContainsString('[redacted]', $dumped);
        self::assertSame('"[redacted]"', json_encode($secret));
        self::assertSame('{"secret":"[redacted]"}', json_encode(['secret' => $secret]));
    }

    /**
     * An exception thrown where the secret is passed shows it in neither its
     * trace nor its string form, and the constructor's argument is marked
     * sensitive, so a failure while building one shows it neither.
     *
     * Traces are made to carry arguments for the test, as they do wherever
     * `zend.exception_ignore_args` is off, and a marker passed as an ordinary
     * argument is shown to reach the trace first, so the assertions cannot pass
     * merely because no argument was recorded.
     *
     * @return void
     */
    public function testNoTraceShowsTheSecret(): void
    {
        $previous = ini_get('zend.exception_ignore_args');

        ini_set('zend.exception_ignore_args', '0');

        try {
            self::assertStringContainsString(self::MARKER, print_r(self::failWithMarker(self::MARKER)->getTrace(), true));

            $exception = self::failWith(new Secret(self::SECRET), self::SECRET);

            self::assertSame('The secret was given.', $exception->getMessage());
            self::assertStringNotContainsString(self::SECRET, $exception->getTraceAsString());
            self::assertStringNotContainsString(self::SECRET, (string) $exception);
            self::assertStringNotContainsString(self::SECRET, print_r($exception->getTrace(), true));
        } finally {
            ini_set('zend.exception_ignore_args', (string) $previous);
        }

        $parameter = (new \ReflectionMethod(Secret::class, '__construct'))->getParameters()[0];

        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * There is no string form, so a cast or an interpolation fails loudly
     * rather than writing the secret out.
     *
     * @return void
     */
    public function testHasNoStringForm(): void
    {
        $class = new \ReflectionClass(Secret::class);

        self::assertFalse($class->hasMethod('__toString'));
        self::assertFalse($class->implementsInterface(\Stringable::class));
    }

    /**
     * It refuses to be serialised, so it cannot reach a queue or a cache.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A secret cannot be serialised.');

        serialize(new Secret(self::SECRET));
    }

    /**
     * It refuses to be unserialised, so a crafted payload cannot build one.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A secret cannot be unserialised.');

        (new Secret(self::SECRET))->__unserialize(['secret' => self::SECRET]);
    }

    /**
     * An exception built in a call that is passed an ordinary argument, so the
     * argument is in its trace wherever traces carry arguments.
     *
     * @param  string  $marker
     * @return \RuntimeException
     */
    private static function failWithMarker(string $marker): \RuntimeException
    {
        return new \RuntimeException(strlen($marker) > 0 ? 'A marker was given.' : 'No marker was given.');
    }

    /**
     * An exception built in a call that is passed the secret and, as a
     * sensitive argument, its plaintext, so the call is in its trace.
     *
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $secret
     * @param  string  $plaintext
     * @return \RuntimeException
     */
    private static function failWith(Secret $secret, #[\SensitiveParameter] string $plaintext): \RuntimeException
    {
        return new \RuntimeException($secret->equals($plaintext) ? 'The secret was given.' : 'Another secret was given.');
    }
}
