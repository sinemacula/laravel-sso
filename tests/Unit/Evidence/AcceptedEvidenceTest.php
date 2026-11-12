<?php

declare(strict_types = 1);

namespace Tests\Unit\Evidence;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for accepted evidence, which never shows a provider value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AcceptedEvidence::class)]
final class AcceptedEvidenceTest extends TestCase
{
    use DumpsValues;

    /** @var string A method nothing else in a dump could spell. */
    private const string METHOD = 'retina';

    /** @var string A raw context class nothing else in a dump could spell. */
    private const string RAW_CONTEXT = 'urn:example:raw-context-class';

    /**
     * It holds what it was given, and reads it back through its accessors.
     *
     * @return void
     */
    public function testItHoldsWhatItWasGiven(): void
    {
        $at       = CarbonImmutable::parse('2026-11-01T09:29:00Z');
        $evidence = new AcceptedEvidence('connection-1', $at, [self::METHOD, 'pwd'], self::RAW_CONTEXT);

        self::assertSame('connection-1', $evidence->connectionId);
        self::assertSame($at, $evidence->authenticatedAt);
        self::assertSame([self::METHOD, 'pwd'], $evidence->methods());
        self::assertSame(self::RAW_CONTEXT, $evidence->rawContext());
    }

    /**
     * Methods and a raw context are optional, and none is an empty answer.
     *
     * @return void
     */
    public function testItNeedsNoMethodsOrContext(): void
    {
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'));

        self::assertSame([], $evidence->methods());
        self::assertNull($evidence->rawContext());
    }

    /**
     * JSON shows only the safe fields, in UTC, with counts in place of values.
     *
     * @return void
     */
    public function testJsonShowsOnlyWhatMayBeShown(): void
    {
        $at = CarbonImmutable::parse('2026-11-01T10:29:00+01:00');

        self::assertSame(
            '{"connection_id":"connection-1","authenticated_at":"2026-11-01T09:29:00Z","methods":2,"raw_context":"[redacted]"}',
            json_encode(new AcceptedEvidence('connection-1', $at, [self::METHOD, 'pwd'], self::RAW_CONTEXT)),
        );

        self::assertSame(
            '{"connection_id":"connection-1","authenticated_at":"2026-11-01T09:29:00Z","methods":0,"raw_context":null}',
            json_encode(new AcceptedEvidence('connection-1', $at)),
        );
    }

    /**
     * What a dump is given is exactly what JSON writes.
     *
     * @return void
     */
    public function testTheDebugInfoIsTheJson(): void
    {
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), [self::METHOD], self::RAW_CONTEXT);

        self::assertSame([
            'connection_id'    => 'connection-1',
            'authenticated_at' => '2026-11-01T09:29:00Z',
            'methods'          => 1,
            'raw_context'      => '[redacted]',
        ], $evidence->__debugInfo());
    }

    /**
     * No dump shows a method or the raw context.
     *
     * @return void
     */
    public function testNoDumpShowsAProviderValue(): void
    {
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), [self::METHOD], self::RAW_CONTEXT);

        foreach (self::dumps($evidence) as $name => $dump) {
            self::assertStringNotContainsString(self::METHOD, $dump, $name);
            self::assertStringNotContainsString(self::RAW_CONTEXT, $dump, $name);
        }
    }

    /**
     * The provider values are hidden from exception traces.
     *
     * @return void
     */
    public function testItsProviderValuesAreSensitiveParameters(): void
    {
        $parameters = (new \ReflectionMethod(AcceptedEvidence::class, '__construct'))->getParameters();
        $sensitive  = array_filter($parameters, static fn (\ReflectionParameter $parameter): bool => $parameter->getAttributes(\SensitiveParameter::class) !== []);

        self::assertSame(['methods', 'rawContext'], array_values(array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $sensitive)));
    }

    /**
     * It refuses to be serialised.
     *
     * @return void
     */
    public function testItRefusesToBeSerialised(): void
    {
        $this->expectExceptionObject(new \LogicException('Accepted evidence cannot be serialised.'));

        serialize(new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), [self::METHOD], self::RAW_CONTEXT));
    }

    /**
     * It refuses to be unserialised, whatever was stored.
     *
     * @return void
     */
    public function testItRefusesToBeUnserialised(): void
    {
        $this->expectExceptionObject(new \LogicException('Accepted evidence cannot be unserialised.'));

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(AcceptedEvidence::class), AcceptedEvidence::class));
    }
}
