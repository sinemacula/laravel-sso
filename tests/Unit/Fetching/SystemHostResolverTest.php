<?php

declare(strict_types = 1);

namespace Tests\Unit\Fetching;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Fetching\SystemHostResolver;

/**
 * Unit tests for the default host resolver. Each test injects its own lookup,
 * so nothing hits the network.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemHostResolver::class)]
final class SystemHostResolverTest extends TestCase
{
    /**
     * With no lookup of its own the resolver uses `dns_get_record()`.
     *
     * @return void
     */
    public function testLooksANameUpWithTheSystemResolverByDefault(): void
    {
        $resolver = new SystemHostResolver;
        $lookup   = (new \ReflectionProperty($resolver, 'lookup'))->getValue($resolver);

        self::assertInstanceOf(HostResolver::class, $resolver);
        self::assertInstanceOf(\Closure::class, $lookup);
        self::assertSame('dns_get_record', (new \ReflectionFunction($lookup))->getName());
    }

    /**
     * The lookup is asked once, for the name's A and AAAA records only.
     *
     * @return void
     */
    public function testAsksForTheARecordsAndTheAaaaRecordsOfTheName(): void
    {
        /** @var list<array{string, int}> $asked */
        $asked = [];

        $resolver = new SystemHostResolver(static function (string $host, int $type) use (&$asked): array {
            $asked[] = [$host, $type];

            return [];
        });

        $resolver->addresses('idp.example.com');

        self::assertSame([['idp.example.com', DNS_A | DNS_AAAA]], $asked);
    }

    /**
     * Records the lookup may give, and the addresses answered for them.
     *
     * @return iterable<string, array{mixed, list<string>}>
     */
    public static function provideRecords(): iterable
    {
        yield from [
            'no record'          => [[], []],
            'an A record'        => [[['type' => 'A', 'ip' => '93.184.216.34']], ['93.184.216.34']],
            'an AAAA record'     => [[['type' => 'AAAA', 'ipv6' => '2606:2800:220:1::']], ['2606:2800:220:1::']],
            'both, in order'     => [[['type' => 'AAAA', 'ipv6' => '2001:db8::1'], ['type' => 'A', 'ip' => '192.0.2.1']], ['2001:db8::1', '192.0.2.1']],
            'a repeated address' => [[['ip' => '192.0.2.1'], ['ip' => '192.0.2.2'], ['ip' => '192.0.2.1']], ['192.0.2.1', '192.0.2.2']],
            'no address held'    => [[['type' => 'A'], 'not a record', ['ip' => 3232235777], ['ip' => '192.0.2.1']], ['192.0.2.1']],
            'a failed lookup'    => [false, []],
        ];
    }

    /**
     * Each A and AAAA address is answered once, in lookup order, skipping
     * records without one.
     *
     * @param  mixed  $records
     * @param  list<string>  $expected
     * @return void
     */
    #[DataProvider('provideRecords')]
    public function testAnswersTheAddressOfEachRecordOnce(mixed $records, array $expected): void
    {
        $resolver = new SystemHostResolver(static fn (): mixed => $records);

        self::assertSame($expected, $resolver->addresses('idp.example.com'));
    }

    /**
     * A lookup that warns answers no address, and the warning never reaches the
     * application's handler.
     *
     * @return void
     */
    public function testALookupThatWarnsAnswersNoAddress(): void
    {
        $resolver = new SystemHostResolver(static function (): array {
            trigger_error('dns_get_record(): A temporary server error occurred.', E_USER_WARNING);

            return [['type' => 'A', 'ip' => '192.0.2.1']];
        });

        /** @var list<string> $reported */
        $reported = [];

        set_error_handler(static function (int $severity, string $message) use (&$reported): bool {
            $reported[] = $message;

            return true;
        });

        try {
            $addresses = $resolver->addresses('idp.example.com');
        } finally {
            restore_error_handler();
        }

        self::assertSame([], $addresses);
        self::assertSame([], $reported);
    }

    /**
     * The previous error handler is restored after the lookup, whether it
     * answered or warned.
     *
     * @return void
     */
    public function testRestoresTheErrorHandlerAfterTheLookup(): void
    {
        $handler = static fn (): bool => true;

        $lookups = [
            static fn (): array => [],
            static function (): array {
                trigger_error('A warning.', E_USER_WARNING);

                return [];
            },
        ];

        foreach ($lookups as $lookup) {

            set_error_handler($handler);

            (new SystemHostResolver($lookup))->addresses('idp.example.com');

            $current = set_error_handler(static fn (): bool => true);

            restore_error_handler();
            restore_error_handler();

            self::assertSame($handler, $current);
        }
    }
}
