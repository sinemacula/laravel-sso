<?php

declare(strict_types = 1);

namespace Tests\Unit\RateLimiting;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\RateLimiting\CounterKeys;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;

/**
 * Unit tests for the keys the attempt limiter stores its counters under: keyed
 * digests of the flow, the scope and the value in its canonical form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CounterKeys::class)]
final class CounterKeysTest extends TestCase
{
    /** @var string Application key the keys are derived from. */
    private const string APP_KEY = 'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=';

    /** @var string What the key derived from the application key is for. */
    private const string PURPOSE = 'laravel-sso rate limit counters';

    /**
     * A counter's key is the HMAC-SHA256 of the flow, the scope and the value
     * joined by NUL bytes, under a key derived from the application key: 64
     * lower-case hexadecimal characters, and not the plain digest anyone could
     * recompute from a guessed value.
     *
     * @return void
     */
    public function testACountersKeyIsAKeyedDigestOfItsParts(): void
    {
        $key = self::keys()->counter(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, '203.0.113.7');

        self::assertSame(self::digest(['redemption', 'per_ip', '203.0.113.7']), $key);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key);
        self::assertNotSame(hash('sha256', implode("\0", ['redemption', 'per_ip', '203.0.113.7'])), $key);
        self::assertNotSame(hash_hmac('sha256', implode("\0", ['redemption', 'per_ip', '203.0.113.7']), self::APP_KEY), $key);
    }

    /**
     * The same flow, scope and value give the same key on every call and from
     * every instance, so every server counts in the same row.
     *
     * @return void
     */
    public function testTheSameValueGivesTheSameKey(): void
    {
        $first  = self::keys()->counter(AttemptFlow::COMPLETION, AttemptScope::PER_CONNECTION, 'connection-1');
        $second = self::keys()->counter(AttemptFlow::COMPLETION, AttemptScope::PER_CONNECTION, 'connection-1');

        self::assertSame($first, $second);
    }

    /**
     * Another flow, scope or value gives another key, so no two limits share a
     * counter.
     *
     * @return void
     */
    public function testAnotherFlowScopeOrValueGivesAnotherKey(): void
    {
        $keys = self::keys();

        $counters = [
            $keys->counter(AttemptFlow::COMPLETION, AttemptScope::PER_CONNECTION, 'connection-1'),
            $keys->counter(AttemptFlow::METADATA, AttemptScope::PER_CONNECTION, 'connection-1'),
            $keys->counter(AttemptFlow::DOMAIN_CHECK, AttemptScope::PER_CONNECTION, 'connection-1'),
            $keys->counter(AttemptFlow::COMPLETION, AttemptScope::PER_CONNECTION, 'connection-2'),
            $keys->counter(AttemptFlow::COMPLETION, AttemptScope::PER_IP, 'connection-1'),
            $keys->counter(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_IP, '203.0.113.7'),
            $keys->counter(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, '203.0.113.7'),
            $keys->counter(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, '203.0.113.7'),
        ];

        self::assertCount(count($counters), array_unique($counters));
    }

    /**
     * The parts are joined by a separator no part can hold, so moving text from
     * one part to the next gives another key.
     *
     * @return void
     */
    public function testThePartsAreKeptApart(): void
    {
        self::assertSame(
            self::digest(['metadata', 'per_connection', "a\0b"]),
            self::keys()->counter(AttemptFlow::METADATA, AttemptScope::PER_CONNECTION, "a\0b"),
        );
    }

    /**
     * Another application key gives every counter another key, so rotating it
     * starts the counters afresh.
     *
     * @return void
     */
    public function testAnotherApplicationKeyGivesAnotherKey(): void
    {
        $other = 'base64:' . base64_encode(str_repeat('k', 32));

        $before = self::keys()->counter(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, '203.0.113.7');
        $after  = self::keys($other)->counter(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, '203.0.113.7');

        self::assertNotSame($before, $after);
        self::assertSame(self::digest(['redemption', 'per_ip', '203.0.113.7'], $other), $after);
    }

    /**
     * Application keys that cannot key the counters.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMissingApplicationKeys(): iterable
    {
        yield from [
            'unset'        => [null],
            'empty'        => [''],
            'not a string' => [['base64:abc']],
        ];
    }

    /**
     * Without an application key the counters cannot be keyed, so the limiter
     * fails closed rather than store digests anyone could reverse.
     *
     * @param  mixed  $key
     * @return void
     */
    #[DataProvider('provideMissingApplicationKeys')]
    public function testAMissingApplicationKeyFailsClosed(mixed $key): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The attempt limiter keys its counters with the application key; set `app.key`.');

        self::keys($key)->counter(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, '203.0.113.7');
    }

    /**
     * Rows of `[IP address as given, canonical form]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideIpAddresses(): iterable
    {
        yield from [
            'IPv4'                            => ['203.0.113.7', '203.0.113.7'],
            'IPv4-mapped IPv6'                => ['::ffff:203.0.113.7', '203.0.113.7'],
            'IPv4-mapped IPv6 in hexadecimal' => ['::FFFF:CB00:7107', '203.0.113.7'],
            'NAT64 well-known prefix'         => ['64:ff9b::203.0.113.7', '203.0.113.7'],
            'NAT64 in hexadecimal'            => ['64:FF9B::CB00:7107', '203.0.113.7'],
            'IPv6'                            => ['2001:db8:1:2::1', '2001:db8:1:2::/64'],
            'IPv6 written out in full'        => ['2001:0DB8:0001:0002:0000:0000:0000:0001', '2001:db8:1:2::/64'],
            'IPv6 elsewhere in the same /64'  => ['2001:db8:1:2:ffff:ffff:ffff:fffe', '2001:db8:1:2::/64'],
            'IPv6 in another /64'             => ['2001:db8:1:3::1', '2001:db8:1:3::/64'],
            'IPv6 next to the mapped prefix'  => ['::fffe:203.0.113.7', '::/64'],
            'not an IP address'               => ['Unknown', 'unknown'],
            'an out-of-range IPv4 address'    => ['203.0.113.256', '203.0.113.256'],
        ];
    }

    /**
     * An IP address is counted as the client it stands for: an IPv4 address
     * carried in IPv6 as that IPv4 address, any other IPv6 address as its /64,
     * and anything else lower-cased as given.
     *
     * @param  string  $ip
     * @param  string  $canonical
     * @return void
     */
    #[DataProvider('provideIpAddresses')]
    public function testCountsAnIpAddressInItsCanonicalForm(string $ip, string $canonical): void
    {
        self::assertSame(
            self::digest(['completion', 'per_ip', $canonical]),
            self::keys()->counter(AttemptFlow::COMPLETION, AttemptScope::PER_IP, $ip),
        );
    }

    /**
     * IPv4-mapped and NAT64 addresses count with their IPv4 address; addresses
     * in one /64 share a counter, and addresses in two do not.
     *
     * @return void
     */
    public function testIpAddressesOfOneClientShareAKey(): void
    {
        $keys = self::keys();
        $key  = static fn (string $ip): string => $keys->counter(AttemptFlow::REDEMPTION, AttemptScope::PER_IP, $ip);

        self::assertSame($key('203.0.113.7'), $key('::ffff:203.0.113.7'));
        self::assertSame($key('203.0.113.7'), $key('64:ff9b::203.0.113.7'));
        self::assertNotSame($key('203.0.113.7'), $key('203.0.113.8'));
        self::assertSame($key('2001:db8:1:2::1'), $key('2001:db8:1:2:abcd::9'));
        self::assertNotSame($key('2001:db8:1:2::1'), $key('2001:db8:1:3::1'));
    }

    /**
     * Rows of `[email domain as given, canonical form]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEmailDomains(): iterable
    {
        yield from [
            'lower case'                   => ['example.com', 'example.com'],
            'mixed case'                   => ['Example.COM', 'example.com'],
            'a trailing dot'               => ['example.com.', 'example.com'],
            'a Unicode domain'             => ['Bücher.example', 'xn--bcher-kva.example'],
            'a Unicode domain upper-cased' => ['BÜCHER.EXAMPLE.', 'xn--bcher-kva.example'],
            'its ASCII form'               => ['xn--bcher-kva.example', 'xn--bcher-kva.example'],
            'its ASCII form upper-cased'   => ['XN--BCHER-KVA.EXAMPLE', 'xn--bcher-kva.example'],
            'non-transitional sharp s'     => ['faß.example', 'xn--fa-hia.example'],
            'an empty label'               => ['A..Example', 'a..example'],
            'an empty label and a dot'     => ['A..Example.', 'a..example.'],
            'only a dot'                   => ['.', '.'],
            'empty'                        => ['', ''],
        ];
    }

    /**
     * An email domain is counted lower-cased, without one trailing dot, in
     * ASCII; one that will not convert is counted lower-cased as given.
     *
     * @param  string  $domain
     * @param  string  $canonical
     * @return void
     */
    #[DataProvider('provideEmailDomains')]
    public function testCountsAnEmailDomainInItsCanonicalForm(string $domain, string $canonical): void
    {
        self::assertSame(
            self::digest(['authorization_request', 'per_email_domain', $canonical]),
            self::keys()->counter(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, $domain),
        );
    }

    /**
     * A domain's case, a trailing dot and its Unicode and ASCII forms share a
     * counter; another domain does not.
     *
     * @return void
     */
    public function testFormsOfOneDomainShareAKey(): void
    {
        $keys = self::keys();
        $key  = static fn (string $domain): string => $keys->counter(AttemptFlow::AUTHORIZATION_REQUEST, AttemptScope::PER_EMAIL_DOMAIN, $domain);

        self::assertSame($key('example.com'), $key('EXAMPLE.com.'));
        self::assertSame($key('Bücher.example'), $key('xn--bcher-kva.example'));
        self::assertNotSame($key('example.com'), $key('example.org'));
    }

    /**
     * A connection id is counted exactly as given.
     *
     * @return void
     */
    public function testCountsAConnectionAsGiven(): void
    {
        $keys = self::keys();

        self::assertSame(self::digest(['metadata', 'per_connection', 'Connection-1.']), $keys->counter(AttemptFlow::METADATA, AttemptScope::PER_CONNECTION, 'Connection-1.'));
        self::assertNotSame(
            $keys->counter(AttemptFlow::METADATA, AttemptScope::PER_CONNECTION, 'Connection-1'),
            $keys->counter(AttemptFlow::METADATA, AttemptScope::PER_CONNECTION, 'connection-1'),
        );
    }

    /**
     * Build the keys under the application key.
     *
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Sso\RateLimiting\CounterKeys
     */
    private static function keys(mixed $key = self::APP_KEY): CounterKeys
    {
        return new CounterKeys(new Repository(['app' => ['key' => $key]]));
    }

    /**
     * The keyed digest of the parts, computed independently of the class under
     * test.
     *
     * @param  list<string>  $parts
     * @param  string  $appKey
     * @return string
     */
    private static function digest(array $parts, string $appKey = self::APP_KEY): string
    {
        return hash_hmac('sha256', implode("\0", $parts), hash_hmac('sha256', self::PURPOSE, $appKey, true));
    }
}
