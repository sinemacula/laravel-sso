<?php

declare(strict_types = 1);

namespace Tests\Unit\Domains;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Domains\DomainName;

/**
 * Unit tests for the normalisation of a claimed domain (SSO-3.1): trimmed, no
 * trailing dot, IDNA ASCII in lower case by UTS #46 non-transitional processing
 * with the contextual checks, at most 253 characters from at most 1024 bytes
 * given, and nothing for what is not a host name that could be registered; and
 * the refused-list match, which covers a listed domain and its subdomains only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainName::class)]
final class DomainNameTest extends TestCase
{
    /**
     * Rows of `[given, normalised]`.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function provideDomains(): iterable
    {
        yield 'lower case already' => ['example.com', 'example.com'];
        yield 'capitals' => ['Example.COM', 'example.com'];
        yield 'a trailing dot' => ['example.com.', 'example.com'];
        yield 'whitespace around' => ["  example.com\n", 'example.com'];
        yield 'a subdomain' => ['eu.sales.example.co.uk', 'eu.sales.example.co.uk'];
        yield 'digits and hyphens' => ['a-1.example2.com', 'a-1.example2.com'];
        yield 'Unicode' => ['bücher.de', 'xn--bcher-kva.de'];
        yield 'Unicode in capitals' => ['BÜCHER.de', 'xn--bcher-kva.de'];
        yield 'an A-label' => ['xn--bcher-kva.de', 'xn--bcher-kva.de'];
        yield 'non-Latin script' => ['例え.jp', 'xn--r8jz45g.jp'];
        yield 'an IDNA top-level label' => ['example.xn--p1ai', 'example.xn--p1ai'];
        yield 'a fullwidth dot' => ['example。com', 'example.com'];
        yield 'a label of 63 characters' => [str_repeat('a', 63) . '.com', str_repeat('a', 63) . '.com'];
        yield 'exactly 253 characters' => [self::nameOfLength(253), self::nameOfLength(253)];
        yield 'exactly 1024 bytes given' => ['examples.com' . str_repeat("\u{00AD}", 506), 'examples.com'];
        yield 'a sharp s, non-transitional' => ['faß.de', 'xn--fa-hia.de'];
        yield 'a final sigma, non-transitional' => ['ς.example.com', 'xn--3xa.example.com'];
    }

    /**
     * Each domain normalises as given.
     *
     * @param  string  $given
     * @param  string  $normalized
     * @return void
     */
    #[DataProvider('provideDomains')]
    public function testNormalizesADomain(string $given, string $normalized): void
    {
        self::assertSame($normalized, DomainName::normalize($given));
    }

    /**
     * Rows of `[given]`: what no tenant could register.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideUnregistrableNames(): iterable
    {
        yield 'nothing' => [''];
        yield 'whitespace' => ['   '];
        yield 'a single label' => ['com'];
        yield 'localhost' => ['localhost'];
        yield 'an IPv4 address' => ['192.0.2.1'];
        yield 'an IPv6 literal' => ['[::1]'];
        yield 'a wildcard' => ['*.example.com'];
        yield 'an underscore' => ['_sso.example.com'];
        yield 'a space inside' => ['ex ample.com'];
        yield 'a scheme' => ['https://example.com'];
        yield 'a port' => ['example.com:443'];
        yield 'a path' => ['example.com/path'];
        yield 'an at sign' => ['user@example.com'];
        yield 'an empty label' => ['a..example.com'];
        yield 'two trailing dots' => ['example.com..'];
        yield 'a leading dot' => ['.example.com'];
        yield 'a leading hyphen' => ['-example.com'];
        yield 'a trailing hyphen' => ['example-.com'];
        yield 'hyphens in the third and fourth places' => ['ab--cd.com'];
        yield 'a numeric top-level label' => ['example.42'];
        yield 'a one-letter top-level label' => ['example.c'];
        yield 'a label of 64 characters' => [str_repeat('a', 64) . '.com'];
        yield 'more than 253 characters' => [str_repeat('abc.', 63) . 'com'];
        yield '254 characters' => [self::nameOfLength(254)];
        yield 'more than 1024 bytes given' => ['example.com' . str_repeat("\u{00AD}", 507)];
        yield 'invalid UTF-8' => ["exa\xffmple.com"];
        yield 'a bidirectional mix' => ["\u{05D0}a.com"];
        yield 'a zero-width joiner out of context' => ["a\u{200D}b.com"];
        yield 'a zero-width non-joiner out of context' => ["a\u{200C}b.com"];
        yield '.test' => ['app.test'];
        yield '.example' => ['sso.example'];
        yield '.invalid' => ['nowhere.invalid'];
        yield '.local' => ['printer.local'];
        yield '.localhost' => ['app.localhost'];
        yield '.internal' => ['intranet.internal'];
        yield '.arpa' => ['home.arpa'];
        yield '.onion' => ['hidden.onion'];
        yield '.alt' => ['name.alt'];
    }

    /**
     * Each name normalises to nothing.
     *
     * @param  string  $given
     * @return void
     */
    #[DataProvider('provideUnregistrableNames')]
    public function testRefusesWhatCouldNotBeRegistered(string $given): void
    {
        self::assertNull(DomainName::normalize($given));
    }

    /**
     * A domain is listed when it is a listed domain or under one, and not when
     * a listed domain is under it or merely ends with its characters.
     *
     * @return void
     */
    public function testMatchesAListedDomainAndItsSubdomains(): void
    {
        $listed = ['gmail.com', 'shared.example.org'];

        self::assertTrue(DomainName::isListed('gmail.com', $listed));
        self::assertTrue(DomainName::isListed('mail.gmail.com', $listed));
        self::assertTrue(DomainName::isListed('a.b.shared.example.org', $listed));
        self::assertFalse(DomainName::isListed('notgmail.com', $listed));
        self::assertFalse(DomainName::isListed('example.org', $listed));
        self::assertFalse(DomainName::isListed('gmail.com.evil.test', $listed));
        self::assertFalse(DomainName::isListed('gmail.com', []));
    }

    /**
     * A valid host name of exactly the length given, of three labels of 63
     * characters and a shorter one under `com`.
     *
     * @param  int  $length
     * @return string
     */
    private static function nameOfLength(int $length): string
    {
        return implode('.', array_fill(0, 3, str_repeat('a', 63))) . '.' . str_repeat('b', $length - 196) . '.com';
    }
}
