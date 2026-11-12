<?php

declare(strict_types = 1);

namespace Tests\Unit\Fetching;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;

/**
 * Unit tests for the outbound address policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AddressPolicy::class)]
final class AddressPolicyTest extends TestCase
{
    /**
     * Rows of `[range, first, last]`: each built-in range and its first and
     * last addresses.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideBuiltInRanges(): iterable
    {
        yield from [
            'this network'         => ['0.0.0.0/8', '0.0.0.0', '0.255.255.255'],
            'private 10/8'         => ['10.0.0.0/8', '10.0.0.0', '10.255.255.255'],
            'shared address space' => ['100.64.0.0/10', '100.64.0.0', '100.127.255.255'],
            'loopback'             => ['127.0.0.0/8', '127.0.0.0', '127.255.255.255'],
            'link-local'           => ['169.254.0.0/16', '169.254.0.0', '169.254.255.255'],
            'private 172.16/12'    => ['172.16.0.0/12', '172.16.0.0', '172.31.255.255'],
            'protocol assignments' => ['192.0.0.0/24', '192.0.0.0', '192.0.0.255'],
            'test-net-1'           => ['192.0.2.0/24', '192.0.2.0', '192.0.2.255'],
            '6to4 relay anycast'   => ['192.88.99.0/24', '192.88.99.0', '192.88.99.255'],
            'private 192.168/16'   => ['192.168.0.0/16', '192.168.0.0', '192.168.255.255'],
            'benchmarking'         => ['198.18.0.0/15', '198.18.0.0', '198.19.255.255'],
            'test-net-2'           => ['198.51.100.0/24', '198.51.100.0', '198.51.100.255'],
            'test-net-3'           => ['203.0.113.0/24', '203.0.113.0', '203.0.113.255'],
            'multicast'            => ['224.0.0.0/4', '224.0.0.0', '239.255.255.255'],
            'reserved'             => ['240.0.0.0/4', '240.0.0.0', '255.255.255.254'],
            'limited broadcast'    => ['255.255.255.255/32', '255.255.255.255', '255.255.255.255'],
            'unspecified'          => ['::/128', '::', '::'],
            'ipv6 loopback'        => ['::1/128', '::1', '::1'],
            'discard only'         => ['100::/64', '100::', '100::ffff:ffff:ffff:ffff'],
            'teredo'               => ['2001::/32', '2001::', '2001:0:ffff:ffff:ffff:ffff:ffff:ffff'],
            'ipv6 documentation'   => ['2001:db8::/32', '2001:db8::', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'],
            'unique local'         => ['fc00::/7', 'fc00::', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
            'ipv6 link-local'      => ['fe80::/10', 'fe80::', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
            'site-local'           => ['fec0::/10', 'fec0::', 'feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
            'ipv6 multicast'       => ['ff00::/8', 'ff00::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
        ];
    }

    /**
     * Each built-in range is refused from its first address to its last.
     *
     * @param  string  $range
     * @param  string  $first
     * @param  string  $last
     * @return void
     */
    #[DataProvider('provideBuiltInRanges')]
    public function testRefusesEveryBuiltInRangeFromFirstToLast(string $range, string $first, string $last): void
    {
        $policy = self::policy();

        self::assertContains($range, [...AddressPolicy::REFUSED_IPV4, ...AddressPolicy::REFUSED_IPV6]);
        self::assertTrue($policy->isRefused($first), "{$first} is refused.");
        self::assertTrue($policy->isRefused($last), "{$last} is refused.");
    }

    /**
     * The built-in lists hold exactly the ranges tested here.
     *
     * @return void
     */
    public function testTheBuiltInRangesAreExactlyThoseTested(): void
    {
        $tested = array_map(static fn (array $row): string => $row[0], array_values(iterator_to_array(self::provideBuiltInRanges())));

        self::assertSame($tested, [...AddressPolicy::REFUSED_IPV4, ...AddressPolicy::REFUSED_IPV6]);
    }

    /**
     * Rows of `[address]`: the cloud metadata addresses, in every written form.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMetadataAddresses(): iterable
    {
        yield from [
            'aws, gcp and azure'     => ['169.254.169.254'],
            'aws over ipv6'          => ['fd00:ec2::254'],
            'aws over ipv6, full'    => ['fd00:0ec2:0000:0000:0000:0000:0000:0254'],
            'aws over ipv6, capital' => ['FD00:EC2::254'],
            'ipv4-mapped metadata'   => ['::ffff:169.254.169.254'],
            'ipv4-mapped, hex'       => ['::ffff:a9fe:a9fe'],
            'alibaba'                => ['100.100.100.200'],
        ];
    }

    /**
     * The cloud metadata addresses are refused however they are written.
     *
     * @param  string  $address
     * @return void
     */
    #[DataProvider('provideMetadataAddresses')]
    public function testRefusesTheCloudMetadataAddresses(string $address): void
    {
        self::assertTrue(self::policy()->isRefused($address));
    }

    /**
     * Rows of `[address]`: public addresses, and those just outside each
     * built-in range.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAllowedAddresses(): iterable
    {
        yield from [
            'public ipv4'                => ['93.184.216.34'],
            'public dns'                 => ['8.8.8.8'],
            'cloudflare'                 => ['1.1.1.1'],
            'after this network'         => ['1.0.0.0'],
            'before 10/8'                => ['9.255.255.255'],
            'after 10/8'                 => ['11.0.0.0'],
            'before shared space'        => ['100.63.255.255'],
            'after shared space'         => ['100.128.0.0'],
            'before loopback'            => ['126.255.255.255'],
            'after loopback'             => ['128.0.0.0'],
            'before link-local'          => ['169.253.255.255'],
            'after link-local'           => ['169.255.0.0'],
            'before 172.16/12'           => ['172.15.255.255'],
            'after 172.16/12'            => ['172.32.0.0'],
            'after protocol assignments' => ['192.0.1.0'],
            'after test-net-1'           => ['192.0.3.0'],
            'before 6to4 relay'          => ['192.88.98.255'],
            'after 6to4 relay'           => ['192.88.100.0'],
            'before 192.168/16'          => ['192.167.255.255'],
            'after 192.168/16'           => ['192.169.0.0'],
            'before benchmarking'        => ['198.17.255.255'],
            'after benchmarking'         => ['198.20.0.0'],
            'before test-net-2'          => ['198.51.99.255'],
            'after test-net-2'           => ['198.51.101.0'],
            'before test-net-3'          => ['203.0.112.255'],
            'after test-net-3'           => ['203.0.114.0'],
            'before multicast'           => ['223.255.255.255'],
            'public ipv6'                => ['2606:4700:4700::1111'],
            'public ipv6, full'          => ['2001:4860:4860:0000:0000:0000:0000:8888'],
            'public ipv6, capital'       => ['2A00:1450:4009:81F::200E'],
            'after discard only'         => ['100:0:0:1::'],
            'after teredo'               => ['2001:1::'],
            'before documentation'       => ['2001:db7:ffff:ffff:ffff:ffff:ffff:ffff'],
            'after documentation'        => ['2001:db9::'],
            'before unique local'        => ['fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
            'after unique local'         => ['fe00::'],
            'before ipv6 link-local'     => ['fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
        ];
    }

    /**
     * Public addresses, and those just outside each refused range, are allowed.
     *
     * @param  string  $address
     * @return void
     */
    #[DataProvider('provideAllowedAddresses')]
    public function testAllowsPublicAddresses(string $address): void
    {
        self::assertFalse(self::policy()->isRefused($address));
    }

    /**
     * Rows of `[address, refused]`: IPv6 forms carrying a private or a public
     * IPv4 address.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideCarriedAddresses(): iterable
    {
        yield from [
            'mapped loopback'             => ['::ffff:127.0.0.1', true],
            'mapped private'              => ['::ffff:10.1.2.3', true],
            'mapped metadata'             => ['::ffff:169.254.169.254', true],
            'mapped public'               => ['::ffff:8.8.8.8', false],
            'mapped public, hex'          => ['::ffff:808:808', false],
            'compatible loopback'         => ['::127.0.0.1', true],
            'compatible private'          => ['::192.168.1.1', true],
            'compatible public'           => ['::8.8.8.8', false],
            'translated loopback'         => ['::ffff:0:127.0.0.1', true],
            'translated public'           => ['::ffff:0:8.8.8.8', false],
            'nat64 loopback'              => ['64:ff9b::127.0.0.1', true],
            'nat64 metadata'              => ['64:ff9b::a9fe:a9fe', true],
            'nat64 private'               => ['64:ff9b::10.0.0.1', true],
            'nat64 public'                => ['64:ff9b::8.8.8.8', false],
            'local-use nat64 private'     => ['64:ff9b:1:a00:0:100::', true],
            'local-use nat64 loopback'    => ['64:ff9b:1:7f00:0:100::', true],
            'local-use nat64 public'      => ['64:ff9b:1:808:8:800::', false],
            '6to4 loopback'               => ['2002:7f00:1::', true],
            '6to4 metadata'               => ['2002:a9fe:a9fe::', true],
            '6to4 private'                => ['2002:c0a8:101::1', true],
            '6to4 public'                 => ['2002:808:808::1', false],
            'teredo, whatever it carries' => ['2001:0:4136:e378:8000:63bf:3fff:fdd2', true],
        ];
    }

    /**
     * An IPv6 form is judged by the IPv4 address it carries.
     *
     * @param  string  $address
     * @param  bool  $refused
     * @return void
     */
    #[DataProvider('provideCarriedAddresses')]
    public function testJudgesAnIpv6FormByTheIpv4AddressItCarries(string $address, bool $refused): void
    {
        self::assertSame($refused, self::policy()->isRefused($address));
    }

    /**
     * Configured ranges are refused on top of the built-in ones, for IPv4 and
     * IPv6 carriers alike.
     *
     * @return void
     */
    public function testAddsTheConfiguredRanges(): void
    {
        $policy = self::policy(['8.8.8.0/24', '2606:4700::/32', '93.184.216.34/32', '2a00:1450:4009:81f::200e/128']);

        self::assertTrue($policy->isRefused('8.8.8.0'));
        self::assertTrue($policy->isRefused('8.8.8.255'));
        self::assertTrue($policy->isRefused('::ffff:8.8.8.8'));
        self::assertTrue($policy->isRefused('64:ff9b::8.8.8.8'));
        self::assertTrue($policy->isRefused('2606:4700:4700::1111'));
        self::assertTrue($policy->isRefused('93.184.216.34'));
        self::assertTrue($policy->isRefused('2a00:1450:4009:81f::200e'));
        self::assertTrue($policy->isRefused('127.0.0.1'));

        self::assertFalse($policy->isRefused('8.8.7.255'));
        self::assertFalse($policy->isRefused('8.8.9.0'));
        self::assertFalse($policy->isRefused('93.184.216.35'));
        self::assertFalse($policy->isRefused('2606:4701::1'));
        self::assertFalse($policy->isRefused('2a00:1450:4009:81f::200f'));
    }

    /**
     * A configured prefix that is not whole bytes refuses exactly the addresses
     * under it.
     *
     * @return void
     */
    public function testMatchesAConfiguredRangeToTheBit(): void
    {
        $policy = self::policy(['8.8.8.8/31', '2606:4700::/31']);

        self::assertTrue($policy->isRefused('8.8.8.8'));
        self::assertTrue($policy->isRefused('8.8.8.9'));
        self::assertFalse($policy->isRefused('8.8.8.7'));
        self::assertFalse($policy->isRefused('8.8.8.10'));
        self::assertTrue($policy->isRefused('2606:4701:ffff::1'));
        self::assertFalse($policy->isRefused('2606:4702::1'));
    }

    /**
     * A configured `/0` refuses every address of its family only.
     *
     * @return void
     */
    public function testAConfiguredZeroPrefixRefusesAWholeFamily(): void
    {
        $ipv4 = self::policy(['0.0.0.0/0']);

        self::assertTrue($ipv4->isRefused('8.8.8.8'));
        self::assertTrue($ipv4->isRefused('::ffff:8.8.8.8'));
        self::assertFalse($ipv4->isRefused('2606:4700:4700::1111'));

        $ipv6 = self::policy(['::/0']);

        self::assertTrue($ipv6->isRefused('2606:4700:4700::1111'));
        self::assertFalse($ipv6->isRefused('8.8.8.8'));
    }

    /**
     * The configured ranges are read on each call.
     *
     * @return void
     */
    public function testReadsTheConfiguredRangesOnEachCall(): void
    {
        $config = new Repository(['sso' => ['fetcher' => ['refused_ranges' => []]]]);
        $policy = new AddressPolicy(new FetcherSettings($config));

        self::assertFalse($policy->isRefused('8.8.8.8'));

        $config->set('sso.fetcher.refused_ranges', ['8.8.8.8/32']);

        self::assertTrue($policy->isRefused('8.8.8.8'));
    }

    /**
     * A malformed configured range fails closed rather than being skipped.
     *
     * @return void
     */
    public function testAMalformedConfiguredRangeFailsClosed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.fetcher.refused_ranges.0 must be a CIDR range');

        self::policy(['8.8.8.8'])->isRefused('8.8.8.8');
    }

    /**
     * Rows of `[address]`: strings that are not a valid IP literal.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedAddresses(): iterable
    {
        yield from [
            'empty'              => [''],
            'a host name'        => ['localhost'],
            'a domain'           => ['example.com'],
            'decimal'            => ['2130706433'],
            'octal'              => ['0177.0.0.1'],
            'hex'                => ['0x7f.0.0.1'],
            'short'              => ['127.1'],
            'leading zero'       => ['8.8.8.08'],
            'five parts'         => ['8.8.8.8.8'],
            'out of range'       => ['256.8.8.8'],
            'leading space'      => [' 8.8.8.8'],
            'trailing space'     => ['8.8.8.8 '],
            'trailing newline'   => ["8.8.8.8\n"],
            'with a port'        => ['8.8.8.8:443'],
            'with a prefix'      => ['8.8.8.8/32'],
            'bracketed ipv6'     => ['[2606:4700:4700::1111]'],
            'ipv6 with a zone'   => ['fe80::1%eth0'],
            'ipv6, too many'     => ['1:2:3:4:5:6:7:8:9'],
            'ipv6, double gap'   => ['2606::4700::1111'],
            'a public lookalike' => ['8.8.8.8.'],
        ];
    }

    /**
     * Anything that is not a valid IP literal is refused, never parsed
     * leniently.
     *
     * @param  string  $address
     * @return void
     */
    #[DataProvider('provideMalformedAddresses')]
    public function testRefusesAnythingThatIsNotAnIpLiteral(string $address): void
    {
        self::assertTrue(self::policy()->isRefused($address));
    }

    /**
     * The policy over the given configured ranges.
     *
     * @param  list<string>  $ranges
     * @return \SineMacula\Laravel\Sso\Fetching\AddressPolicy
     */
    private static function policy(array $ranges = []): AddressPolicy
    {
        return new AddressPolicy(new FetcherSettings(new Repository(['sso' => ['fetcher' => ['refused_ranges' => $ranges]]])));
    }
}
