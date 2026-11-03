<?php

declare(strict_types = 1);

namespace Benchmarks\Fetching;

use Illuminate\Config\Repository;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;

/**
 * PHPBench suite for judging an address
 * (`Fetching\AddressPolicy::isRefused()`), which the fetcher asks of every
 * address a host resolves to before it connects: allowed public addresses,
 * which are checked against every range, and refused ones. It resolves nothing
 * and connects nowhere, and needs no application. A subject answers whether the
 * address is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[BeforeMethods('setUp')]
#[Iterations(5)]
#[Revs(1000)]
#[Warmup(1)]
final class AddressPolicyBench
{
    /** @var \SineMacula\Laravel\Sso\Fetching\AddressPolicy The policy, with no range added. */
    private AddressPolicy $policy; // @phpstan-ignore property.uninitialized

    /**
     * Build the policy once.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->policy = new AddressPolicy(new FetcherSettings(new Repository));
    }

    /**
     * Allow a public IPv4 address.
     *
     * @return bool
     */
    public function benchPublicV4(): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate -- a subject is named for its input.
    {
        return $this->policy->isRefused('8.8.8.8');
    }

    /**
     * Allow a public IPv6 address.
     *
     * @return bool
     */
    public function benchPublicV6(): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate -- a subject is named for its input.
    {
        return $this->policy->isRefused('2606:4700:4700::1111');
    }

    /**
     * Refuse a private IPv4 address.
     *
     * @return bool
     */
    public function benchPrivate(): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate -- a subject is named for its input.
    {
        return $this->policy->isRefused('10.0.0.1');
    }

    /**
     * Refuse a link-local IPv6 address.
     *
     * @return bool
     */
    public function benchLinkLocal(): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate -- a subject is named for its input.
    {
        return $this->policy->isRefused('fe80::1');
    }

    /**
     * Refuse the cloud metadata address.
     *
     * @return bool
     */
    public function benchMetadata(): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate -- a subject is named for its input.
    {
        return $this->policy->isRefused('169.254.169.254');
    }

    /**
     * Refuse an IPv6 address carrying a loopback IPv4 address.
     *
     * @return bool
     */
    public function benchMapped(): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate -- a subject is named for its input.
    {
        return $this->policy->isRefused('::ffff:127.0.0.1');
    }
}
