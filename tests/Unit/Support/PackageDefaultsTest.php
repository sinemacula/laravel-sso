<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use SineMacula\Laravel\Sso\Support\PackageDefaults;

/**
 * Unit tests for `PackageDefaults`: the private key of each default, the
 * abstracts the package scopes, and that every default implements its contract,
 * once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackageDefaults::class)]
final class PackageDefaultsTest extends TestCase
{
    /**
     * A default's key is the contract under the package's prefix.
     *
     * @return void
     */
    public function testTheKeyIsTheContractUnderThePrefix(): void
    {
        self::assertSame('sso.default:' . Fetcher::class, PackageDefaults::key(Fetcher::class));
    }

    /**
     * The scoped abstracts are each scoped default's key, then the driver
     * scope.
     *
     * @return void
     */
    public function testTheScopedAbstractsAreTheScopedKeysAndTheDriverScope(): void
    {
        self::assertSame(
            [
                'sso.default:' . SingleUseStore::class,
                'sso.default:' . SecretEncrypter::class,
                'sso.default:' . Fetcher::class,
                'sso.default:' . AttemptLimiter::class,
                'sso.default:' . DnsResolver::class,
                'sso.default:' . Enforcement::class,
                'sso.default:' . EndpointResolver::class,
                'sso.default:' . HandoffIssuer::class,
                DriverScope::class,
            ],
            PackageDefaults::scoped(),
        );
    }

    /**
     * Every default implements its contract, and no contract is both a
     * singleton and scoped.
     *
     * @return void
     */
    public function testEveryDefaultImplementsItsContractOnce(): void
    {
        self::assertSame([], array_intersect_key(PackageDefaults::SINGLETONS, PackageDefaults::SCOPED));

        foreach ([...PackageDefaults::SINGLETONS, ...PackageDefaults::SCOPED] as $contract => $default) {
            self::assertTrue((new \ReflectionClass($default))->implementsInterface($contract), $default . ' does not implement ' . $contract . '.');
        }
    }
}
