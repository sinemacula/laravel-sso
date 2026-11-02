<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcCheck;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits;
use Tests\TestCase;

/**
 * Feature tests for the caps, windows and timeouts every OIDC connection is
 * held to (SSO-2.9, SSO-7.1 to SSO-7.5, SSO-12.3): each default, each bound at,
 * under and over, a malformed value failing closed with its key, and `[oidc]`
 * checking each the same way, only while the `oidc` feature is on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OidcLimits::class)]
#[CoversClass(OidcCheck::class)]
final class OidcLimitsTest extends TestCase
{
    /** @var list<int> Every limit's default, in the order the check reads them. */
    private const array DEFAULTS = [16384, 65536, 50, 65536, 65536, 65536, 2048, 8192, 16, 300, 300, 10, 10];

    /**
     * With nothing configured, each limit is its default, the production-safe
     * one the configuration publishes.
     *
     * @return void
     */
    public function testEachLimitDefaults(): void
    {
        config()->set('sso.oidc', []);

        $check = new OidcCheck(config());

        self::assertSame(self::DEFAULTS, array_map(static fn (\Closure $read): mixed => $read(), $check->checks()));

        config()->set('sso.oidc', (require dirname(__DIR__, 4) . '/config/sso.php')['oidc']);

        self::assertSame(self::DEFAULTS, array_map(static fn (\Closure $read): mixed => $read(), $check->checks()));
    }

    /**
     * Rows of `[key, read, least, most]`: each limit, what reads it, and its
     * bounds.
     *
     * @return iterable<string, array{0: string, 1: \Closure(\SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits): int, 2: int, 3: int}>
     */
    public static function provideLimits(): iterable
    {
        yield from [
            'id token'           => ['max_id_token_bytes', static fn (OidcLimits $limits): int => $limits->maxIdTokenBytes(), 2048, 16384],
            'jwks'               => ['max_jwks_bytes', static fn (OidcLimits $limits): int => $limits->maxJwksBytes(), 4096, 65536],
            'jwks keys'          => ['max_jwks_keys', static fn (OidcLimits $limits): int => $limits->maxJwksKeys(), 1, 50],
            'discovery'          => ['max_discovery_bytes', static fn (OidcLimits $limits): int => $limits->maxDiscoveryBytes(), 4096, 1048576],
            'token response'     => ['max_token_response_bytes', static fn (OidcLimits $limits): int => $limits->maxTokenResponseBytes(), 4096, 1048576],
            'userinfo'           => ['max_userinfo_bytes', static fn (OidcLimits $limits): int => $limits->maxUserInfoBytes(), 4096, 1048576],
            'callback parameter' => ['max_callback_parameter_bytes', static fn (OidcLimits $limits): int => $limits->maxCallbackParameterBytes(), 256, 2048],
            'callback query'     => ['max_callback_query_bytes', static fn (OidcLimits $limits): int => $limits->maxCallbackQueryBytes(), 1024, 16384],
            'callback count'     => ['max_callback_parameters', static fn (OidcLimits $limits): int => $limits->maxCallbackParameters(), 4, 32],
            'refetch cooldown'   => ['jwks_refetch_cooldown_seconds', static fn (OidcLimits $limits): int => $limits->jwksRefetchCooldownSeconds(), 60, 3600],
            'id token age'       => ['id_token_max_age_seconds', static fn (OidcLimits $limits): int => $limits->idTokenMaxAgeSeconds(), 30, 3600],
            'token timeout'      => ['token_timeout_seconds', static fn (OidcLimits $limits): int => $limits->tokenTimeoutSeconds(), 1, 60],
            'userinfo timeout'   => ['userinfo_timeout_seconds', static fn (OidcLimits $limits): int => $limits->userInfoTimeoutSeconds(), 1, 60],
        ];
    }

    /**
     * Each limit is read at its bounds, from the string `env()` gives, and
     * refused one past either bound or malformed, naming its key.
     *
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits): int  $read
     * @param  int  $least
     * @param  int  $most
     * @return void
     */
    #[DataProvider('provideLimits')]
    public function testEachLimitIsHeldToItsBounds(string $key, \Closure $read, int $least, int $most): void
    {
        $limits = new OidcLimits(config());

        foreach ([$least, $most, (string) $least] as $value) {
            config()->set('sso.oidc.' . $key, $value);

            self::assertSame((int) $value, $read($limits));
        }

        foreach ([$least - 1, $most + 1, '1e3', ' 100', null] as $value) {
            config()->set('sso.oidc.' . $key, $value);

            try {
                $read($limits);
                self::fail("sso.oidc.{$key} accepted " . var_export($value, true) . '.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('sso.oidc.%s must be an integer from %d to %d.', $key, $least, $most), $exception->getMessage());
            }
        }
    }

    /**
     * `[oidc]` applies while the `oidc` feature is on or its switch is
     * malformed, and checks each limit.
     *
     * @return void
     */
    public function testTheCheckAppliesWithTheFeatureAndChecksEachLimit(): void
    {
        $check = new OidcCheck(config());

        config()->set('sso.features.oidc', false);
        self::assertFalse($check->applies());

        config()->set('sso.features.oidc', 'maybe');
        self::assertTrue($check->applies());

        config()->set('sso.features.oidc', true);
        self::assertTrue($check->applies());
        self::assertCount(13, $check->checks());

        config()->set('sso.oidc.userinfo_timeout_seconds', 61);

        $this->expectExceptionObject(new \InvalidArgumentException('sso.oidc.userinfo_timeout_seconds must be an integer from 1 to 60.'));

        $check->checks()[12]();
    }
}
