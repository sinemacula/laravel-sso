<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Check;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits;
use Tests\TestCase;

/**
 * Feature tests for the caps and windows every SAML connection is held to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Saml2Limits::class)]
#[CoversClass(Saml2Check::class)]
final class Saml2LimitsTest extends TestCase
{
    /**
     * With nothing configured, each limit is its default.
     *
     * @return void
     */
    public function testEachLimitDefaults(): void
    {
        config()->set('sso.saml2', []);

        $limits = new Saml2Limits(config());

        self::assertSame([262144, 196608, 131072, 300], [$limits->maxResponseBytes(), $limits->maxXmlBytes(), $limits->maxDecryptedBytes(), $limits->issueInstantMaxAgeSeconds()]);
    }

    /**
     * Rows of `[key, read, least, most]`: each limit, what reads it, and its
     * bounds.
     *
     * @return iterable<string, array{0: string, 1: \Closure(\SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits): int, 2: int, 3: int}>
     */
    public static function provideLimits(): iterable
    {
        yield from [
            'response'      => ['max_response_bytes', static fn (Saml2Limits $limits): int => $limits->maxResponseBytes(), 16384, 1048576],
            'xml'           => ['max_xml_bytes', static fn (Saml2Limits $limits): int => $limits->maxXmlBytes(), 16384, 1048576],
            'decrypted'     => ['max_decrypted_bytes', static fn (Saml2Limits $limits): int => $limits->maxDecryptedBytes(), 4096, 1048576],
            'issue instant' => ['issue_instant_max_age_seconds', static fn (Saml2Limits $limits): int => $limits->issueInstantMaxAgeSeconds(), 30, 3600],
        ];
    }

    /**
     * Each limit is read at its bounds, from the string `env()` gives, and
     * refused one past either bound or malformed, naming its key.
     *
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits): int  $read
     * @param  int  $least
     * @param  int  $most
     * @return void
     */
    #[DataProvider('provideLimits')]
    public function testEachLimitIsHeldToItsBounds(string $key, \Closure $read, int $least, int $most): void
    {
        $limits = new Saml2Limits(config());

        foreach ([$least, $most, (string) $least] as $value) {
            config()->set('sso.saml2.' . $key, $value);

            self::assertSame((int) $value, $read($limits));
        }

        foreach ([$least - 1, $most + 1, '1e3', ' 100'] as $value) {
            config()->set('sso.saml2.' . $key, $value);

            try {
                $read($limits);
                self::fail("sso.saml2.{$key} accepted " . var_export($value, true) . '.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('sso.saml2.%s must be an integer from %d to %d.', $key, $least, $most), $exception->getMessage());
            }
        }
    }

    /**
     * `[saml2]` applies while the `saml2` feature is on or its switch is
     * malformed, and checks each limit.
     *
     * @return void
     */
    public function testTheCheckAppliesWithTheFeatureAndChecksEachLimit(): void
    {
        $check = new Saml2Check(config());

        config()->set('sso.features.saml2', false);
        self::assertFalse($check->applies());

        config()->set('sso.features.saml2', 'maybe');
        self::assertTrue($check->applies());

        config()->set('sso.features.saml2', true);
        self::assertTrue($check->applies());

        self::assertSame([262144, 196608, 131072, 300], array_map(static fn (\Closure $check): mixed => $check(), $check->checks()));

        config()->set('sso.saml2.max_decrypted_bytes', 1);

        $this->expectExceptionObject(new \InvalidArgumentException('sso.saml2.max_decrypted_bytes must be an integer from 4096 to 1048576.'));

        $check->checks()[2]();
    }
}
