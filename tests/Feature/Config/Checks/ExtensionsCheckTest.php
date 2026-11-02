<?php

declare(strict_types = 1);

namespace Tests\Feature\Config\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Config\Checks\ExtensionsCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[extensions]`: checked while the package is in use, every
 * extension `composer.json` requires and the IDNA conversion present, and a
 * missing one named with what it is needed for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExtensionsCheck::class)]
final class ExtensionsCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * Not checked while the package is not in use; passes on this runtime once
     * it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        self::assertNull($this->problemsOf(ExtensionsCheck::class));

        $this->useThePackage();

        self::assertSame([], $this->problemsOf(ExtensionsCheck::class));
    }

    /**
     * The extensions are those `composer.json` requires.
     *
     * @return void
     */
    public function testChecksEveryRequiredExtension(): void
    {
        /** @var array{require: array<string, string>} $composer */
        $composer = json_decode((string) file_get_contents(dirname(__DIR__, 4) . '/composer.json'), true, flags: JSON_THROW_ON_ERROR);

        $extensions = array_filter(array_keys($composer['require']), static fn (string $package): bool => str_starts_with($package, 'ext-'));
        $required   = array_map(static fn (string $package): string => substr($package, 4), array_values($extensions));

        self::assertSame(['bcmath', 'curl', 'dom', 'hash', 'libxml', 'mbstring', 'openssl', 'zlib'], array_keys(ExtensionsCheck::EXTENSIONS));
        self::assertSame($required, array_keys(ExtensionsCheck::EXTENSIONS));
    }

    /**
     * A missing extension, and a missing IDNA conversion, are each named with
     * what the package needs them for; every one is reported in a run.
     *
     * @return void
     */
    public function testNamesEachMissingExtension(): void
    {
        $this->useThePackage();

        $check = new ExtensionsCheck(
            static fn (string $extension): bool => !in_array($extension, ['curl', 'zlib'], true),
            static fn (string $function): bool => $function !== 'idn_to_ascii',
        );

        $this->app?->instance(ExtensionsCheck::class, $check);

        self::assertSame([
            'The PHP extension `curl` is not loaded; laravel-sso needs it for the outbound fetcher, which pins the address it checked with CURLOPT_RESOLVE.',
            'The PHP extension `zlib` is not loaded; laravel-sso needs it for the DEFLATE encoding of the SAML HTTP-Redirect binding.',
            '`idn_to_ascii()` is not available; laravel-sso needs it, from `ext-intl` or `symfony/polyfill-intl-idn`, to normalise domains.',
        ], $this->problemsOf(ExtensionsCheck::class));
    }
}
