<?php

declare(strict_types = 1);

namespace Tests\Feature\Config\Checks;

use Illuminate\Filesystem\Filesystem;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Config\Checks\ExtensionsCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for the `[extensions]` configuration check.
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

    /** @var string The end of every registry problem. */
    private const string REINSTALL = 'run `composer install` with plugins enabled and `simplesamlphp/composer-xmlprovider-installer`'
        . ' allowed in `allow-plugins`, into a fresh vendor directory if the plugin has run before.';

    /** @var string A temporary directory holding the packages' registries and the directory the library loads. */
    private string $directory;

    /**
     * Make the temporary directory, with a `loaded` directory inside it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->directory = sys_get_temp_dir() . '/' . uniqid('laravel-sso-registries-', true);

        mkdir($this->directory . '/loaded', 0777, true);
    }

    /**
     * Remove the temporary directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        (new Filesystem)->deleteDirectory($this->directory);

        parent::tearDown();
    }

    /**
     * Extensions are checked only while the package is in use, and pass here.
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
     * Each missing extension is named with what it is needed for.
     *
     * @return void
     */
    public function testNamesEachMissingExtension(): void
    {
        $this->useThePackage();

        $check = new ExtensionsCheck(
            config(),
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

    /**
     * Each registry loaded once passes.
     *
     * @return void
     */
    public function testPassesWhileEachRegistryIsLoadedOnce(): void
    {
        $this->useThePackage();
        $this->registry('a', 'A');
        $this->registry('b', 'B');
        $this->loaded('element.registry.1.php', 'A');
        $this->loaded('element.registry.2.php', 'B');
        $this->loaded('backup.element.registry.1.php', 'A');
        $this->loaded('element.registry.1.php.orig', 'A');

        mkdir($this->directory . '/loaded/element.registry.3.php');

        self::assertSame([], $this->registryProblems());
    }

    /**
     * A registry the library does not load, or loads differently, is named.
     *
     * @return void
     */
    public function testNamesARegistryTheLibraryDoesNotLoad(): void
    {
        $this->useThePackage();
        $this->registry('a', 'A');
        $this->registry('b', '100');
        $this->loaded('element.registry.1.php', 'A');
        $this->loaded('element.registry.2.php', '1e2');

        self::assertSame(['The SAML library does not load the XML element registry of `vendor/b`; ' . self::REINSTALL], $this->registryProblems());
    }

    /**
     * A missing loaded directory loads none of the installed registries.
     *
     * @return void
     */
    public function testNamesAnInstalledRegistryMissingFromTheLoadedDirectory(): void
    {
        $this->useThePackage();

        $directory = $this->directory . '/missing';
        $check     = new ExtensionsCheck(config(), registryDirectory: static fn (): string => $directory);

        $this->app?->instance(ExtensionsCheck::class, $check);

        self::assertSame(['The SAML library does not load the XML element registry of `simplesamlphp/saml2`; ' . self::REINSTALL], $this->problemsOf(ExtensionsCheck::class));
    }

    /**
     * A registry loaded twice is named.
     *
     * @return void
     */
    public function testNamesARegistryLoadedTwice(): void
    {
        $this->useThePackage();
        $this->registry('a', 'A');
        $this->loaded('element.registry.1.php', 'A');
        $this->loaded('element.registry.2.php', 'A');

        self::assertSame(['The SAML library loads the XML element registry of `vendor/a` more than once; ' . self::REINSTALL], $this->registryProblems());
    }

    /**
     * A loaded registry that is no installed package's is named by its file.
     *
     * @return void
     */
    public function testNamesAStaleRegistryTheLibraryLoads(): void
    {
        $this->useThePackage();
        $this->registry('a', 'A');
        $this->loaded('element.registry.1.php', 'A');
        $this->loaded('element.registry.2.php', 'A, older');

        $stale = 'The SAML library loads the XML element registry `element.registry.2.php`, which is no installed package\'s; ';

        self::assertSame([$stale . self::REINSTALL], $this->registryProblems());
    }

    /**
     * A package's registry that cannot be read is named by its package.
     *
     * @return void
     */
    public function testNamesAnUnreadableRegistry(): void
    {
        $this->useThePackage();
        $this->registry('a', 'A');
        $this->loaded('element.registry.1.php', 'A');

        chmod($this->directory . '/a.php', 0o000);

        self::assertSame(['The XML element registry of `vendor/a` cannot be read; ' . self::REINSTALL], $this->registryProblems());
    }

    /**
     * A loaded registry that cannot be read is named by its file.
     *
     * @return void
     */
    public function testNamesAnUnreadableLoadedRegistry(): void
    {
        $this->useThePackage();
        $this->registry('a', 'A');
        $this->loaded('element.registry.1.php', 'A');

        chmod($this->directory . '/loaded/element.registry.1.php', 0o000);

        self::assertSame(['The XML element registry `element.registry.1.php` the SAML library loads cannot be read; ' . self::REINSTALL], $this->registryProblems());
    }

    /**
     * The registries are checked only while `saml2` is on or malformed.
     *
     * @return void
     */
    public function testChecksTheRegistriesOnlyWhileSamlIsOn(): void
    {
        $this->useThePackage();
        $this->registry('a', 'A');

        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', true);

        self::assertSame([], $this->registryProblems());

        config()->set('sso.features.saml2', 'on');

        self::assertSame(['The SAML library does not load the XML element registry of `vendor/a`; ' . self::REINSTALL], $this->registryProblems());
    }

    /**
     * Write a package's registry, `vendor/<name>`'s.
     *
     * @param  string  $name
     * @param  string  $contents
     * @return void
     */
    private function registry(string $name, string $contents): void
    {
        file_put_contents("{$this->directory}/{$name}.php", $contents);
    }

    /**
     * Write a file to the directory the library loads from.
     *
     * @param  string  $name
     * @param  string  $contents
     * @return void
     */
    private function loaded(string $name, string $contents): void
    {
        file_put_contents("{$this->directory}/loaded/{$name}", $contents);
    }

    /**
     * The check's problems given the written registries and the loaded
     * directory.
     *
     * @return ?list<string>
     */
    private function registryProblems(): ?array
    {
        $registries = [];

        foreach (glob($this->directory . '/*.php') ?: [] as $registry) {
            $registries['vendor/' . basename($registry, '.php')] = $registry;
        }

        $directory = $this->directory . '/loaded';
        $check     = new ExtensionsCheck(config(), registries: static fn (): array => $registries, registryDirectory: static fn (): string => $directory);

        $this->app?->instance(ExtensionsCheck::class, $check);

        return $this->problemsOf(ExtensionsCheck::class);
    }
}
