<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Composer\InstalledVersions;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Exceptions\ElementRegistryException;
use SineMacula\Laravel\Sso\Exceptions\MissingExtensionException;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ElementRegistries;

/**
 * Checks at boot for the PHP extensions the package needs and, for SAML, the
 * XML element registries, which an install can skip despite Composer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExtensionsCheck implements ConfigurationCheck
{
    /** @var array<string, string> Each extension the package needs, and what for. */
    public const array EXTENSIONS = [
        'bcmath'   => 'the SAML library\'s XML Schema types (simplesamlphp/xml-common)',
        'curl'     => 'the outbound fetcher, which pins the address it checked with CURLOPT_RESOLVE',
        'dom'      => 'parsing SAML messages and metadata',
        'hash'     => 'digests and constant-time comparison',
        'libxml'   => 'parsing SAML messages and metadata',
        'mbstring' => 'length caps and sanitising of multibyte text',
        'openssl'  => 'keys, certificates, signatures and encryption',
        'zlib'     => 'the DEFLATE encoding of the SAML HTTP-Redirect binding',
    ];

    /** @var string The Composer package type whose element registries the XML library loads. */
    private const string XML_PROVIDER = 'simplesamlphp-xmlprovider';

    /** @var string A file name `ElementRegistry` loads. */
    private const string LOADED_REGISTRY = '/^element\.registry\.(.*)\.php$/';

    /** @var string The fix that ends each registry problem. */
    private const string REINSTALL = 'run `composer install` with plugins enabled and `simplesamlphp/composer-xmlprovider-installer`'
        . ' allowed in `allow-plugins`, into a fresh vendor directory if the plugin has run before.';

    /** @var string The problem of a package's registry the library does not load. */
    private const string NOT_LOADED = 'The SAML library does not load the XML element registry of `%s`; ' . self::REINSTALL;

    /** @var string The problem of a package's registry the library loads more than once. */
    private const string LOADED_TWICE = 'The SAML library loads the XML element registry of `%s` more than once; ' . self::REINSTALL;

    /** @var string The problem of a package's registry that cannot be read. */
    private const string UNREADABLE = 'The XML element registry of `%s` cannot be read; ' . self::REINSTALL;

    /** @var string The problem of a loaded registry file no installed package owns. */
    private const string STALE = 'The SAML library loads the XML element registry `%s`, which is no installed package\'s; ' . self::REINSTALL;

    /** @var string The problem of a loaded registry file that cannot be read. */
    private const string UNREADABLE_LOADED = 'The XML element registry `%s` the SAML library loads cannot be read; ' . self::REINSTALL;

    /** @var \Closure(string): bool Whether an extension is loaded. */
    private \Closure $loaded;

    /** @var \Closure(string): bool Whether a function exists. */
    private \Closure $exists;

    /** @var \Closure(): array<string, string> Each XML provider's registry file, by package. */
    private \Closure $registries;

    /** @var \Closure(): string The directory the XML library loads element registries from. */
    private \Closure $registryDirectory;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  ?\Closure(string): bool  $loaded
     * @param  ?\Closure(string): bool  $exists
     * @param  ?\Closure(): array<string, string>  $registries
     * @param  ?\Closure(): string  $registryDirectory
     */
    public function __construct(

        /** The configuration that says what is in use. */
        private Repository $config,

        // Not promoted: defaults to `extension_loaded()`
        ?\Closure $loaded = null,

        // Not promoted: defaults to `function_exists()`
        ?\Closure $exists = null,

        // Not promoted: defaults to the installed registries
        ?\Closure $registries = null,

        // Not promoted: defaults to the library's directory
        ?\Closure $registryDirectory = null,
    ) {
        $this->loaded            = $loaded            ?? extension_loaded(...);
        $this->exists            = $exists            ?? function_exists(...);
        $this->registries        = $registries        ?? self::installedRegistries(...);
        $this->registryDirectory = $registryDirectory ?? ElementRegistries::directory(...);
    }

    /**
     * Applies while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * Each extension, then `idn_to_ascii()`, then the registries while SAML is
     * requested.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [];

        foreach (self::EXTENSIONS as $extension => $purpose) {
            $checks[] = function () use ($extension, $purpose): void {
                if (!($this->loaded)($extension)) {
                    throw new MissingExtensionException(sprintf('The PHP extension `%s` is not loaded; laravel-sso needs it for %s.', $extension, $purpose));
                }
            };
        }

        $checks[] = function (): void {
            if (!($this->exists)('idn_to_ascii')) {
                $message = '`idn_to_ascii()` is not available; laravel-sso needs it, from `ext-intl` or `symfony/polyfill-intl-idn`, to normalise domains.';

                throw new MissingExtensionException($message);
            }
        };

        if (Features::requested($this->config, Feature::SAML2)) {
            $checks[] = function (): void {
                $this->assertRegistriesLoaded();
            };
        }

        return $checks;
    }

    /**
     * Each registry must load exactly once: a duplicate or stale copy is merged
     * into lists where the library expects class names.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Exceptions\ElementRegistryException
     */
    private function assertRegistriesLoaded(): void
    {
        $loaded    = self::loadedRegistries(($this->registryDirectory)());
        $installed = [];

        foreach (($this->registries)() as $package => $registry) {

            $contents    = self::read($registry) ?? throw new ElementRegistryException(sprintf(self::UNREADABLE, $package));
            $copies      = count(array_keys($loaded, $contents, true));
            $installed[] = $contents;

            if ($copies === 0) {
                throw new ElementRegistryException(sprintf(self::NOT_LOADED, $package));
            }

            if ($copies > 1) {
                throw new ElementRegistryException(sprintf(self::LOADED_TWICE, $package));
            }
        }

        $stale = array_key_first(array_diff($loaded, $installed));

        if ($stale !== null) {
            throw new ElementRegistryException(sprintf(self::STALE, $stale));
        }
    }

    /**
     * The contents of each registry file `ElementRegistry` would load, by file
     * name.
     *
     * @param  string  $directory
     * @return array<string, string>
     *
     * @throws \SineMacula\Laravel\Sso\Exceptions\ElementRegistryException
     */
    private static function loadedRegistries(string $directory): array
    {
        if (!is_dir($directory)) {
            return [];
        }

        $loaded = [];

        foreach (new \DirectoryIterator($directory) as $file) {

            if (!$file->isFile() || preg_match(self::LOADED_REGISTRY, $file->getFilename()) !== 1) {
                continue;
            }

            $loaded[$file->getFilename()] = self::read($file->getPathname()) ?? throw new ElementRegistryException(sprintf(self::UNREADABLE_LOADED, $file->getFilename()));
        }

        return $loaded;
    }

    /**
     * Each installed XML provider's `classes/element.registry.php`, by package.
     *
     * @return array<string, string>
     */
    private static function installedRegistries(): array
    {
        $registries = [];

        foreach (InstalledVersions::getInstalledPackagesByType(self::XML_PROVIDER) as $package) {

            $registry = InstalledVersions::getInstallPath($package) . '/classes/element.registry.php';

            if (!file_exists($registry)) {
                continue;
            }

            $registries[$package] = $registry;
        }

        return $registries;
    }

    /**
     * The file's contents, or `null` when it cannot be read.
     *
     * @param  string  $file
     * @return ?string
     */
    private static function read(string $file): ?string
    {
        $contents = is_readable($file) ? file_get_contents($file) : false;

        return $contents === false ? null : $contents;
    }
}
