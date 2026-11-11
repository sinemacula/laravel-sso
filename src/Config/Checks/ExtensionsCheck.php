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
 * `[extensions]`: the PHP extensions and functions the package needs, while it
 * is in use. Composer requires them, but an install that ignored the platform,
 * or a runtime built without one, would otherwise fail on the first request
 * that reached for it; this names the missing one at boot instead.
 *
 * While the `saml2` feature is on, or its switch is malformed, it also checks
 * that the XML library will load each XML provider package's element registry
 * exactly once. The Composer plugin
 * `simplesamlphp/composer-xmlprovider-installer` puts them in place; an install
 * that skipped it would otherwise fail on the first SAML message parsed. It
 * reads files only.
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

    /** @var string A file name `ElementRegistry` loads, as it matches one. */
    private const string LOADED_REGISTRY = '/^element\.registry\.(.*)\.php$/';

    /** @var string How to put the registries in place, ending each registry problem. */
    private const string REINSTALL = 'run `composer install` with plugins enabled and `simplesamlphp/composer-xmlprovider-installer`'
        . ' allowed in `allow-plugins`, into a fresh vendor directory if the plugin has run before.';

    /** @var string The problem of a package's registry the library does not load. */
    private const string NOT_LOADED = 'The SAML library does not load the XML element registry of `%s`; ' . self::REINSTALL;

    /** @var string The problem of a package's registry the library loads more than once. */
    private const string LOADED_TWICE = 'The SAML library loads the XML element registry of `%s` more than once; ' . self::REINSTALL;

    /** @var string The problem of a package's registry that cannot be read. */
    private const string UNREADABLE = 'The XML element registry of `%s` cannot be read; ' . self::REINSTALL;

    /** @var string The problem of a registry file the library loads that cannot be read. */
    private const string UNREADABLE_LOADED = 'The XML element registry `%s` the SAML library loads cannot be read; ' . self::REINSTALL;

    /** @var \Closure(string): bool Whether an extension is loaded. */
    private \Closure $loaded;

    /** @var \Closure(string): bool Whether a function exists. */
    private \Closure $exists;

    /** @var \Closure(): array<string, string> Each XML provider package's element registry file, by package. */
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

        // Not promoted: `extension_loaded()` stands in when none is given
        ?\Closure $loaded = null,

        // Not promoted: `function_exists()` stands in when none is given
        ?\Closure $exists = null,

        // Not promoted: the installed registries stand in when none is given
        ?\Closure $registries = null,

        // Not promoted: the library's directory stands in when none is given
        ?\Closure $registryDirectory = null,
    ) {
        $this->loaded            = $loaded            ?? extension_loaded(...);
        $this->exists            = $exists            ?? function_exists(...);
        $this->registries        = $registries        ?? self::installedRegistries(...);
        $this->registryDirectory = $registryDirectory ?? ElementRegistries::directory(...);
    }

    /**
     * The extensions are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * One check per extension, then the IDNA conversion domains are normalised
     * with (SSO-3.1), from `ext-intl` or `symfony/polyfill-intl-idn`, then,
     * while SAML is on, the XML element registries.
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
     * Every XML provider package's registry is loaded by the XML library
     * exactly once: a missing one leaves its elements unparsed, and one loaded
     * twice is merged into lists where the library expects class names.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Exceptions\ElementRegistryException
     */
    private function assertRegistriesLoaded(): void
    {
        $loaded = self::loadedRegistries(($this->registryDirectory)());

        foreach (($this->registries)() as $package => $registry) {

            $contents = self::read($registry) ?? throw new ElementRegistryException(sprintf(self::UNREADABLE, $package));
            $copies   = count(array_keys($loaded, $contents, true));

            if ($copies === 0) {
                throw new ElementRegistryException(sprintf(self::NOT_LOADED, $package));
            }

            if ($copies > 1) {
                throw new ElementRegistryException(sprintf(self::LOADED_TWICE, $package));
            }
        }
    }

    /**
     * The contents of each registry file in the directory, found as
     * `ElementRegistry` finds them; a directory that does not exist holds none.
     *
     * @param  string  $directory
     * @return list<string>
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

            $loaded[] = self::read($file->getPathname()) ?? throw new ElementRegistryException(sprintf(self::UNREADABLE_LOADED, $file->getFilename()));
        }

        return $loaded;
    }

    /**
     * Each installed XML provider package's `classes/element.registry.php`, by
     * package; a package without one has nothing for the plugin to put in
     * place.
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
