<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;

/**
 * The registry of protocol drivers, keyed by the name a connection's protocol
 * holds (SSO-2.2), and of the presets that fill in a connection's settings.
 *
 * The package registers its own drivers, `saml2` and `oidc`, so their names are
 * reserved: `extend('saml2', ...)` throws. Other drivers register themselves
 * with `extend()` under a lower-case name (a letter, then up to 63 letters,
 * digits or underscores), for example from a service provider's `register()`
 * once the registry resolves:
 *
 * `$this->callAfterResolving(ProtocolManager::class, fn ($protocols) =>
 * $protocols->extend('cas', ...));`
 *
 * A singleton that keeps each driver it builds for as long as the same
 * application is serving (the life of the process, except under Octane, where
 * each request's sandbox builds its own), which is why drivers must hold no
 * connection, tenant, flow or result state (SSO-11.2). There is no default
 * driver: every connection names the protocol it runs over, exactly as it was
 * registered.
 *
 * A connection is usable only while it is enabled, its protocol is available
 * and its driver finds it complete (SSO-2.1). `saml2` is available while
 * `sso.features.saml2` is on and `oidc` while `sso.features.oidc` is; a driver
 * an application registered is available while either is on, since with neither
 * on the package is not in use and nothing of it is checked.
 *
 * Presets are data (SSO-2.2): the package ships those in `Presets`, and an
 * application registers its own with `registerPreset()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ProtocolManager extends Manager
{
    /** @var string Pattern a registered driver's name must match; it fits the connections table's `protocol` column. */
    private const string NAME_PATTERN = '/^[a-z][a-z0-9_]{0,63}$/D';

    /** @var array<string, \SineMacula\Laravel\Sso\Config\Enums\Feature> The drivers the package registers itself, by name, with the feature that switches each on; `extend()` refuses them. */
    private const array PACKAGE_DRIVERS = [
        Saml2Driver::NAME => Feature::SAML2,
        OidcDriver::NAME  => Feature::OIDC,
    ];

    /** @var bool Whether the manager follows the application serving: it was built with the one then serving and given no container since. */
    private bool $followsApplication;

    /** @var array<string, \SineMacula\Laravel\Sso\Protocols\Preset> The presets an application registered, by name. */
    private array $registeredPresets = [];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(ContainerContract $container)
    {
        parent::__construct($container);

        $this->followsApplication = $container === Container::getInstance();
    }

    /**
     * Return the driver registered under the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolDriver
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function protocol(string $name): ProtocolDriver
    {
        return self::assertDriver($name, $this->driver($name));
    }

    /**
     * The names drivers are registered under: the package's own, then those
     * registered with `extend()`, in the order they were registered.
     *
     * @return list<string>
     */
    public function names(): array
    {
        /** @var list<string> $registered */
        $registered = array_keys($this->customCreators);

        return [...array_keys(self::PACKAGE_DRIVERS), ...$registered];
    }

    /**
     * Whether a driver is registered under exactly the name: one of the
     * package's own, or one registered with `extend()`.
     *
     * @param  string  $name
     * @return bool
     */
    public function isRegistered(string $name): bool
    {
        return array_key_exists($name, $this->customCreators) || array_key_exists($name, self::PACKAGE_DRIVERS);
    }

    /**
     * Whether connections over the protocol may be used: a driver is registered
     * under it, and its feature is on (`sso.features.saml2` or
     * `sso.features.oidc` for the package's own, either for one an application
     * registered). A malformed switch fails closed with the
     * `InvalidArgumentException` `Config\Features::enabled()` throws.
     *
     * @param  string  $name
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isAvailable(string $name): bool
    {
        if (!$this->isRegistered($name)) {
            return false;
        }

        $feature = self::PACKAGE_DRIVERS[$name] ?? null;

        if ($feature !== null) {
            return Features::enabled($feature);
        }

        return Features::enabled(Feature::SAML2) || Features::enabled(Feature::OIDC);
    }

    /**
     * Whether the connection may be used (SSO-2.1): it is enabled, its protocol
     * is available, and its driver finds it complete. Read from what the
     * connection holds now; a caller deciding whether a flow may run reads the
     * connection from the write connection first (SSO-11.3).
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function isUsable(SsoConnection $connection): bool
    {
        if (!$connection->isEnabled() || !$this->isAvailable($connection->getProtocol())) {
            return false;
        }

        return $this->protocol($connection->getProtocol())->isComplete($connection);
    }

    /**
     * Whether the name is one a driver can be registered under: a lower-case
     * letter, then up to 63 lower-case letters, digits or underscores.
     *
     * @param  string  $name
     * @return bool
     */
    public static function isValidName(string $name): bool
    {
        return preg_match(self::NAME_PATTERN, $name) === 1;
    }

    /**
     * Register a driver under the name, which must be lower case (a letter,
     * then up to 63 letters, digits or underscores), so each protocol has one
     * spelling for connections to hold. The package's own drivers cannot be
     * replaced: their settings, checks and events are the package's guarantees.
     *
     * @param  mixed  $driver
     * @param  \Closure  $callback
     * @return $this
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore missingType.callable
     */
    #[\Override]
    public function extend(mixed $driver, \Closure $callback): self
    {
        if (!is_string($driver) || !self::isValidName($driver)) {
            throw new \InvalidArgumentException('A protocol driver\'s name must be lower case: a letter, then up to 63 letters, digits or underscores.');
        }

        if (array_key_exists($driver, self::PACKAGE_DRIVERS)) {
            throw new \InvalidArgumentException(sprintf('The [%s] protocol is the package\'s own and cannot be replaced; register yours under another name.', $driver));
        }

        parent::extend($driver, $callback);

        return $this;
    }

    /**
     * The preset under the name: one the package ships, or one an application
     * registered; `null` when there is none.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Protocols\Preset
     */
    public function preset(string $name): ?Preset
    {
        return $this->presets()[$name] ?? null;
    }

    /**
     * Every preset, by name: the package's, then those registered, in the order
     * they were registered.
     *
     * @return array<string, \SineMacula\Laravel\Sso\Protocols\Preset>
     */
    public function presets(): array
    {
        return [...Presets::shipped(), ...$this->registeredPresets];
    }

    /**
     * Register a preset under its name. A shipped preset cannot be replaced,
     * and a preset's protocol must be registered first.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Preset  $preset
     * @return $this
     *
     * @throws \InvalidArgumentException
     */
    public function registerPreset(Preset $preset): self
    {
        if (array_key_exists($preset->name, Presets::shipped())) {
            throw new \InvalidArgumentException(sprintf('The [%s] preset is the package\'s own and cannot be replaced; register yours under another name.', $preset->name));
        }

        if (!$this->isRegistered($preset->protocol)) {
            throw new \InvalidArgumentException(sprintf('The [%s] preset is for the [%s] protocol, which is not registered.', $preset->name, $preset->protocol));
        }

        $this->registeredPresets[$preset->name] = $preset;

        return $this;
    }

    /**
     * Return the driver registered under the name. A manager built with the
     * application then serving builds its drivers with the application now
     * serving: drivers built with another application are forgotten first, so
     * they are built again with this one, and drivers registered with
     * `extend()` stay registered. A manager given a container of its own, at
     * construction or through `setContainer()`, keeps it.
     *
     * Under Octane each request runs in a sandbox: a copy of the application
     * the worker booted, with the request's own configuration and bindings. A
     * manager resolved at boot would otherwise build every driver with the
     * booted application, for the life of the worker.
     *
     * @param  mixed  $driver
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function driver(mixed $driver = null): mixed
    {
        $current = Container::getInstance();

        if ($this->followsApplication && $current !== $this->container) {
            $this->container = $current;
            $this->config    = $current->make('config');
            $this->drivers   = [];
        }

        return parent::driver($driver);
    }

    /**
     * Build the drivers with the container given from now on, whichever
     * application is serving.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return $this
     */
    #[\Override]
    public function setContainer(ContainerContract $container): self
    {
        $this->followsApplication = false;

        return parent::setContainer($container);
    }

    /**
     * Refuse to pick a driver: every connection names its protocol.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function getDefaultDriver(): string
    {
        throw new \InvalidArgumentException('Protocol drivers have no default; name the protocol to use.');
    }

    /**
     * Build the driver registered under exactly the name: one of the package's
     * own, through its `create<Name>Driver()` method, or one registered with
     * `extend()`. Any other spelling, including one that differs only in case,
     * is unknown.
     *
     * @param  mixed  $driver
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    protected function createDriver(mixed $driver): mixed
    {
        if (!is_string($driver) || !$this->isRegistered($driver)) {
            throw new \InvalidArgumentException(sprintf('Protocol driver [%s] is not registered.', is_string($driver) ? $driver : get_debug_type($driver)));
        }

        return parent::createDriver($driver);
    }

    /**
     * Build the SAML 2.0 driver, with its collaborators, from the container the
     * drivers are built with.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function createSaml2Driver(): Saml2Driver
    {
        return $this->container->make(Saml2Driver::class);
    }

    /**
     * Build the OpenID Connect driver.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver
     */
    protected function createOidcDriver(): OidcDriver
    {
        return new OidcDriver;
    }

    /**
     * Return what the name resolved to when it is a protocol driver.
     *
     * @param  string  $name
     * @param  mixed  $driver
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolDriver
     *
     * @throws \LogicException
     */
    private static function assertDriver(string $name, mixed $driver): ProtocolDriver
    {
        if (!$driver instanceof ProtocolDriver) {
            throw new \LogicException(sprintf('Protocol driver [%s] resolved to %s, which does not implement %s.', $name, get_debug_type($driver), ProtocolDriver::class));
        }

        return $driver;
    }
}
