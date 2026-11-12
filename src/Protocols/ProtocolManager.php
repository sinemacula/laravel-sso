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
 * Registry of protocol drivers and presets. Drivers are rebuilt per request or
 * job scope, so a driver must hold no connection, tenant or flow state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ProtocolManager extends Manager
{
    /** @var string Driver name pattern; fits the connections `protocol` column. */
    public const string NAME_PATTERN = '/^[a-z][a-z0-9_]{0,63}$/D';

    /** @var array<string, \SineMacula\Laravel\Sso\Config\Enums\Feature> Reserved package drivers and the feature switching each on. */
    private const array PACKAGE_DRIVERS = [
        Saml2Driver::NAME => Feature::SAML2,
        OidcDriver::NAME  => Feature::OIDC,
    ];

    /** @var bool Whether drivers follow the serving application's container. */
    private bool $followsApplication;

    /** @var ?\SineMacula\Laravel\Sso\Protocols\DriverScope The scope the kept drivers were built in. */
    private ?DriverScope $scope = null;

    /** @var array<string, \SineMacula\Laravel\Sso\Protocols\Preset> Application-registered presets, by name. */
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
     * Registered driver names: the package's, then extensions in order.
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
     * Whether a driver is registered under exactly the name.
     *
     * @param  string  $name
     * @return bool
     */
    public function isRegistered(string $name): bool
    {
        return array_key_exists($name, $this->customCreators) || array_key_exists($name, self::PACKAGE_DRIVERS);
    }

    /**
     * Whether the protocol is registered and its feature is on; an extension is
     * on while either package feature is.
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
     * Whether the connection is enabled, available and complete. A caller
     * deciding whether a flow may run reads it from the write connection first.
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
     * Whether a driver can be registered under the name.
     *
     * @param  string  $name
     * @return bool
     */
    public static function isValidName(string $name): bool
    {
        return preg_match(self::NAME_PATTERN, $name) === 1;
    }

    /**
     * Register a driver under a lower-case name. The package's own drivers
     * cannot be replaced.
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
     * The shipped or registered preset under the name, if any.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Protocols\Preset
     */
    public function preset(string $name): ?Preset
    {
        return $this->presets()[$name] ?? null;
    }

    /**
     * Every preset by name: the shipped ones, then those registered.
     *
     * @return array<string, \SineMacula\Laravel\Sso\Protocols\Preset>
     */
    public function presets(): array
    {
        return [...Presets::shipped(), ...$this->registeredPresets];
    }

    /**
     * Register a preset; its protocol must already be registered.
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
     * Return the driver, rebuilt when the serving application or its scope has
     * changed, as Octane sandboxes and queue jobs do.
     *
     * @param  mixed  $driver
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function driver(mixed $driver = null): mixed
    {
        if ($driver !== null && !is_string($driver) && !$driver instanceof \UnitEnum) {
            throw new \InvalidArgumentException(sprintf('Protocol driver [%s] is not registered.', get_debug_type($driver)));
        }

        if ($this->followsApplication) {
            $this->followApplication(Container::getInstance());
        }

        return parent::driver($driver);
    }

    /**
     * Pin the drivers to the given container, whichever application serves.
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
     * Build the driver registered under exactly the name; case matters.
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
     * Build the SAML 2.0 driver.
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
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function createOidcDriver(): OidcDriver
    {
        return $this->container->make(OidcDriver::class);
    }

    /**
     * Forget the kept drivers unless built with this application and scope.
     *
     * @param  \Illuminate\Container\Container  $current
     * @return void
     */
    private function followApplication(Container $current): void
    {
        $scope = $current->make(DriverScope::class);

        if ($current === $this->container && $scope === $this->scope) {
            return;
        }

        $this->container = $current;
        $this->config    = $current->make('config');
        $this->drivers   = [];
        $this->scope     = $scope;
    }

    /**
     * Return the resolved driver if it implements the contract.
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
